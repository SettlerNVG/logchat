package p2p

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/logmessager/client/internal/crypto"
	"github.com/rs/zerolog/log"
)

// Client represents a P2P client that connects to a host
type Client struct {
	mu     sync.RWMutex
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	identityKey     *crypto.KeyPair
	ephemeralKey    *crypto.KeyPair
	sessionCipher   *crypto.SessionCipher
	peerPublicKey   []byte
	encryptionReady bool

	onMessage    func(text string)
	onDisconnect func()

	connected bool
	stopped   bool
}

// NewClient creates a new P2P client
func NewClient(identityKey *crypto.KeyPair) *Client {
	// Generate ephemeral key pair for this session
	ephemeralKey, err := crypto.GenerateEphemeralKeyPair()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate ephemeral key")
		ephemeralKey = identityKey // fallback
	}
	
	return &Client{
		identityKey:  identityKey,
		ephemeralKey: ephemeralKey,
	}
}

// Connect connects to a P2P host
func (c *Client) Connect(hostAddress, sessionToken string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.DialTimeout("tcp", hostAddress, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to host: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)
	c.connected = true
	c.stopped = false

	log.Info().Str("address", hostAddress).Msg("Connected to P2P host")

	// Start reading messages
	go c.readLoop()

	// Initiate E2EE handshake - send our public key first
	go c.sendHandshake()

	return nil
}

func (c *Client) readLoop() {
	for {
		c.mu.RLock()
		reader := c.reader
		stopped := c.stopped
		c.mu.RUnlock()

		if stopped || reader == nil {
			return
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Error().Err(err).Msg("Read error")
			}
			c.handleDisconnect()
			return
		}

		var msg Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			log.Error().Err(err).Msg("Invalid message format")
			continue
		}

		switch msg.Type {
		case "handshake":
			// Received host's public key, establish encryption
			c.mu.Lock()
			c.peerPublicKey = msg.PublicKey
			
			// Compute shared secret using ECDH
			sharedSecret, err := crypto.ComputeSharedSecret(c.ephemeralKey.PrivateKeyBytes(), c.peerPublicKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to compute shared secret")
				c.mu.Unlock()
				continue
			}
			
			// Create session cipher (client IS initiator - we initiated connection)
			c.sessionCipher, err = crypto.NewSessionCipher(sharedSecret, true)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create session cipher")
				c.mu.Unlock()
				continue
			}
			c.encryptionReady = true
			c.mu.Unlock()
			
			log.Info().Msg("E2EE handshake complete - encryption established")
			
		case "msg":
			c.mu.RLock()
			cipher := c.sessionCipher
			encReady := c.encryptionReady
			c.mu.RUnlock()
			
			var plaintext string
			if encReady && cipher != nil && len(msg.Ciphertext) > 0 {
				// Decrypt message
				decrypted, err := cipher.Decrypt(msg.Ciphertext, msg.Nonce)
				if err != nil {
					log.Error().Err(err).Msg("Failed to decrypt message")
					continue
				}
				plaintext = string(decrypted)
				log.Info().Str("decrypted", plaintext).Msg("Client decrypted message")
			} else {
				// Fallback to unencrypted (shouldn't happen in production)
				plaintext = msg.Data
				log.Warn().Msg("Received unencrypted message")
			}
			
			c.mu.RLock()
			handler := c.onMessage
			c.mu.RUnlock()
			if handler != nil {
				handler(plaintext)
			}
		}
	}
}

func (c *Client) handleDisconnect() {
	c.mu.Lock()
	c.connected = false
	handler := c.onDisconnect
	c.mu.Unlock()

	log.Info().Msg("Disconnected from host")
	if handler != nil {
		handler()
	}
}

// Disconnect closes the connection
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stopped = true
	c.connected = false
	c.encryptionReady = false

	// Destroy session cipher keys
	if c.sessionCipher != nil {
		c.sessionCipher.Destroy()
		c.sessionCipher = nil
	}
	
	// Clear peer public key
	c.peerPublicKey = nil

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	log.Info().Msg("Disconnected from P2P host, encryption keys destroyed")
}

// SendMessage sends a message to the host
func (c *Client) SendMessage(text []byte) error {
	c.mu.RLock()
	writer := c.writer
	connected := c.connected
	cipher := c.sessionCipher
	encReady := c.encryptionReady
	c.mu.RUnlock()

	if !connected || writer == nil {
		return fmt.Errorf("not connected")
	}

	var msg Message
	if encReady && cipher != nil {
		// Encrypt message
		ciphertext, nonce, err := cipher.Encrypt(text)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		msg = Message{Type: "msg", Ciphertext: ciphertext, Nonce: nonce}
		log.Info().Int("ciphertext_len", len(ciphertext)).Msg("Client sending encrypted message")
	} else {
		// Fallback to unencrypted (shouldn't happen)
		msg = Message{Type: "msg", Data: string(text)}
		log.Warn().Msg("Sending unencrypted message - encryption not ready")
	}
	
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.writer.WriteString(string(data) + "\n"); err != nil {
		return err
	}
	return c.writer.Flush()
}

// sendHandshake sends our public key to host
func (c *Client) sendHandshake() error {
	c.mu.RLock()
	writer := c.writer
	ephKey := c.ephemeralKey
	c.mu.RUnlock()

	if writer == nil || ephKey == nil {
		return fmt.Errorf("not ready for handshake")
	}

	msg := Message{Type: "handshake", PublicKey: ephKey.PublicKeyBytes()}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.writer.WriteString(string(data) + "\n"); err != nil {
		return err
	}
	log.Info().Msg("Client sent handshake with public key")
	return c.writer.Flush()
}

// SetMessageHandler sets callback for incoming messages
func (c *Client) SetMessageHandler(handler func(text string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onMessage = handler
}

// SetDisconnectHandler sets callback for disconnection
func (c *Client) SetDisconnectHandler(handler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnect = handler
}

// IsConnected returns connection status
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}
