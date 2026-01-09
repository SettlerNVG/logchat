package p2p

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/logmessager/client/internal/crypto"
	"github.com/rs/zerolog/log"
)

// Message represents a P2P message
type Message struct {
	Type       string `json:"type"` // "msg", "handshake", "ack"
	Data       string `json:"data,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	PublicKey  []byte `json:"public_key,omitempty"`
}

// Host represents a P2P host that accepts incoming connections
type Host struct {
	mu           sync.RWMutex
	listener     net.Listener
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	port         int
	portRange    [2]int
	sessionToken string

	identityKey    *crypto.KeyPair
	ephemeralKey   *crypto.KeyPair
	sessionCipher  *crypto.SessionCipher
	peerPublicKey  []byte
	encryptionReady bool

	onMessage    func(text string)
	onDisconnect func()
	onConnect    func()

	connected bool
	stopped   bool
}

// NewHost creates a new P2P host
func NewHost(portRangeStart, portRangeEnd int, identityKey *crypto.KeyPair) *Host {
	// Generate ephemeral key pair for this session
	ephemeralKey, err := crypto.GenerateEphemeralKeyPair()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate ephemeral key")
		ephemeralKey = identityKey // fallback
	}
	
	return &Host{
		portRange:    [2]int{portRangeStart, portRangeEnd},
		identityKey:  identityKey,
		ephemeralKey: ephemeralKey,
	}
}

// Start starts listening for incoming connections
func (h *Host) Start(sessionToken string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sessionToken = sessionToken
	h.stopped = false

	// Find available port
	var err error
	for port := h.portRange[0]; port <= h.portRange[1]; port++ {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		h.listener, err = net.Listen("tcp", addr)
		if err == nil {
			h.port = port
			break
		}
	}

	if h.listener == nil {
		return "", fmt.Errorf("no available port in range %d-%d", h.portRange[0], h.portRange[1])
	}

	// Get public address
	publicAddr := h.getPublicAddress()

	log.Info().Int("port", h.port).Str("address", publicAddr).Msg("P2P host started")

	// Accept connections in background
	go h.acceptLoop()

	return publicAddr, nil
}

func (h *Host) acceptLoop() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			h.mu.RLock()
			stopped := h.stopped
			h.mu.RUnlock()
			if stopped {
				return
			}
			log.Error().Err(err).Msg("Accept error")
			continue
		}

		h.mu.Lock()
		h.conn = conn
		h.reader = bufio.NewReader(conn)
		h.writer = bufio.NewWriter(conn)
		h.connected = true
		connectHandler := h.onConnect
		h.mu.Unlock()

		log.Info().Str("remote", conn.RemoteAddr().String()).Msg("Client connected to host")

		// Notify about connection
		if connectHandler != nil {
			connectHandler()
		}

		// Read messages
		go h.readLoop()
		break // Only accept one connection
	}
}

func (h *Host) readLoop() {
	for {
		h.mu.RLock()
		reader := h.reader
		stopped := h.stopped
		h.mu.RUnlock()

		if stopped || reader == nil {
			return
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Error().Err(err).Msg("Read error")
			}
			h.handleDisconnect()
			return
		}

		var msg Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			log.Error().Err(err).Msg("Invalid message format")
			continue
		}

		switch msg.Type {
		case "handshake":
			// Received peer's public key, establish encryption
			h.mu.Lock()
			h.peerPublicKey = msg.PublicKey
			
			// Compute shared secret using ECDH
			sharedSecret, err := crypto.ComputeSharedSecret(h.ephemeralKey.PrivateKeyBytes(), h.peerPublicKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to compute shared secret")
				h.mu.Unlock()
				continue
			}
			
			// Create session cipher (host is NOT initiator - client initiated connection)
			h.sessionCipher, err = crypto.NewSessionCipher(sharedSecret, false)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create session cipher")
				h.mu.Unlock()
				continue
			}
			h.encryptionReady = true
			h.mu.Unlock()
			
			log.Info().Msg("E2EE handshake complete - encryption established")
			
			// Send our public key back
			if err := h.sendHandshake(); err != nil {
				log.Error().Err(err).Msg("Failed to send handshake")
			}
			
		case "msg":
			h.mu.RLock()
			cipher := h.sessionCipher
			encReady := h.encryptionReady
			h.mu.RUnlock()
			
			var plaintext string
			if encReady && cipher != nil && len(msg.Ciphertext) > 0 {
				// Decrypt message
				decrypted, err := cipher.Decrypt(msg.Ciphertext, msg.Nonce)
				if err != nil {
					log.Error().Err(err).Msg("Failed to decrypt message")
					continue
				}
				plaintext = string(decrypted)
				log.Info().Str("decrypted", plaintext).Msg("Host decrypted message")
			} else {
				// Fallback to unencrypted (shouldn't happen in production)
				plaintext = msg.Data
				log.Warn().Msg("Received unencrypted message")
			}
			
			h.mu.RLock()
			handler := h.onMessage
			h.mu.RUnlock()
			if handler != nil {
				handler(plaintext)
			}
		}
	}
}

func (h *Host) handleDisconnect() {
	h.mu.Lock()
	h.connected = false
	handler := h.onDisconnect
	h.mu.Unlock()

	log.Info().Msg("Client disconnected")
	if handler != nil {
		handler()
	}
}

// Stop stops the host
func (h *Host) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stopped = true
	h.connected = false
	h.encryptionReady = false

	// Destroy session cipher keys
	if h.sessionCipher != nil {
		h.sessionCipher.Destroy()
		h.sessionCipher = nil
	}
	
	// Clear peer public key
	h.peerPublicKey = nil

	if h.conn != nil {
		h.conn.Close()
		h.conn = nil
	}
	if h.listener != nil {
		h.listener.Close()
		h.listener = nil
	}

	log.Info().Msg("P2P host stopped, encryption keys destroyed")
}

// SendMessage sends a message to the connected client
func (h *Host) SendMessage(text []byte) error {
	h.mu.RLock()
	writer := h.writer
	connected := h.connected
	cipher := h.sessionCipher
	encReady := h.encryptionReady
	h.mu.RUnlock()

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
		log.Info().Int("ciphertext_len", len(ciphertext)).Msg("Host sending encrypted message")
	} else {
		// Fallback to unencrypted (shouldn't happen)
		msg = Message{Type: "msg", Data: string(text)}
		log.Warn().Msg("Sending unencrypted message - encryption not ready")
	}
	
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, err := h.writer.WriteString(string(data) + "\n"); err != nil {
		return err
	}
	return h.writer.Flush()
}

// sendHandshake sends our public key to peer
func (h *Host) sendHandshake() error {
	h.mu.RLock()
	writer := h.writer
	ephKey := h.ephemeralKey
	h.mu.RUnlock()

	if writer == nil || ephKey == nil {
		return fmt.Errorf("not ready for handshake")
	}

	msg := Message{Type: "handshake", PublicKey: ephKey.PublicKeyBytes()}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, err := h.writer.WriteString(string(data) + "\n"); err != nil {
		return err
	}
	log.Info().Msg("Host sent handshake with public key")
	return h.writer.Flush()
}

// SetMessageHandler sets callback for incoming messages
func (h *Host) SetMessageHandler(handler func(text string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onMessage = handler
}

// SetDisconnectHandler sets callback for disconnection
func (h *Host) SetDisconnectHandler(handler func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onDisconnect = handler
}

// SetConnectHandler sets callback for client connection
func (h *Host) SetConnectHandler(handler func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onConnect = handler
}

// IsConnected returns connection status
func (h *Host) IsConnected() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.connected
}

func (h *Host) getPublicAddress() string {
	// For local testing, prefer localhost
	// In production, this would need proper NAT traversal
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return fmt.Sprintf("127.0.0.1:%d", h.port)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	
	// If we get a VPN or virtual interface IP, use localhost instead
	ip := localAddr.IP.String()
	if strings.HasPrefix(ip, "198.18.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return fmt.Sprintf("127.0.0.1:%d", h.port)
	}
	
	return fmt.Sprintf("%s:%d", ip, h.port)
}
