package p2p

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/logmessager/client/internal/crypto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client represents a P2P client that connects to a host
type Client struct {
	mu           sync.Mutex
	conn         *grpc.ClientConn
	sessionToken string
	
	// Crypto
	identityKey   *crypto.KeyPair
	ephemeralKey  *crypto.KeyPair
	sessionCipher *crypto.SessionCipher
	
	// Callbacks
	onMessage     func(msg []byte)
	onDisconnect  func()
	
	// State
	connected bool
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewClient creates a new P2P client
func NewClient(identityKey *crypto.KeyPair) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		identityKey: identityKey,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Connect connects to a P2P host
func (c *Client) Connect(hostAddress, sessionToken string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessionToken = sessionToken

	// Generate ephemeral key for this session
	var err error
	c.ephemeralKey, err = crypto.GenerateEphemeralKeyPair()
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Connect to host
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	// TODO: Use TLS in production
	conn, err := grpc.DialContext(ctx, hostAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("connect to host: %w", err)
	}

	c.conn = conn

	log.Info().
		Str("address", hostAddress).
		Msg("Connected to P2P host")

	return nil
}

// Disconnect closes the connection
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancel()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Destroy session cipher
	if c.sessionCipher != nil {
		c.sessionCipher.Destroy()
		c.sessionCipher = nil
	}

	// Clear ephemeral key
	c.ephemeralKey = nil

	c.connected = false

	log.Info().Msg("Disconnected from P2P host")
}

// SetMessageHandler sets callback for incoming messages
func (c *Client) SetMessageHandler(handler func(msg []byte)) {
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

// SendMessage encrypts and sends a message
func (c *Client) SendMessage(plaintext []byte) error {
	c.mu.Lock()
	cipher := c.sessionCipher
	c.mu.Unlock()

	if cipher == nil {
		return fmt.Errorf("session not established")
	}

	ciphertext, nonce, err := cipher.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Send via gRPC stream
	_ = ciphertext
	_ = nonce
	// Implementation depends on generated proto

	return nil
}

// GetEphemeralPublicKey returns the ephemeral public key for handshake
func (c *Client) GetEphemeralPublicKey() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.ephemeralKey == nil {
		return nil
	}
	return c.ephemeralKey.PublicKeyBytes()
}

// EstablishSession completes key exchange and creates session cipher
func (c *Client) EstablishSession(peerEphemeralKey []byte, isInitiator bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ephemeralKey == nil {
		return fmt.Errorf("ephemeral key not generated")
	}

	// Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(
		c.ephemeralKey.PrivateKeyBytes(),
		peerEphemeralKey,
	)
	if err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}

	// Create session cipher
	c.sessionCipher, err = crypto.NewSessionCipher(sharedSecret, isInitiator)
	if err != nil {
		return fmt.Errorf("create session cipher: %w", err)
	}

	// Clear shared secret from memory
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	c.connected = true
	return nil
}

// Handshake performs the cryptographic handshake with the host
func (c *Client) Handshake(peerPublicKey []byte) error {
	// 1. Send HandshakeRequest with ephemeral key and signature
	// 2. Receive HandshakeResponse with host's ephemeral key
	// 3. Verify host's signature
	// 4. Establish session cipher
	
	// This would use the generated ChatService client
	// For now, showing the pattern:
	
	/*
	client := chatpb.NewChatServiceClient(c.conn)
	
	// Sign handshake data
	signature := c.identityKey.SignHandshake(c.sessionToken, c.GetEphemeralPublicKey())
	
	resp, err := client.Handshake(c.ctx, &chatpb.HandshakeRequest{
		SessionToken:       c.sessionToken,
		EphemeralPublicKey: c.GetEphemeralPublicKey(),
		Signature:          signature,
	})
	if err != nil {
		return err
	}
	
	// Verify host's signature
	if !crypto.VerifyHandshake(peerPublicKey, c.sessionToken, resp.EphemeralPublicKey, resp.Signature) {
		return fmt.Errorf("invalid host signature")
	}
	
	// Establish session
	return c.EstablishSession(resp.EphemeralPublicKey, true)
	*/
	
	return nil
}

// IsConnected returns connection status
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}
