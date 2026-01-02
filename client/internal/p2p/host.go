package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/logmessager/client/internal/crypto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

// Host represents a P2P host that accepts incoming connections
type Host struct {
	mu           sync.Mutex
	listener     net.Listener
	server       *grpc.Server
	port         int
	portRange    [2]int
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

// NewHost creates a new P2P host
func NewHost(portRangeStart, portRangeEnd int, identityKey *crypto.KeyPair) *Host {
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{
		portRange:   [2]int{portRangeStart, portRangeEnd},
		identityKey: identityKey,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts listening for incoming connections
func (h *Host) Start(sessionToken string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sessionToken = sessionToken

	// Generate ephemeral key for this session
	var err error
	h.ephemeralKey, err = crypto.GenerateEphemeralKeyPair()
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Find available port in range
	var listener net.Listener
	for port := h.portRange[0]; port <= h.portRange[1]; port++ {
		addr := fmt.Sprintf(":%d", port)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			h.port = port
			break
		}
	}

	if listener == nil {
		return "", fmt.Errorf("no available port in range %d-%d", h.portRange[0], h.portRange[1])
	}

	h.listener = listener

	// Create gRPC server
	h.server = grpc.NewServer()
	// Register ChatService here when proto is generated

	// Start serving in background
	go func() {
		if err := h.server.Serve(listener); err != nil {
			log.Error().Err(err).Msg("P2P server error")
		}
	}()

	// Get public address
	publicAddr, err := h.getPublicAddress()
	if err != nil {
		// Fallback to local address
		publicAddr = fmt.Sprintf("127.0.0.1:%d", h.port)
	}

	log.Info().
		Int("port", h.port).
		Str("address", publicAddr).
		Msg("P2P host started")

	return publicAddr, nil
}

// Stop stops the host
func (h *Host) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cancel()

	if h.server != nil {
		h.server.GracefulStop()
	}

	if h.listener != nil {
		h.listener.Close()
	}

	// Destroy session cipher
	if h.sessionCipher != nil {
		h.sessionCipher.Destroy()
		h.sessionCipher = nil
	}

	// Clear ephemeral key
	h.ephemeralKey = nil

	log.Info().Msg("P2P host stopped")
}

// SetMessageHandler sets callback for incoming messages
func (h *Host) SetMessageHandler(handler func(msg []byte)) {
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

// SendMessage encrypts and sends a message
func (h *Host) SendMessage(plaintext []byte) error {
	h.mu.Lock()
	cipher := h.sessionCipher
	h.mu.Unlock()

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

// getPublicAddress attempts to determine public IP address
func (h *Host) getPublicAddress() (string, error) {
	// Try to get outbound IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return fmt.Sprintf("%s:%d", localAddr.IP.String(), h.port), nil
}

// GetEphemeralPublicKey returns the ephemeral public key for handshake
func (h *Host) GetEphemeralPublicKey() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	if h.ephemeralKey == nil {
		return nil
	}
	return h.ephemeralKey.PublicKeyBytes()
}

// EstablishSession completes key exchange and creates session cipher
func (h *Host) EstablishSession(peerEphemeralKey []byte, isInitiator bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ephemeralKey == nil {
		return fmt.Errorf("ephemeral key not generated")
	}

	// Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(
		h.ephemeralKey.PrivateKeyBytes(),
		peerEphemeralKey,
	)
	if err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}

	// Create session cipher
	h.sessionCipher, err = crypto.NewSessionCipher(sharedSecret, isInitiator)
	if err != nil {
		return fmt.Errorf("create session cipher: %w", err)
	}

	// Clear shared secret from memory
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	h.connected = true
	return nil
}
