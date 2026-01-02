package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/logmessager/client/internal/config"
	"github.com/logmessager/client/internal/crypto"
	"github.com/logmessager/client/internal/p2p"
	"github.com/logmessager/client/internal/storage"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Client is the main LogChat client
type Client struct {
	mu sync.RWMutex

	cfg     *config.Config
	storage *storage.Storage
	conn    *grpc.ClientConn

	// Identity
	identityKey *crypto.KeyPair
	credentials *storage.Credentials

	// P2P
	p2pHost   *p2p.Host
	p2pClient *p2p.Client

	// State
	isOnline bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates a new client instance
func New(cfg *config.Config) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	store := storage.NewStorage(cfg.CredentialsPath(), cfg.KeysPath())

	// Ensure data directory exists
	if err := cfg.EnsureDataDir(); err != nil {
		cancel()
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Load or create identity keys
	identityKey, err := store.LoadOrCreateKeys()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// Load credentials if exist
	creds, _ := store.LoadCredentials()

	return &Client{
		cfg:         cfg,
		storage:     store,
		identityKey: identityKey,
		credentials: creds,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// Connect establishes connection to central server
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	// TODO: Add TLS support
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	conn, err := grpc.DialContext(ctx, c.cfg.Server.Address, opts...)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}

	c.conn = conn
	log.Info().Str("address", c.cfg.Server.Address).Msg("Connected to server")

	return nil
}

// Disconnect closes connection to central server
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Close shuts down the client
func (c *Client) Close() {
	c.cancel()
	c.Disconnect()

	if c.p2pHost != nil {
		c.p2pHost.Stop()
	}
	if c.p2pClient != nil {
		c.p2pClient.Disconnect()
	}
}

// IsLoggedIn returns true if user is logged in
func (c *Client) IsLoggedIn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.credentials != nil && c.credentials.AccessToken != ""
}

// GetUsername returns current username
func (c *Client) GetUsername() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.credentials != nil {
		return c.credentials.Username
	}
	return ""
}

// GetUserID returns current user ID
func (c *Client) GetUserID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.credentials != nil {
		return c.credentials.UserID
	}
	return ""
}

// Register creates a new account
func (c *Client) Register(username, password string) error {
	if err := c.Connect(); err != nil {
		return err
	}

	// This would use generated proto client
	// For now, showing the pattern:
	/*
	client := authpb.NewAuthServiceClient(c.conn)
	resp, err := client.Register(c.ctx, &authpb.RegisterRequest{
		Username:  username,
		Password:  password,
		PublicKey: c.identityKey.PublicKeyBytes(),
	})
	*/

	log.Info().Str("username", username).Msg("Registration would happen here")
	return nil
}

// Login authenticates with the server
func (c *Client) Login(username, password string) error {
	if err := c.Connect(); err != nil {
		return err
	}

	// This would use generated proto client
	/*
	client := authpb.NewAuthServiceClient(c.conn)
	resp, err := client.Login(c.ctx, &authpb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.credentials = &storage.Credentials{
		UserID:       resp.User.Id,
		Username:     resp.User.Username,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
	}
	c.mu.Unlock()

	return c.storage.SaveCredentials(c.credentials)
	*/

	log.Info().Str("username", username).Msg("Login would happen here")
	return nil
}

// Logout logs out from the server
func (c *Client) Logout() error {
	c.mu.Lock()
	c.credentials = nil
	c.mu.Unlock()

	return c.storage.DeleteCredentials()
}

// authContext returns context with authorization header
func (c *Client) authContext() context.Context {
	c.mu.RLock()
	token := ""
	if c.credentials != nil {
		token = c.credentials.AccessToken
	}
	c.mu.RUnlock()

	if token == "" {
		return c.ctx
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(c.ctx, md)
}

// UpdatePresence updates online status
func (c *Client) UpdatePresence(online bool) error {
	if !c.IsLoggedIn() {
		return fmt.Errorf("not logged in")
	}

	// Check if we can accept inbound connections
	canAccept, publicAddr := c.checkNetworkCapability()

	// This would use generated proto client
	/*
	client := userpb.NewUserServiceClient(c.conn)
	_, err := client.UpdatePresence(c.authContext(), &userpb.UpdatePresenceRequest{
		IsOnline: online,
		Network: &userpb.NetworkCapability{
			CanAcceptInbound: canAccept,
			PublicAddress:    publicAddr,
		},
	})
	*/

	c.mu.Lock()
	c.isOnline = online
	c.mu.Unlock()

	log.Debug().
		Bool("online", online).
		Bool("can_accept", canAccept).
		Str("public_addr", publicAddr).
		Msg("Presence updated")

	return nil
}

// checkNetworkCapability tests if we can accept incoming connections
func (c *Client) checkNetworkCapability() (bool, string) {
	// Try to start a temporary listener
	host := p2p.NewHost(c.cfg.P2P.PortRangeStart, c.cfg.P2P.PortRangeEnd, c.identityKey)
	addr, err := host.Start("test")
	host.Stop()

	if err != nil {
		return false, ""
	}

	return true, addr
}

// ListOnlineUsers returns list of online users
func (c *Client) ListOnlineUsers() ([]UserInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	// This would use generated proto client
	/*
	client := userpb.NewUserServiceClient(c.conn)
	resp, err := client.ListOnlineUsers(c.authContext(), &userpb.ListOnlineUsersRequest{
		Limit: 50,
	})
	if err != nil {
		return nil, err
	}

	users := make([]UserInfo, len(resp.Users))
	for i, u := range resp.Users {
		users[i] = UserInfo{
			ID:       u.Id,
			Username: u.Username,
			IsOnline: u.IsOnline,
		}
	}
	return users, nil
	*/

	// Mock data for now
	return []UserInfo{
		{ID: "1", Username: "alice", IsOnline: true},
		{ID: "2", Username: "bob", IsOnline: true},
	}, nil
}

// RequestChat initiates a chat with another user
func (c *Client) RequestChat(targetUserID string) (string, error) {
	if !c.IsLoggedIn() {
		return "", fmt.Errorf("not logged in")
	}

	// This would use generated proto client
	/*
	client := sessionpb.NewSessionServiceClient(c.conn)
	resp, err := client.RequestChat(c.authContext(), &sessionpb.RequestChatRequest{
		TargetUserId: targetUserID,
	})
	if err != nil {
		return "", err
	}
	return resp.RequestId, nil
	*/

	log.Info().Str("target", targetUserID).Msg("Chat request would be sent")
	return "mock-request-id", nil
}

// UserInfo represents basic user information
type UserInfo struct {
	ID       string
	Username string
	IsOnline bool
}

// SessionInfo represents chat session information
type SessionInfo struct {
	SessionID     string
	PeerID        string
	PeerUsername  string
	HostUserID    string
	HostAddress   string
	SessionToken  string
	PeerPublicKey []byte
	IsHost        bool
}

// StartP2PHost starts P2P server for hosting a chat
func (c *Client) StartP2PHost(sessionToken string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.p2pHost != nil {
		c.p2pHost.Stop()
	}

	c.p2pHost = p2p.NewHost(c.cfg.P2P.PortRangeStart, c.cfg.P2P.PortRangeEnd, c.identityKey)
	return c.p2pHost.Start(sessionToken)
}

// ConnectP2P connects to a P2P host
func (c *Client) ConnectP2P(hostAddress, sessionToken string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.p2pClient != nil {
		c.p2pClient.Disconnect()
	}

	c.p2pClient = p2p.NewClient(c.identityKey)
	return c.p2pClient.Connect(hostAddress, sessionToken)
}

// SendMessage sends an encrypted message
func (c *Client) SendMessage(text string) error {
	c.mu.RLock()
	host := c.p2pHost
	client := c.p2pClient
	c.mu.RUnlock()

	payload := []byte(text)

	if host != nil {
		return host.SendMessage(payload)
	}
	if client != nil {
		return client.SendMessage(payload)
	}

	return fmt.Errorf("no active chat session")
}

// EndChat ends the current chat session
func (c *Client) EndChat() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.p2pHost != nil {
		c.p2pHost.Stop()
		c.p2pHost = nil
	}
	if c.p2pClient != nil {
		c.p2pClient.Disconnect()
		c.p2pClient = nil
	}
}
