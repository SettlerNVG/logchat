package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	pb "github.com/logmessager/proto/gen"

	"github.com/logmessager/client/internal/config"
	"github.com/logmessager/client/internal/crypto"
	"github.com/logmessager/client/internal/nat"
	"github.com/logmessager/client/internal/p2p"
	"github.com/logmessager/client/internal/reconnect"
	"github.com/logmessager/client/internal/storage"
	tlsutil "github.com/logmessager/client/internal/tls"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// Client is the main LogChat client
type Client struct {
	mu sync.RWMutex

	cfg     *config.Config
	storage *storage.Storage
	conn    *grpc.ClientConn

	// gRPC clients
	authClient    pb.AuthServiceClient
	userClient    pb.UserServiceClient
	sessionClient pb.SessionServiceClient

	// Identity
	encryptionKey *crypto.KeyPair
	signatureKey  *crypto.SigningKeyPair
	credentials   *storage.Credentials

	// Reconnection
	reconnectMgr *reconnect.Manager

	// P2P
	p2pHost   *p2p.Host
	p2pClient *p2p.Client
	
	// P2P handlers (stored to apply when host/client created)
	onMessage    func(text string)
	onDisconnect func()
	onConnect    func()

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
	encryptionKey, signatureKey, err := store.LoadOrCreateKeys()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// Don't load saved credentials - require fresh login each time
	// This allows multiple clients on same machine for testing

	client := &Client{
		cfg:           cfg,
		storage:       store,
		encryptionKey: encryptionKey,
		signatureKey:  signatureKey,
		credentials:   nil,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Setup reconnection manager
	reconnectCfg := reconnect.DefaultConfig()
	client.reconnectMgr = reconnect.NewManager(reconnectCfg, func() error {
		return client.reconnectToServer()
	})

	return client, nil
}

// reconnectToServer attempts to reconnect to the server
func (c *Client) reconnectToServer() error {
	log.Info().Msg("Attempting to reconnect to server...")

	// Close old connection
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()

	// Try to connect
	if err := c.Connect(); err != nil {
		return fmt.Errorf("reconnect failed: %w", err)
	}

	// Update presence if logged in
	if c.IsLoggedIn() {
		if err := c.UpdatePresence(true); err != nil {
			log.Warn().Err(err).Msg("Failed to update presence after reconnect")
		}
	}

	return nil
}

// Connect establishes connection to central server
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Check if connection is still alive
		state := c.conn.GetState()
		if state == connectivity.Ready || state == connectivity.Idle {
			return nil
		}
		// Connection is dead, close it
		c.conn.Close()
		c.conn = nil
	}

	var opts []grpc.DialOption

	// Add TLS if enabled
	if c.cfg.Server.TLS.Enabled {
		creds, err := tlsutil.LoadClientCredentials(
			c.cfg.Server.TLS.CAFile,
			c.cfg.Server.TLS.ServerName,
		)
		if err != nil {
			return fmt.Errorf("load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
		log.Info().
			Str("server_name", c.cfg.Server.TLS.ServerName).
			Msg("TLS enabled for gRPC client")
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		log.Warn().Msg("TLS disabled - insecure connection!")
	}

	// Add keepalive parameters
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10 * time.Second, // Send ping every 10s
		Timeout:             3 * time.Second,  // Wait 3s for pong
		PermitWithoutStream: true,             // Send pings even without active streams
	}))

	// Add connection state monitoring
	opts = append(opts, grpc.WithBlock()) // Wait for connection to be ready

	// Create connection with timeout
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.cfg.Server.Address, opts...)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}

	c.conn = conn
	c.authClient = pb.NewAuthServiceClient(conn)
	c.userClient = pb.NewUserServiceClient(conn)
	c.sessionClient = pb.NewSessionServiceClient(conn)

	log.Info().Str("address", c.cfg.Server.Address).Msg("Connected to server")

	// Start monitoring connection state
	go c.monitorConnection()

	return nil
}

// monitorConnection monitors the gRPC connection state
func (c *Client) monitorConnection() {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return
	}

	for {
		state := conn.GetState()
		
		// Wait for state change
		if !conn.WaitForStateChange(c.ctx, state) {
			// Context cancelled
			return
		}

		newState := conn.GetState()
		log.Debug().
			Str("old_state", state.String()).
			Str("new_state", newState.String()).
			Msg("Connection state changed")

		// If connection failed, start reconnection
		if newState == connectivity.TransientFailure || newState == connectivity.Shutdown {
			log.Warn().Str("state", newState.String()).Msg("Connection lost, starting reconnection")
			
			c.mu.RLock()
			reconnectMgr := c.reconnectMgr
			c.mu.RUnlock()

			if reconnectMgr != nil && !reconnectMgr.IsReconnecting() {
				reconnectMgr.Start(c.ctx)
			}
			return
		}
	}
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
	// Stop reconnection manager
	if c.reconnectMgr != nil {
		c.reconnectMgr.Stop()
	}

	c.cancel()
	c.Disconnect()

	if c.p2pHost != nil {
		c.p2pHost.Stop()
	}
	if c.p2pClient != nil {
		c.p2pClient.Disconnect()
	}
}

// Reconnect changes server address and reconnects
func (c *Client) Reconnect(serverAddr string) error {
	// Close existing connection
	c.Disconnect()

	// Update server address
	c.cfg.Server.Address = serverAddr

	// Auto-enable TLS for non-localhost and non-ngrok
	if !isLocalhost(serverAddr) && !isNgrok(serverAddr) {
		c.cfg.Server.TLS.Enabled = true
		// Auto-detect server name
		c.cfg.Server.TLS.ServerName = extractHostname(serverAddr)
	} else {
		c.cfg.Server.TLS.Enabled = false
	}

	log.Info().Str("address", serverAddr).Bool("tls", c.cfg.Server.TLS.Enabled).Msg("Reconnecting to new server")

	// Connect will be called on next operation
	return nil
}

func isLocalhost(addr string) bool {
	return strings.HasPrefix(addr, "localhost:") ||
		strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "[::1]:")
}

func isNgrok(addr string) bool {
	return strings.Contains(addr, "ngrok.io")
}

func extractHostname(addr string) string {
	// Handle IPv6 addresses like [::1]:50051
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]"); idx != -1 {
			return addr[1:idx]
		}
	}
	
	// Handle regular addresses like localhost:50051
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	
	return addr
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

	encPubKey := c.encryptionKey.PublicKeyBytes()
	sigPubKey := c.signatureKey.PublicKey
	
	log.Debug().
		Int("enc_key_len", len(encPubKey)).
		Int("sig_key_len", len(sigPubKey)).
		Msg("Registering with keys")

	resp, err := c.authClient.Register(c.ctx, &pb.RegisterRequest{
		Username:            username,
		Password:            password,
		EncryptionPublicKey: encPubKey,
		SignaturePublicKey:  sigPubKey,
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	log.Info().Str("username", resp.Username).Str("user_id", resp.UserId).Msg("Registered successfully")
	return nil
}

// Login authenticates with the server
func (c *Client) Login(username, password string) error {
	if err := c.Connect(); err != nil {
		return err
	}

	resp, err := c.authClient.Login(c.ctx, &pb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
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

	if err := c.storage.SaveCredentials(c.credentials); err != nil {
		log.Warn().Err(err).Msg("Failed to save credentials")
	}

	log.Info().Str("username", username).Msg("Logged in successfully")

	// Update presence to online
	go func() {
		if err := c.UpdatePresence(true); err != nil {
			log.Warn().Err(err).Msg("Failed to update presence")
		}
	}()

	return nil
}

// Logout logs out from the server
func (c *Client) Logout() error {
	c.mu.Lock()
	creds := c.credentials
	c.credentials = nil
	c.mu.Unlock()

	// Try to logout on server if we have credentials
	if creds != nil && creds.RefreshToken != "" && c.authClient != nil {
		_, _ = c.authClient.Logout(c.ctx, &pb.LogoutRequest{
			RefreshToken: creds.RefreshToken,
		})
	}

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

	var networkCap *pb.NetworkCapability

	if online && c.cfg.STUN.Enabled {
		// Perform STUN discovery
		canAccept, publicAddr, natType := c.discoverNetwork()
		
		networkCap = &pb.NetworkCapability{
			CanAcceptInbound: canAccept,
			PublicAddress:    publicAddr,
			NatType:          natType,
		}
	}

	_, err := c.userClient.UpdatePresence(c.authContext(), &pb.UpdatePresenceRequest{
		IsOnline: online,
		Network:  networkCap,
	})
	if err != nil {
		return fmt.Errorf("update presence: %w", err)
	}

	c.mu.Lock()
	c.isOnline = online
	c.mu.Unlock()

	log.Debug().
		Bool("online", online).
		Msg("Presence updated")

	return nil
}

// discoverNetwork performs STUN discovery to determine network capabilities
func (c *Client) discoverNetwork() (bool, string, pb.NatType) {
	// Try STUN discovery
	result, err := nat.DiscoverWithFallback(c.cfg.STUN.Servers, 0)
	if err != nil {
		log.Warn().Err(err).Msg("STUN discovery failed, using fallback")
		return c.checkNetworkCapabilityFallback()
	}

	log.Info().
		Str("public_ip", result.PublicIP).
		Int("public_port", result.PublicPort).
		Str("nat_type", result.NATType).
		Bool("can_accept", result.CanAccept).
		Msg("Network discovered via STUN")

	natType := convertNATType(result.NATType)
	publicAddr := fmt.Sprintf("%s:%d", result.PublicIP, result.PublicPort)

	return result.CanAccept, publicAddr, natType
}

// checkNetworkCapabilityFallback is the old method without STUN
func (c *Client) checkNetworkCapabilityFallback() (bool, string, pb.NatType) {
	// Try to start a temporary listener
	host := p2p.NewHost(c.cfg.P2P.PortRangeStart, c.cfg.P2P.PortRangeEnd, c.encryptionKey, c.signatureKey)
	addr, err := host.Start("test")
	host.Stop()

	if err != nil {
		return false, "", pb.NatType_NAT_TYPE_UNSPECIFIED
	}

	return true, addr, pb.NatType_NAT_TYPE_NONE
}

func convertNATType(natType string) pb.NatType {
	switch natType {
	case "None":
		return pb.NatType_NAT_TYPE_NONE
	case "Full Cone":
		return pb.NatType_NAT_TYPE_FULL_CONE
	case "Symmetric":
		return pb.NatType_NAT_TYPE_SYMMETRIC
	case "Restricted":
		return pb.NatType_NAT_TYPE_RESTRICTED
	default:
		return pb.NatType_NAT_TYPE_UNSPECIFIED
	}
}

// ListOnlineUsers returns list of online users
func (c *Client) ListOnlineUsers() ([]UserInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	resp, err := c.userClient.ListOnlineUsers(c.authContext(), &pb.ListOnlineUsersRequest{
		Limit: 50,
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	// Filter out current user
	currentUserID := c.GetUserID()
	users := make([]UserInfo, 0, len(resp.Users))
	for _, u := range resp.Users {
		if u.Id != currentUserID {
			users = append(users, UserInfo{
				ID:       u.Id,
				Username: u.Username,
				IsOnline: u.IsOnline,
			})
		}
	}
	return users, nil
}

// SearchUsers searches for users by username
func (c *Client) SearchUsers(query string) ([]UserInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	resp, err := c.userClient.SearchUsers(c.authContext(), &pb.SearchUsersRequest{
		Query: query,
		Limit: 20,
	})
	if err != nil {
		return nil, fmt.Errorf("search users: %w", err)
	}

	// Filter out current user
	currentUserID := c.GetUserID()
	users := make([]UserInfo, 0, len(resp.Users))
	for _, u := range resp.Users {
		if u.Id != currentUserID {
			users = append(users, UserInfo{
				ID:       u.Id,
				Username: u.Username,
				IsOnline: u.IsOnline,
			})
		}
	}
	return users, nil
}

// ContactInfo represents a contact
type ContactInfo struct {
	ID       string
	UserID   string
	Username string
	Nickname string
	IsOnline bool
}

// AddContact adds a user to contacts by username
func (c *Client) AddContact(username, nickname string) (*ContactInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	resp, err := c.userClient.AddContact(c.authContext(), &pb.AddContactRequest{
		Username: username,
		Nickname: nickname,
	})
	if err != nil {
		return nil, fmt.Errorf("add contact: %w", err)
	}

	return &ContactInfo{
		ID:       resp.Contact.Id,
		UserID:   resp.Contact.UserId,
		Username: resp.Contact.Username,
		Nickname: resp.Contact.Nickname,
		IsOnline: resp.Contact.IsOnline,
	}, nil
}

// RemoveContact removes a contact
func (c *Client) RemoveContact(contactID string) error {
	if !c.IsLoggedIn() {
		return fmt.Errorf("not logged in")
	}

	_, err := c.userClient.RemoveContact(c.authContext(), &pb.RemoveContactRequest{
		ContactId: contactID,
	})
	if err != nil {
		return fmt.Errorf("remove contact: %w", err)
	}

	return nil
}

// ListContacts returns user's contact list
func (c *Client) ListContacts() ([]ContactInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	if c.userClient == nil {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
	}

	resp, err := c.userClient.ListContacts(c.authContext(), &pb.ListContactsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}

	contacts := make([]ContactInfo, len(resp.Contacts))
	for i, ct := range resp.Contacts {
		contacts[i] = ContactInfo{
			ID:       ct.Id,
			UserID:   ct.UserId,
			Username: ct.Username,
			Nickname: ct.Nickname,
			IsOnline: ct.IsOnline,
		}
	}
	return contacts, nil
}

// RequestChat initiates a chat with another user
func (c *Client) RequestChat(targetUserID string) (string, error) {
	if !c.IsLoggedIn() {
		return "", fmt.Errorf("not logged in")
	}

	resp, err := c.sessionClient.RequestChat(c.authContext(), &pb.RequestChatRequest{
		TargetUserId: targetUserID,
	})
	if err != nil {
		return "", fmt.Errorf("request chat: %w", err)
	}

	log.Info().Str("target", targetUserID).Str("request_id", resp.RequestId).Msg("Chat request sent")
	return resp.RequestId, nil
}

// AcceptChat accepts an incoming chat request
func (c *Client) AcceptChat(requestID string) (*SessionInfo, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	resp, err := c.sessionClient.AcceptChat(c.authContext(), &pb.AcceptChatRequest{
		RequestId: requestID,
	})
	if err != nil {
		return nil, fmt.Errorf("accept chat: %w", err)
	}

	return &SessionInfo{
		SessionID:                resp.Session.SessionId,
		HostUserID:               resp.Session.HostUserId,
		SessionToken:             resp.Session.SessionToken,
		PeerEncryptionPublicKey:  resp.Session.PeerEncryptionPublicKey,
		PeerSignaturePublicKey:   resp.Session.PeerSignaturePublicKey,
		PeerUsername:             resp.Session.PeerUsername,
		IsHost:                   resp.Session.MyRole == pb.Role_ROLE_HOST,
	}, nil
}

// DeclineChat declines an incoming chat request
func (c *Client) DeclineChat(requestID string) error {
	if !c.IsLoggedIn() {
		return fmt.Errorf("not logged in")
	}

	_, err := c.sessionClient.DeclineChat(c.authContext(), &pb.DeclineChatRequest{
		RequestId: requestID,
	})
	if err != nil {
		return fmt.Errorf("decline chat: %w", err)
	}

	return nil
}

// ChatRequestInfo represents an incoming chat request
type ChatRequestInfo struct {
	RequestID    string
	FromUserID   string
	FromUsername string
}

// SubscribeSessionEvents subscribes to session events and returns a channel
func (c *Client) SubscribeSessionEvents() (<-chan interface{}, error) {
	if !c.IsLoggedIn() {
		return nil, fmt.Errorf("not logged in")
	}

	if c.sessionClient == nil {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
	}

	stream, err := c.sessionClient.SubscribeSessionEvents(c.authContext(), &pb.SubscribeSessionEventsRequest{})
	if err != nil {
		return nil, fmt.Errorf("subscribe events: %w", err)
	}

	eventCh := make(chan interface{}, 10)

	go func() {
		defer close(eventCh)
		for {
			event, err := stream.Recv()
			if err != nil {
				log.Debug().Err(err).Msg("Session event stream ended")
				return
			}

			switch e := event.Event.(type) {
			case *pb.SessionEvent_ChatRequest:
				log.Info().Str("request_id", e.ChatRequest.RequestId).Str("from", e.ChatRequest.FromUsername).Msg("Received chat request event")
				eventCh <- ChatRequestInfo{
					RequestID:    e.ChatRequest.RequestId,
					FromUserID:   e.ChatRequest.FromUserId,
					FromUsername: e.ChatRequest.FromUsername,
				}
			case *pb.SessionEvent_SessionStarted:
				log.Info().Str("session_id", e.SessionStarted.Session.SessionId).Str("peer", e.SessionStarted.Session.PeerUsername).Msg("Received session started event")
				eventCh <- SessionInfo{
					SessionID:                e.SessionStarted.Session.SessionId,
					HostUserID:               e.SessionStarted.Session.HostUserId,
					SessionToken:             e.SessionStarted.Session.SessionToken,
					PeerEncryptionPublicKey:  e.SessionStarted.Session.PeerEncryptionPublicKey,
					PeerSignaturePublicKey:   e.SessionStarted.Session.PeerSignaturePublicKey,
					PeerUsername:             e.SessionStarted.Session.PeerUsername,
					IsHost:                   e.SessionStarted.Session.MyRole == pb.Role_ROLE_HOST,
				}
			case *pb.SessionEvent_HostReady:
				log.Info().Str("session_id", e.HostReady.SessionId).Str("host_addr", e.HostReady.HostAddress).Msg("Received host ready event")
				eventCh <- HostReadyInfo{
					SessionID:   e.HostReady.SessionId,
					HostAddress: e.HostReady.HostAddress,
				}
			case *pb.SessionEvent_SessionEnded:
				log.Info().Str("session_id", e.SessionEnded.SessionId).Msg("Received session ended event")
				eventCh <- SessionEndedInfo{
					SessionID: e.SessionEnded.SessionId,
				}
			}
		}
	}()

	return eventCh, nil
}

// HostReadyInfo represents host ready event
type HostReadyInfo struct {
	SessionID   string
	HostAddress string
}

// SessionEndedInfo represents session ended event
type SessionEndedInfo struct {
	SessionID string
}

// UserInfo represents basic user information
type UserInfo struct {
	ID       string
	Username string
	IsOnline bool
}

// SessionInfo represents chat session information
type SessionInfo struct {
	SessionID                string
	PeerID                   string
	PeerUsername             string
	HostUserID               string
	HostAddress              string
	SessionToken             string
	PeerEncryptionPublicKey  []byte
	PeerSignaturePublicKey   []byte
	IsHost                   bool
}

// StartP2PHost starts P2P server for hosting a chat
func (c *Client) StartP2PHost(sessionToken string, peerEncPubKey, peerSigPubKey []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.p2pHost != nil {
		c.p2pHost.Stop()
	}

	c.p2pHost = p2p.NewHost(c.cfg.P2P.PortRangeStart, c.cfg.P2P.PortRangeEnd, c.encryptionKey, c.signatureKey)
	
	// Set peer's public keys for signature verification
	c.p2pHost.SetPeerPublicKeys(peerEncPubKey, peerSigPubKey)
	
	// Apply stored handlers
	if c.onMessage != nil {
		c.p2pHost.SetMessageHandler(c.onMessage)
	}
	if c.onDisconnect != nil {
		c.p2pHost.SetDisconnectHandler(c.onDisconnect)
	}
	if c.onConnect != nil {
		c.p2pHost.SetConnectHandler(c.onConnect)
	}
	
	return c.p2pHost.Start(sessionToken)
}

// SetMessageHandler sets callback for incoming P2P messages
func (c *Client) SetMessageHandler(handler func(text string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.onMessage = handler
	
	if c.p2pHost != nil {
		c.p2pHost.SetMessageHandler(handler)
	}
	if c.p2pClient != nil {
		c.p2pClient.SetMessageHandler(handler)
	}
}

// SetDisconnectHandler sets callback for P2P disconnection
func (c *Client) SetDisconnectHandler(handler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.onDisconnect = handler
	
	if c.p2pHost != nil {
		c.p2pHost.SetDisconnectHandler(handler)
	}
	if c.p2pClient != nil {
		c.p2pClient.SetDisconnectHandler(handler)
	}
}

// SetConnectHandler sets callback for P2P connection (host only)
func (c *Client) SetConnectHandler(handler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.onConnect = handler
	
	if c.p2pHost != nil {
		c.p2pHost.SetConnectHandler(handler)
	}
}

// ConnectP2P connects to a P2P host
func (c *Client) ConnectP2P(hostAddress, sessionToken string, peerEncPubKey, peerSigPubKey []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.p2pClient != nil {
		c.p2pClient.Disconnect()
	}

	c.p2pClient = p2p.NewClient(c.encryptionKey, c.signatureKey)
	
	// Apply stored handlers
	if c.onMessage != nil {
		c.p2pClient.SetMessageHandler(c.onMessage)
	}
	if c.onDisconnect != nil {
		c.p2pClient.SetDisconnectHandler(c.onDisconnect)
	}
	
	return c.p2pClient.Connect(hostAddress, sessionToken, peerEncPubKey, peerSigPubKey)
}

// SendMessage sends an encrypted message
func (c *Client) SendMessage(text string) error {
	c.mu.RLock()
	host := c.p2pHost
	client := c.p2pClient
	c.mu.RUnlock()

	log.Info().Str("text", text).Bool("has_host", host != nil).Bool("has_client", client != nil).Msg("SendMessage called")

	payload := []byte(text)

	if host != nil {
		log.Info().Msg("Sending via P2P host")
		return host.SendMessage(payload)
	}
	if client != nil {
		log.Info().Msg("Sending via P2P client")
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

// EndSession ends a session on the server
func (c *Client) EndSession(sessionID string) error {
	if !c.IsLoggedIn() {
		return fmt.Errorf("not logged in")
	}

	if c.sessionClient == nil {
		if err := c.Connect(); err != nil {
			return fmt.Errorf("connect: %w", err)
		}
	}

	_, err := c.sessionClient.EndSession(c.authContext(), &pb.EndSessionRequest{
		SessionId: sessionID,
		Reason:    pb.EndReason_END_REASON_USER_LEFT,
	})
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}

	log.Info().Str("session_id", sessionID).Msg("Session ended on server")
	return nil
}

// ReportHostReady reports to server that P2P host is ready
func (c *Client) ReportHostReady(sessionID, listenAddress string) error {
	if !c.IsLoggedIn() {
		return fmt.Errorf("not logged in")
	}

	if c.sessionClient == nil {
		if err := c.Connect(); err != nil {
			return fmt.Errorf("connect: %w", err)
		}
	}

	_, err := c.sessionClient.ReportHostReady(c.authContext(), &pb.ReportHostReadyRequest{
		SessionId:     sessionID,
		ListenAddress: listenAddress,
	})
	if err != nil {
		return fmt.Errorf("report host ready: %w", err)
	}

	log.Info().Str("session_id", sessionID).Str("address", listenAddress).Msg("Reported host ready to server")
	return nil
}
