package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Limiter manages rate limiting for different resources
type Limiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

// NewLimiter creates a new rate limiter
// rate: requests per second
// burst: maximum burst size
func NewLimiter(r rate.Limit, b int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

// GetLimiter returns a rate limiter for the given key (e.g., user ID or IP)
func (l *Limiter) GetLimiter(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[key] = limiter
	}

	return limiter
}

// Allow checks if a request is allowed for the given key
func (l *Limiter) Allow(key string) bool {
	limiter := l.GetLimiter(key)
	return limiter.Allow()
}

// Wait blocks until a request is allowed for the given key
func (l *Limiter) Wait(ctx context.Context, key string) error {
	limiter := l.GetLimiter(key)
	return limiter.Wait(ctx)
}

// Cleanup removes old limiters (call periodically)
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Remove limiters that haven't been used recently
	for key, limiter := range l.limiters {
		// If limiter has full burst capacity, it hasn't been used recently
		if limiter.Tokens() >= float64(l.burst) {
			delete(l.limiters, key)
		}
	}
}

// StartCleanup starts periodic cleanup of old limiters
func (l *Limiter) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			l.Cleanup()
		}
	}()
}

// Config holds rate limiting configuration for different endpoints
type Config struct {
	// Global limits
	GlobalRate  rate.Limit
	GlobalBurst int

	// Per-endpoint limits
	RegisterRate  rate.Limit
	RegisterBurst int

	LoginRate  rate.Limit
	LoginBurst int

	ChatRequestRate  rate.Limit
	ChatRequestBurst int

	MessageRate  rate.Limit
	MessageBurst int
}

// DefaultConfig returns default rate limiting configuration
func DefaultConfig() Config {
	return Config{
		// Global: 100 requests per second, burst of 200
		GlobalRate:  100,
		GlobalBurst: 200,

		// Register: 5 per minute (prevent spam registration)
		RegisterRate:  rate.Every(12 * time.Second),
		RegisterBurst: 5,

		// Login: 10 per minute (prevent brute force)
		LoginRate:  rate.Every(6 * time.Second),
		LoginBurst: 10,

		// Chat requests: 20 per minute
		ChatRequestRate:  rate.Every(3 * time.Second),
		ChatRequestBurst: 20,

		// Messages: 60 per minute
		MessageRate:  rate.Every(time.Second),
		MessageBurst: 60,
	}
}

// Manager manages multiple rate limiters
type Manager struct {
	global      *Limiter
	register    *Limiter
	login       *Limiter
	chatRequest *Limiter
	message     *Limiter
}

// NewManager creates a new rate limit manager
func NewManager(cfg Config) *Manager {
	m := &Manager{
		global:      NewLimiter(cfg.GlobalRate, cfg.GlobalBurst),
		register:    NewLimiter(cfg.RegisterRate, cfg.RegisterBurst),
		login:       NewLimiter(cfg.LoginRate, cfg.LoginBurst),
		chatRequest: NewLimiter(cfg.ChatRequestRate, cfg.ChatRequestBurst),
		message:     NewLimiter(cfg.MessageRate, cfg.MessageBurst),
	}

	// Start cleanup for all limiters
	m.global.StartCleanup(5 * time.Minute)
	m.register.StartCleanup(10 * time.Minute)
	m.login.StartCleanup(10 * time.Minute)
	m.chatRequest.StartCleanup(5 * time.Minute)
	m.message.StartCleanup(1 * time.Minute)

	return m
}

// CheckGlobal checks global rate limit
func (m *Manager) CheckGlobal(key string) error {
	if !m.global.Allow(key) {
		return status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}
	return nil
}

// CheckRegister checks registration rate limit
func (m *Manager) CheckRegister(key string) error {
	if !m.register.Allow(key) {
		return status.Error(codes.ResourceExhausted, "too many registration attempts, please try again later")
	}
	return nil
}

// CheckLogin checks login rate limit
func (m *Manager) CheckLogin(key string) error {
	if !m.login.Allow(key) {
		return status.Error(codes.ResourceExhausted, "too many login attempts, please try again later")
	}
	return nil
}

// CheckChatRequest checks chat request rate limit
func (m *Manager) CheckChatRequest(key string) error {
	if !m.chatRequest.Allow(key) {
		return status.Error(codes.ResourceExhausted, "too many chat requests, please slow down")
	}
	return nil
}

// CheckMessage checks message rate limit
func (m *Manager) CheckMessage(key string) error {
	if !m.message.Allow(key) {
		return status.Error(codes.ResourceExhausted, "sending messages too fast, please slow down")
	}
	return nil
}

// UnaryInterceptor returns a gRPC unary interceptor for rate limiting
func (m *Manager) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract user ID or IP for rate limiting key
		key := extractKey(ctx)

		// Check global rate limit
		if err := m.CheckGlobal(key); err != nil {
			return nil, err
		}

		// Check method-specific rate limits
		if err := m.checkMethodLimit(info.FullMethod, key); err != nil {
			return nil, err
		}

		// Call the handler
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream interceptor for rate limiting
func (m *Manager) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Extract user ID or IP for rate limiting key
		key := extractKey(ss.Context())

		// Check global rate limit
		if err := m.CheckGlobal(key); err != nil {
			return err
		}

		// Call the handler
		return handler(srv, ss)
	}
}

// checkMethodLimit checks rate limit for specific methods
func (m *Manager) checkMethodLimit(method, key string) error {
	switch method {
	case "/logmessager.auth.v1.AuthService/Register":
		return m.CheckRegister(key)
	case "/logmessager.auth.v1.AuthService/Login":
		return m.CheckLogin(key)
	case "/logmessager.session.v1.SessionService/RequestChat":
		return m.CheckChatRequest(key)
	}
	return nil
}

// extractKey extracts a key for rate limiting from context
// Uses user ID if authenticated, otherwise uses IP address
func extractKey(ctx context.Context) string {
	// Try to get user ID from context (set by auth interceptor)
	if userID, ok := ctx.Value("user_id").(string); ok && userID != "" {
		return fmt.Sprintf("user:%s", userID)
	}

	// Fallback to IP address (would need to be set by another interceptor)
	// For now, use a default key
	return "anonymous"
}
