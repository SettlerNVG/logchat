package reconnect

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Manager handles automatic reconnection with exponential backoff
type Manager struct {
	mu            sync.RWMutex
	maxAttempts   int
	baseDelay     time.Duration
	maxDelay      time.Duration
	jitterFactor  float64
	onReconnect   func() error
	onGiveUp      func()
	onAttempt     func(attempt int, delay time.Duration)

	attempt      int
	reconnecting bool
	cancel       context.CancelFunc
	ctx          context.Context
}

// Config for reconnection manager
type Config struct {
	MaxAttempts  int           // Maximum reconnection attempts (0 = infinite)
	BaseDelay    time.Duration // Initial delay between attempts
	MaxDelay     time.Duration // Maximum delay between attempts
	JitterFactor float64       // Jitter factor (0.0 - 1.0)
}

// DefaultConfig returns default reconnection configuration
func DefaultConfig() Config {
	return Config{
		MaxAttempts:  10,
		BaseDelay:    1 * time.Second,
		MaxDelay:     60 * time.Second,
		JitterFactor: 0.25,
	}
}

// NewManager creates a new reconnection manager
func NewManager(cfg Config, onReconnect func() error) *Manager {
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 10
	}
	if cfg.BaseDelay == 0 {
		cfg.BaseDelay = 1 * time.Second
	}
	if cfg.MaxDelay == 0 {
		cfg.MaxDelay = 60 * time.Second
	}
	if cfg.JitterFactor == 0 {
		cfg.JitterFactor = 0.25
	}

	return &Manager{
		maxAttempts:  cfg.MaxAttempts,
		baseDelay:    cfg.BaseDelay,
		maxDelay:     cfg.MaxDelay,
		jitterFactor: cfg.JitterFactor,
		onReconnect:  onReconnect,
	}
}

// SetGiveUpHandler sets callback for when max attempts reached
func (m *Manager) SetGiveUpHandler(handler func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onGiveUp = handler
}

// SetAttemptHandler sets callback for each reconnection attempt
func (m *Manager) SetAttemptHandler(handler func(attempt int, delay time.Duration)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onAttempt = handler
}

// Start begins the reconnection process
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.reconnecting {
		m.mu.Unlock()
		return
	}

	m.reconnecting = true
	m.attempt = 0

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.ctx = ctx
	m.mu.Unlock()

	log.Info().Msg("Starting reconnection manager")
	go m.reconnectLoop()
}

// Stop stops the reconnection process
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.reconnecting {
		return
	}

	if m.cancel != nil {
		m.cancel()
	}

	m.reconnecting = false
	m.attempt = 0

	log.Info().Msg("Stopped reconnection manager")
}

// IsReconnecting returns true if currently attempting to reconnect
func (m *Manager) IsReconnecting() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reconnecting
}

// CurrentAttempt returns the current attempt number
func (m *Manager) CurrentAttempt() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attempt
}

// reconnectLoop performs reconnection attempts with exponential backoff
func (m *Manager) reconnectLoop() {
	for {
		m.mu.Lock()
		m.attempt++
		attempt := m.attempt
		maxAttempts := m.maxAttempts
		ctx := m.ctx
		m.mu.Unlock()

		// Check if max attempts reached
		if maxAttempts > 0 && attempt > maxAttempts {
			log.Error().
				Int("attempts", attempt-1).
				Msg("Max reconnection attempts reached")

			m.mu.RLock()
			giveUpHandler := m.onGiveUp
			m.mu.RUnlock()

			if giveUpHandler != nil {
				giveUpHandler()
			}

			m.Stop()
			return
		}

		// Calculate delay with exponential backoff and jitter
		delay := m.calculateDelay(attempt)

		log.Info().
			Int("attempt", attempt).
			Dur("delay", delay).
			Msg("Reconnecting...")

		// Notify about attempt
		m.mu.RLock()
		attemptHandler := m.onAttempt
		m.mu.RUnlock()

		if attemptHandler != nil {
			attemptHandler(attempt, delay)
		}

		// Wait before attempting
		select {
		case <-time.After(delay):
			// Try to reconnect
			m.mu.RLock()
			reconnectFunc := m.onReconnect
			m.mu.RUnlock()

			if reconnectFunc != nil {
				err := reconnectFunc()
				if err == nil {
					log.Info().
						Int("attempt", attempt).
						Msg("✓ Reconnected successfully")

					m.Stop()
					return
				}

				log.Warn().
					Err(err).
					Int("attempt", attempt).
					Msg("Reconnection failed")
			}

		case <-ctx.Done():
			log.Info().Msg("Reconnection cancelled")
			m.Stop()
			return
		}
	}
}

// calculateDelay calculates delay with exponential backoff and jitter
func (m *Manager) calculateDelay(attempt int) time.Duration {
	// Exponential backoff: baseDelay * 2^(attempt-1)
	delay := float64(m.baseDelay) * math.Pow(2, float64(attempt-1))

	// Cap at maxDelay
	if delay > float64(m.maxDelay) {
		delay = float64(m.maxDelay)
	}

	// Add jitter to prevent thundering herd
	// jitter = delay * jitterFactor * random(-1, 1)
	jitter := delay * m.jitterFactor * (rand.Float64()*2 - 1)
	delay += jitter

	// Ensure delay is positive
	if delay < 0 {
		delay = float64(m.baseDelay)
	}

	return time.Duration(delay)
}

// Reset resets the attempt counter (useful after successful operation)
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempt = 0
}
