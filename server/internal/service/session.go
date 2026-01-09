package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/logmessager/server/internal/repository"
	"github.com/rs/zerolog/log"
)

var (
	ErrUserOffline         = errors.New("user is offline")
	ErrNoConnectionPath    = errors.New("no connection path available (both users behind NAT)")
	ErrRequestNotFound     = errors.New("chat request not found")
	ErrAlreadyInSession    = errors.New("user already in active session")
	ErrCannotChatWithSelf  = errors.New("cannot start chat with yourself")
	ErrRequestExpired      = errors.New("chat request expired or already handled")
)

type SessionService struct {
	sessionRepo *repository.SessionRepository
	userRepo    *repository.UserRepository

	// In-memory event subscribers
	mu          sync.RWMutex
	subscribers map[uuid.UUID]chan SessionEvent
}

type SessionEvent struct {
	Type    string
	Payload interface{}
}

type ChatRequestEvent struct {
	RequestID    uuid.UUID
	FromUserID   uuid.UUID
	FromUsername string
}

type SessionStartedEvent struct {
	SessionID     uuid.UUID
	PeerID        uuid.UUID
	PeerUsername  string
	HostUserID    uuid.UUID
	HostAddress   string
	SessionToken  string
	PeerPublicKey []byte
	IsHost        bool
}

type SessionEndedEvent struct {
	SessionID uuid.UUID
	Reason    string
}

type HostReadyEvent struct {
	SessionID   uuid.UUID
	HostAddress string
}

func NewSessionService(sessionRepo *repository.SessionRepository, userRepo *repository.UserRepository) *SessionService {
	return &SessionService{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		subscribers: make(map[uuid.UUID]chan SessionEvent),
	}
}

func (s *SessionService) RequestChat(ctx context.Context, fromUserID, toUserID uuid.UUID) (*repository.ChatRequest, error) {
	log.Info().Str("from", fromUserID.String()).Str("to", toUserID.String()).Msg("RequestChat called")

	// Can't chat with yourself
	if fromUserID == toUserID {
		return nil, ErrCannotChatWithSelf
	}

	// Check if initiator already in session
	existingSession, err := s.sessionRepo.GetActiveSessionForUser(ctx, fromUserID)
	if err == nil {
		log.Warn().Str("session_id", existingSession.ID.String()).Msg("User already in active session")
		return nil, ErrAlreadyInSession
	}

	// Check if target is online
	presence, err := s.userRepo.GetPresence(ctx, toUserID)
	if err != nil {
		log.Error().Err(err).Str("user_id", toUserID.String()).Msg("Failed to get presence")
		return nil, err
	}
	if !presence.IsOnline {
		log.Warn().Str("user_id", toUserID.String()).Msg("Target user is offline")
		return nil, ErrUserOffline
	}

	// Check if target already in session
	_, err = s.sessionRepo.GetActiveSessionForUser(ctx, toUserID)
	if err == nil {
		log.Warn().Str("user_id", toUserID.String()).Msg("Target user already in active session")
		return nil, ErrAlreadyInSession
	}

	// Create chat request
	request, err := s.sessionRepo.CreateChatRequest(ctx, fromUserID, toUserID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create chat request")
		return nil, err
	}

	log.Info().Str("request_id", request.ID.String()).Msg("Chat request created")

	// Notify target user
	fromUser, _ := s.userRepo.GetByID(ctx, fromUserID)
	s.notifyUser(toUserID, SessionEvent{
		Type: "chat_request",
		Payload: ChatRequestEvent{
			RequestID:    request.ID,
			FromUserID:   fromUserID,
			FromUsername: fromUser.Username,
		},
	})

	log.Info().Str("request_id", request.ID.String()).Str("to_user", toUserID.String()).Msg("Notified target user")

	return request, nil
}

func (s *SessionService) AcceptChat(ctx context.Context, requestID uuid.UUID, acceptingUserID uuid.UUID) (*SessionStartedEvent, *SessionStartedEvent, error) {
	log.Info().Str("request_id", requestID.String()).Str("accepting_user", acceptingUserID.String()).Msg("AcceptChat called")

	// Get request
	request, err := s.sessionRepo.GetChatRequest(ctx, requestID)
	if err != nil {
		log.Error().Err(err).Str("request_id", requestID.String()).Msg("Failed to get chat request")
		return nil, nil, ErrRequestNotFound
	}

	log.Info().Str("from_user", request.FromUserID.String()).Str("to_user", request.ToUserID.String()).Str("status", request.Status).Msg("Found chat request")

	// Verify accepting user is the target
	if request.ToUserID != acceptingUserID {
		log.Warn().Str("expected", request.ToUserID.String()).Str("got", acceptingUserID.String()).Msg("Wrong user trying to accept")
		return nil, nil, ErrRequestNotFound
	}

	// Check request is still pending
	if request.Status != "pending" {
		log.Warn().Str("status", request.Status).Msg("Request not pending")
		return nil, nil, ErrRequestExpired
	}

	// Update request status
	if err := s.sessionRepo.UpdateChatRequestStatus(ctx, requestID, "accepted"); err != nil {
		log.Error().Err(err).Msg("Failed to update request status")
		return nil, nil, err
	}

	// Determine host
	initiatorPresence, _ := s.userRepo.GetPresence(ctx, request.FromUserID)
	responderPresence, _ := s.userRepo.GetPresence(ctx, request.ToUserID)

	var hostID uuid.UUID
	if initiatorPresence != nil && initiatorPresence.CanAcceptInbound {
		hostID = request.FromUserID
		log.Info().Str("host", "initiator").Msg("Initiator will be host")
	} else if responderPresence != nil && responderPresence.CanAcceptInbound {
		hostID = request.ToUserID
		log.Info().Str("host", "responder").Msg("Responder will be host")
	} else {
		// Neither can accept inbound - fail
		log.Warn().Msg("Neither user can accept inbound connections")
		_ = s.sessionRepo.UpdateChatRequestStatus(ctx, requestID, "failed")
		return nil, nil, ErrNoConnectionPath
	}

	// Create session
	session, err := s.sessionRepo.CreateSession(ctx, request.FromUserID, request.ToUserID, &hostID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session")
		return nil, nil, err
	}

	log.Info().Str("session_id", session.ID.String()).Str("host_id", hostID.String()).Msg("Session created")

	// Generate session token
	sessionToken := generateSessionToken()

	// Get user info and public keys
	initiator, _ := s.userRepo.GetByID(ctx, request.FromUserID)
	responder, _ := s.userRepo.GetByID(ctx, request.ToUserID)
	initiatorKey, _ := s.userRepo.GetPublicKey(ctx, request.FromUserID)
	responderKey, _ := s.userRepo.GetPublicKey(ctx, request.ToUserID)

	// Prepare events for both users
	initiatorEvent := &SessionStartedEvent{
		SessionID:     session.ID,
		PeerID:        responder.ID,
		PeerUsername:  responder.Username,
		HostUserID:    hostID,
		SessionToken:  sessionToken,
		PeerPublicKey: responderKey.PublicKey,
		IsHost:        hostID == request.FromUserID,
	}

	responderEvent := &SessionStartedEvent{
		SessionID:     session.ID,
		PeerID:        initiator.ID,
		PeerUsername:  initiator.Username,
		HostUserID:    hostID,
		SessionToken:  sessionToken,
		PeerPublicKey: initiatorKey.PublicKey,
		IsHost:        hostID == request.ToUserID,
	}

	// Notify initiator (user A who sent the request)
	log.Info().Str("user_id", request.FromUserID.String()).Str("peer", responder.Username).Bool("is_host", initiatorEvent.IsHost).Msg("Notifying initiator")
	s.notifyUser(request.FromUserID, SessionEvent{
		Type:    "session_started",
		Payload: initiatorEvent,
	})

	return initiatorEvent, responderEvent, nil
}

func (s *SessionService) DeclineChat(ctx context.Context, requestID uuid.UUID, decliningUserID uuid.UUID) error {
	request, err := s.sessionRepo.GetChatRequest(ctx, requestID)
	if err != nil {
		return ErrRequestNotFound
	}

	if request.ToUserID != decliningUserID {
		return ErrRequestNotFound
	}

	if request.Status != "pending" {
		return ErrRequestExpired
	}

	if err := s.sessionRepo.UpdateChatRequestStatus(ctx, requestID, "declined"); err != nil {
		return err
	}

	// Notify initiator
	s.notifyUser(request.FromUserID, SessionEvent{
		Type: "request_cancelled",
		Payload: map[string]interface{}{
			"request_id": requestID,
			"reason":     "declined",
		},
	})

	return nil
}

func (s *SessionService) EndSession(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID, reason string) error {
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Verify user is part of session
	if session.InitiatorID != userID && session.ResponderID != userID {
		return repository.ErrSessionNotFound
	}

	if err := s.sessionRepo.EndSession(ctx, sessionID, reason); err != nil {
		return err
	}

	// Notify both users
	event := SessionEvent{
		Type: "session_ended",
		Payload: SessionEndedEvent{
			SessionID: sessionID,
			Reason:    reason,
		},
	}

	s.notifyUser(session.InitiatorID, event)
	s.notifyUser(session.ResponderID, event)

	return nil
}

func (s *SessionService) ReportHostReady(ctx context.Context, sessionID uuid.UUID, hostUserID uuid.UUID, listenAddress string) error {
	session, err := s.sessionRepo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Determine client user
	var clientUserID uuid.UUID
	if session.InitiatorID == hostUserID {
		clientUserID = session.ResponderID
	} else {
		clientUserID = session.InitiatorID
	}

	// Notify client that host is ready
	s.notifyUser(clientUserID, SessionEvent{
		Type: "host_ready",
		Payload: HostReadyEvent{
			SessionID:   sessionID,
			HostAddress: listenAddress,
		},
	})

	return nil
}

func (s *SessionService) Subscribe(userID uuid.UUID) <-chan SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan SessionEvent, 10)
	s.subscribers[userID] = ch
	log.Info().Str("user_id", userID.String()).Int("total_subscribers", len(s.subscribers)).Msg("User subscribed to session events")
	return ch
}

func (s *SessionService) Unsubscribe(userID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ch, ok := s.subscribers[userID]; ok {
		close(ch)
		delete(s.subscribers, userID)
		log.Info().Str("user_id", userID.String()).Msg("User unsubscribed from session events")
	}
}

func (s *SessionService) notifyUser(userID uuid.UUID, event SessionEvent) {
	s.mu.RLock()
	ch, ok := s.subscribers[userID]
	s.mu.RUnlock()

	if !ok {
		log.Warn().Str("user_id", userID.String()).Str("event_type", event.Type).Msg("User not subscribed, cannot notify")
		return
	}

	select {
	case ch <- event:
		log.Info().Str("user_id", userID.String()).Str("event_type", event.Type).Msg("Event sent to user")
	default:
		log.Warn().Str("user_id", userID.String()).Str("event_type", event.Type).Msg("Channel full, event dropped")
	}
}

func generateSessionToken() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
