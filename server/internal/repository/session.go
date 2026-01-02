package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrRequestNotFound = errors.New("chat request not found")
)

type Session struct {
	ID             uuid.UUID
	InitiatorID    uuid.UUID
	ResponderID    uuid.UUID
	HostID         *uuid.UUID
	ConnectionType string
	Status         string
	StartedAt      time.Time
	EndedAt        *time.Time
	EndReason      string
}

type ChatRequest struct {
	ID          uuid.UUID
	FromUserID  uuid.UUID
	ToUserID    uuid.UUID
	Status      string
	CreatedAt   time.Time
	RespondedAt *time.Time
}

type SessionRepository struct {
	db *DB
}

func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Chat Requests

func (r *SessionRepository) CreateChatRequest(ctx context.Context, fromUserID, toUserID uuid.UUID) (*ChatRequest, error) {
	var req ChatRequest
	err := r.db.Pool.QueryRow(ctx, `
		INSERT INTO chat_requests (from_user_id, to_user_id, status)
		VALUES ($1, $2, 'pending')
		RETURNING id, from_user_id, to_user_id, status, created_at
	`, fromUserID, toUserID).Scan(
		&req.ID, &req.FromUserID, &req.ToUserID, &req.Status, &req.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func (r *SessionRepository) GetChatRequest(ctx context.Context, requestID uuid.UUID) (*ChatRequest, error) {
	var req ChatRequest
	var respondedAt *time.Time

	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, from_user_id, to_user_id, status, created_at, responded_at
		FROM chat_requests WHERE id = $1
	`, requestID).Scan(
		&req.ID, &req.FromUserID, &req.ToUserID, &req.Status, &req.CreatedAt, &respondedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRequestNotFound
		}
		return nil, err
	}
	req.RespondedAt = respondedAt
	return &req, nil
}

func (r *SessionRepository) GetPendingRequestsForUser(ctx context.Context, userID uuid.UUID) ([]ChatRequest, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, from_user_id, to_user_id, status, created_at
		FROM chat_requests
		WHERE to_user_id = $1 AND status = 'pending'
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []ChatRequest
	for rows.Next() {
		var req ChatRequest
		if err := rows.Scan(&req.ID, &req.FromUserID, &req.ToUserID, &req.Status, &req.CreatedAt); err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (r *SessionRepository) UpdateChatRequestStatus(ctx context.Context, requestID uuid.UUID, status string) error {
	result, err := r.db.Pool.Exec(ctx, `
		UPDATE chat_requests
		SET status = $2, responded_at = NOW()
		WHERE id = $1
	`, requestID, status)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrRequestNotFound
	}
	return nil
}

// Sessions

func (r *SessionRepository) CreateSession(ctx context.Context, initiatorID, responderID uuid.UUID, hostID *uuid.UUID) (*Session, error) {
	var session Session
	err := r.db.Pool.QueryRow(ctx, `
		INSERT INTO sessions (initiator_id, responder_id, host_id, status, connection_type)
		VALUES ($1, $2, $3, 'active', 'direct')
		RETURNING id, initiator_id, responder_id, host_id, connection_type, status, started_at
	`, initiatorID, responderID, hostID).Scan(
		&session.ID, &session.InitiatorID, &session.ResponderID, &session.HostID,
		&session.ConnectionType, &session.Status, &session.StartedAt,
	)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	var session Session
	var hostID *uuid.UUID
	var endedAt *time.Time
	var endReason *string

	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, initiator_id, responder_id, host_id, connection_type, status, started_at, ended_at, end_reason
		FROM sessions WHERE id = $1
	`, sessionID).Scan(
		&session.ID, &session.InitiatorID, &session.ResponderID, &hostID,
		&session.ConnectionType, &session.Status, &session.StartedAt, &endedAt, &endReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	session.HostID = hostID
	session.EndedAt = endedAt
	if endReason != nil {
		session.EndReason = *endReason
	}

	return &session, nil
}

func (r *SessionRepository) GetActiveSessionForUser(ctx context.Context, userID uuid.UUID) (*Session, error) {
	var session Session
	var hostID *uuid.UUID

	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, initiator_id, responder_id, host_id, connection_type, status, started_at
		FROM sessions
		WHERE (initiator_id = $1 OR responder_id = $1) AND status = 'active'
		LIMIT 1
	`, userID).Scan(
		&session.ID, &session.InitiatorID, &session.ResponderID, &hostID,
		&session.ConnectionType, &session.Status, &session.StartedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	session.HostID = hostID
	return &session, nil
}

func (r *SessionRepository) EndSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	result, err := r.db.Pool.Exec(ctx, `
		UPDATE sessions
		SET status = 'ended', ended_at = NOW(), end_reason = $2
		WHERE id = $1 AND status = 'active'
	`, sessionID, reason)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (r *SessionRepository) UpdateSessionHost(ctx context.Context, sessionID uuid.UUID, hostID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE sessions SET host_id = $2 WHERE id = $1
	`, sessionID, hostID)
	return err
}
