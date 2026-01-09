package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrContactNotFound = errors.New("contact not found")
	ErrContactExists   = errors.New("contact already exists")
	ErrCannotAddSelf   = errors.New("cannot add yourself as contact")
)

type Contact struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	ContactUserID uuid.UUID
	Nickname      sql.NullString
	CreatedAt     time.Time
}

type ContactWithUser struct {
	Contact
	Username string
	IsOnline bool
	LastSeen time.Time
}

type ContactRepository struct {
	pool *pgxpool.Pool
}

func NewContactRepository(db *DB) *ContactRepository {
	return &ContactRepository{pool: db.Pool}
}

func (r *ContactRepository) Create(ctx context.Context, userID, contactUserID uuid.UUID, nickname string) (*Contact, error) {
	if userID == contactUserID {
		return nil, ErrCannotAddSelf
	}

	contact := &Contact{
		ID:            uuid.New(),
		UserID:        userID,
		ContactUserID: contactUserID,
		CreatedAt:     time.Now(),
	}

	if nickname != "" {
		contact.Nickname = sql.NullString{String: nickname, Valid: true}
	}

	query := `
		INSERT INTO contacts (id, user_id, contact_user_id, nickname, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, contact_user_id) DO NOTHING
		RETURNING id`

	var returnedID uuid.UUID
	err := r.pool.QueryRow(ctx, query,
		contact.ID, contact.UserID, contact.ContactUserID, contact.Nickname, contact.CreatedAt,
	).Scan(&returnedID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrContactExists
		}
		return nil, err
	}

	contact.ID = returnedID
	return contact, nil
}

func (r *ContactRepository) Delete(ctx context.Context, userID, contactID uuid.UUID) error {
	query := `DELETE FROM contacts WHERE id = $1 AND user_id = $2`
	result, err := r.pool.Exec(ctx, query, contactID, userID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return ErrContactNotFound
	}
	return nil
}

func (r *ContactRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]ContactWithUser, error) {
	query := `
		SELECT c.id, c.user_id, c.contact_user_id, c.nickname, c.created_at,
		       u.username,
		       COALESCE(p.is_online, false) as is_online,
		       COALESCE(p.last_seen, u.created_at) as last_seen
		FROM contacts c
		JOIN users u ON u.id = c.contact_user_id
		LEFT JOIN user_presence p ON p.user_id = c.contact_user_id
		WHERE c.user_id = $1
		ORDER BY u.username`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []ContactWithUser
	for rows.Next() {
		var c ContactWithUser
		err := rows.Scan(
			&c.ID, &c.UserID, &c.ContactUserID, &c.Nickname, &c.CreatedAt,
			&c.Username, &c.IsOnline, &c.LastSeen,
		)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, c)
	}

	return contacts, rows.Err()
}

func (r *ContactRepository) GetByID(ctx context.Context, userID, contactID uuid.UUID) (*ContactWithUser, error) {
	query := `
		SELECT c.id, c.user_id, c.contact_user_id, c.nickname, c.created_at,
		       u.username,
		       COALESCE(p.is_online, false) as is_online,
		       COALESCE(p.last_seen, u.created_at) as last_seen
		FROM contacts c
		JOIN users u ON u.id = c.contact_user_id
		LEFT JOIN user_presence p ON p.user_id = c.contact_user_id
		WHERE c.id = $1 AND c.user_id = $2`

	var c ContactWithUser
	err := r.pool.QueryRow(ctx, query, contactID, userID).Scan(
		&c.ID, &c.UserID, &c.ContactUserID, &c.Nickname, &c.CreatedAt,
		&c.Username, &c.IsOnline, &c.LastSeen,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrContactNotFound
		}
		return nil, err
	}

	return &c, nil
}
