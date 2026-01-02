package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type PublicKey struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	KeyType   string
	PublicKey []byte
	CreatedAt time.Time
}

type UserPresence struct {
	UserID           uuid.UUID
	IsOnline         bool
	LastSeen         time.Time
	NatType          string
	CanAcceptInbound bool
	PublicAddress    string
}

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, username, passwordHash string, publicKey []byte) (*User, error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var user User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (username, password_hash)
		VALUES ($1, $2)
		RETURNING id, username, password_hash, created_at, updated_at
	`, username, passwordHash).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrUserAlreadyExists
		}
		return nil, err
	}

	// Insert public key
	_, err = tx.Exec(ctx, `
		INSERT INTO public_keys (user_id, key_type, public_key)
		VALUES ($1, 'curve25519', $2)
	`, user.ID, publicKey)
	if err != nil {
		return nil, err
	}

	// Create presence record
	_, err = tx.Exec(ctx, `
		INSERT INTO user_presence (user_id, is_online)
		VALUES ($1, false)
	`, user.ID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var user User
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, username, password_hash, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, username, password_hash, created_at, updated_at
		FROM users WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetPublicKey(ctx context.Context, userID uuid.UUID) (*PublicKey, error) {
	var pk PublicKey
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, key_type, public_key, created_at
		FROM public_keys WHERE user_id = $1 AND key_type = 'curve25519'
	`, userID).Scan(&pk.ID, &pk.UserID, &pk.KeyType, &pk.PublicKey, &pk.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &pk, nil
}

func (r *UserRepository) UpdatePresence(ctx context.Context, userID uuid.UUID, presence *UserPresence) error {
	_, err := r.db.Pool.Exec(ctx, `
		UPDATE user_presence
		SET is_online = $2, nat_type = $3, can_accept_inbound = $4, public_address = $5, last_seen = NOW()
		WHERE user_id = $1
	`, userID, presence.IsOnline, presence.NatType, presence.CanAcceptInbound, presence.PublicAddress)
	return err
}

func (r *UserRepository) GetPresence(ctx context.Context, userID uuid.UUID) (*UserPresence, error) {
	var p UserPresence
	err := r.db.Pool.QueryRow(ctx, `
		SELECT user_id, is_online, last_seen, nat_type, can_accept_inbound, COALESCE(public_address, '')
		FROM user_presence WHERE user_id = $1
	`, userID).Scan(&p.UserID, &p.IsOnline, &p.LastSeen, &p.NatType, &p.CanAcceptInbound, &p.PublicAddress)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (r *UserRepository) ListOnline(ctx context.Context, limit, offset int) ([]User, int, error) {
	var total int
	err := r.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_presence WHERE is_online = true
	`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.password_hash, u.created_at, u.updated_at
		FROM users u
		JOIN user_presence p ON u.id = p.user_id
		WHERE p.is_online = true
		ORDER BY u.username
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}

	return users, total, nil
}

func (r *UserRepository) SearchByUsername(ctx context.Context, query string, limit int) ([]User, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, username, password_hash, created_at, updated_at
		FROM users
		WHERE username ILIKE $1 || '%'
		ORDER BY username
		LIMIT $2
	`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

func isDuplicateKeyError(err error) bool {
	return err != nil && (err.Error() == "ERROR: duplicate key value violates unique constraint \"users_username_key\" (SQLSTATE 23505)" ||
		contains(err.Error(), "duplicate key") || contains(err.Error(), "23505"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
