package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/logmessager/server/internal/auth"
	"github.com/logmessager/server/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrUsernameTaken      = errors.New("username already taken")
	ErrWeakPassword       = errors.New("password must be at least 8 characters")
	ErrInvalidUsername    = errors.New("username must be 3-50 alphanumeric characters")
)

type AuthService struct {
	userRepo  *repository.UserRepository
	tokenRepo *repository.TokenRepository
	jwt       *auth.JWTManager
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	User         *repository.User
}

func NewAuthService(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository, jwt *auth.JWTManager) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwt:       jwt,
	}
}

func (s *AuthService) Register(ctx context.Context, username, password string, encryptionPubKey, signaturePubKey []byte) (*repository.User, error) {
	// Validate username
	if len(username) < 3 || len(username) > 50 || !isAlphanumeric(username) {
		return nil, ErrInvalidUsername
	}

	// Validate password
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}

	// Validate keys
	if len(encryptionPubKey) != 32 {
		return nil, errors.New("invalid encryption public key length (expected 32 bytes)")
	}
	if len(signaturePubKey) != 32 {
		return nil, errors.New("invalid signature public key length (expected 32 bytes)")
	}

	// Hash password
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user
	user, err := s.userRepo.Create(ctx, username, passwordHash, encryptionPubKey, signaturePubKey)
	if err != nil {
		if errors.Is(err, repository.ErrUserAlreadyExists) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	// Get user
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Check password
	if !auth.CheckPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	// Generate tokens
	accessToken, expiresAt, err := s.jwt.GenerateAccessToken(user.ID, user.Username)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshHash, refreshExpires, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token
	_, err = s.tokenRepo.Create(ctx, user.ID, refreshHash, refreshExpires)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User:         user,
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, time.Time, error) {
	// Hash the provided token
	tokenHash := s.jwt.HashRefreshToken(refreshToken)

	// Find token in DB
	storedToken, err := s.tokenRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return "", time.Time{}, ErrInvalidToken
		}
		return "", time.Time{}, err
	}

	// Check if revoked
	if storedToken.RevokedAt != nil {
		return "", time.Time{}, ErrInvalidToken
	}

	// Check if expired
	if time.Now().After(storedToken.ExpiresAt) {
		return "", time.Time{}, ErrInvalidToken
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, storedToken.UserID)
	if err != nil {
		return "", time.Time{}, err
	}

	// Generate new access token
	accessToken, expiresAt, err := s.jwt.GenerateAccessToken(user.ID, user.Username)
	if err != nil {
		return "", time.Time{}, err
	}

	return accessToken, expiresAt, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := s.jwt.HashRefreshToken(refreshToken)
	return s.tokenRepo.Revoke(ctx, tokenHash)
}

func (s *AuthService) ValidateToken(ctx context.Context, accessToken string) (*auth.Claims, error) {
	return s.jwt.ValidateAccessToken(accessToken)
}

func (s *AuthService) GetUserByID(ctx context.Context, userID uuid.UUID) (*repository.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}
