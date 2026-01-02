package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTManager_GenerateAccessToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	userID := uuid.New()
	username := "testuser"

	token, expiresAt, err := manager.GenerateAccessToken(userID, username)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token is empty")
	}

	if expiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}

	expectedExpiry := time.Now().Add(15 * time.Minute)
	if expiresAt.After(expectedExpiry.Add(time.Second)) {
		t.Error("ExpiresAt is too far in the future")
	}
}

func TestJWTManager_ValidateAccessToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	userID := uuid.New()
	username := "testuser"

	token, _, err := manager.GenerateAccessToken(userID, username)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.UserID != userID.String() {
		t.Errorf("UserID = %s, want %s", claims.UserID, userID.String())
	}

	if claims.Username != username {
		t.Errorf("Username = %s, want %s", claims.Username, username)
	}
}

func TestJWTManager_ValidateAccessToken_Invalid(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	_, err := manager.ValidateAccessToken("invalid-token")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

func TestJWTManager_ValidateAccessToken_WrongSecret(t *testing.T) {
	manager1 := NewJWTManager("secret-1", 15*time.Minute, 7*24*time.Hour)
	manager2 := NewJWTManager("secret-2", 15*time.Minute, 7*24*time.Hour)

	token, _, _ := manager1.GenerateAccessToken(uuid.New(), "user")

	_, err := manager2.ValidateAccessToken(token)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

func TestJWTManager_ValidateAccessToken_Expired(t *testing.T) {
	// Create manager with very short expiry
	manager := NewJWTManager("test-secret", 1*time.Millisecond, 7*24*time.Hour)

	token, _, _ := manager.GenerateAccessToken(uuid.New(), "user")

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err := manager.ValidateAccessToken(token)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got %v", err)
	}
}

func TestJWTManager_GenerateRefreshToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	token, hash, expiresAt, err := manager.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token is empty")
	}

	if hash == "" {
		t.Error("Hash is empty")
	}

	if token == hash {
		t.Error("Token equals hash (should be different)")
	}

	expectedExpiry := time.Now().Add(7 * 24 * time.Hour)
	if expiresAt.Before(expectedExpiry.Add(-time.Minute)) || expiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Error("ExpiresAt is not approximately 7 days from now")
	}
}

func TestJWTManager_HashRefreshToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	token := "test-refresh-token"
	hash1 := manager.HashRefreshToken(token)
	hash2 := manager.HashRefreshToken(token)

	// Same token should produce same hash
	if hash1 != hash2 {
		t.Error("Same token produced different hashes")
	}

	// Different tokens should produce different hashes
	hash3 := manager.HashRefreshToken("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens produced same hash")
	}
}

func TestJWTManager_RefreshTokenUniqueness(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 7*24*time.Hour)

	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, _, _, _ := manager.GenerateRefreshToken()
		if tokens[token] {
			t.Error("Duplicate refresh token generated")
		}
		tokens[token] = true
	}
}
