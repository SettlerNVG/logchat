package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Error("Hash is empty")
	}

	if hash == password {
		t.Error("Hash equals password (not hashed)")
	}

	// Hash should start with bcrypt prefix
	if len(hash) < 4 || hash[:4] != "$2a$" {
		t.Error("Hash does not appear to be bcrypt format")
	}
}

func TestHashPassword_Uniqueness(t *testing.T) {
	password := "testpassword123"

	hash1, _ := HashPassword(password)
	hash2, _ := HashPassword(password)

	// Same password should produce different hashes (due to salt)
	if hash1 == hash2 {
		t.Error("Same password produced identical hashes")
	}
}

func TestCheckPassword_Valid(t *testing.T) {
	password := "testpassword123"
	hash, _ := HashPassword(password)

	if !CheckPassword(password, hash) {
		t.Error("CheckPassword returned false for valid password")
	}
}

func TestCheckPassword_Invalid(t *testing.T) {
	password := "testpassword123"
	hash, _ := HashPassword(password)

	if CheckPassword("wrongpassword", hash) {
		t.Error("CheckPassword returned true for invalid password")
	}
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	hash, _ := HashPassword("somepassword")

	if CheckPassword("", hash) {
		t.Error("CheckPassword returned true for empty password")
	}
}

func TestCheckPassword_InvalidHash(t *testing.T) {
	if CheckPassword("password", "invalid-hash") {
		t.Error("CheckPassword returned true for invalid hash")
	}
}

func TestHashPassword_LongPassword(t *testing.T) {
	// bcrypt has a 72 byte limit, but should not error
	longPassword := "a]very_long_password_that_exceeds_normal_length_limits_1234567890"

	hash, err := HashPassword(longPassword)
	if err != nil {
		t.Fatalf("HashPassword failed for long password: %v", err)
	}

	if !CheckPassword(longPassword, hash) {
		t.Error("CheckPassword failed for long password")
	}
}

func TestHashPassword_SpecialCharacters(t *testing.T) {
	passwords := []string{
		"пароль123",
		"密码测试",
		"p@$$w0rd!#$%",
		"pass word with spaces",
		"emoji🔐password",
	}

	for _, password := range passwords {
		hash, err := HashPassword(password)
		if err != nil {
			t.Errorf("HashPassword failed for %q: %v", password, err)
			continue
		}

		if !CheckPassword(password, hash) {
			t.Errorf("CheckPassword failed for %q", password)
		}
	}
}
