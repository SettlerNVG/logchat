package service

import (
	"testing"
)

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"username", true},
		{"user123", true},
		{"User_Name", true},
		{"user_name_123", true},
		{"USERNAME", true},
		{"user-name", false},
		{"user.name", false},
		{"user@name", false},
		{"user name", false},
		{"пользователь", false},
		{"", true}, // empty is technically valid
	}

	for _, tt := range tests {
		result := isAlphanumeric(tt.input)
		if result != tt.expected {
			t.Errorf("isAlphanumeric(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}
