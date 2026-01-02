package storage

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/logmessager/client/internal/crypto"
)

// Credentials stores user authentication data locally
type Credentials struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// KeyStore stores identity keys locally
type KeyStore struct {
	IdentityPublicKey  []byte `json:"identity_public_key"`
	IdentityPrivateKey []byte `json:"identity_private_key"`
}

// Storage handles local file storage for credentials and keys
type Storage struct {
	mu              sync.RWMutex
	credentialsPath string
	keysPath        string
}

// NewStorage creates a new storage instance
func NewStorage(credentialsPath, keysPath string) *Storage {
	return &Storage{
		credentialsPath: credentialsPath,
		keysPath:        keysPath,
	}
}

// SaveCredentials saves credentials to file
func (s *Storage) SaveCredentials(creds *Credentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.credentialsPath, data, 0600)
}

// LoadCredentials loads credentials from file
func (s *Storage) LoadCredentials() (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.credentialsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

// DeleteCredentials removes credentials file
func (s *Storage) DeleteCredentials() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.credentialsPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// SaveKeys saves identity keys to file
func (s *Storage) SaveKeys(keys *KeyStore) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.keysPath, data, 0600)
}

// LoadKeys loads identity keys from file
func (s *Storage) LoadKeys() (*KeyStore, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.keysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var keys KeyStore
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}

	return &keys, nil
}

// LoadOrCreateKeys loads existing keys or creates new ones
func (s *Storage) LoadOrCreateKeys() (*crypto.KeyPair, error) {
	keys, err := s.LoadKeys()
	if err != nil {
		return nil, err
	}

	if keys != nil && len(keys.IdentityPublicKey) > 0 {
		var kp crypto.KeyPair
		copy(kp.PublicKey[:], keys.IdentityPublicKey)
		copy(kp.PrivateKey[:], keys.IdentityPrivateKey)
		return &kp, nil
	}

	// Generate new keys
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Save keys
	newKeys := &KeyStore{
		IdentityPublicKey:  kp.PublicKeyBytes(),
		IdentityPrivateKey: kp.PrivateKeyBytes(),
	}

	if err := s.SaveKeys(newKeys); err != nil {
		return nil, err
	}

	return kp, nil
}

// HasCredentials checks if credentials exist
func (s *Storage) HasCredentials() bool {
	creds, _ := s.LoadCredentials()
	return creds != nil && creds.AccessToken != ""
}
