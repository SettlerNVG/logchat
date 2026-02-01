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
	// Encryption keys (Curve25519 for ECDH)
	EncryptionPublicKey  []byte `json:"encryption_public_key"`
	EncryptionPrivateKey []byte `json:"encryption_private_key"`
	// Signature keys (Ed25519 for signatures)
	SignaturePublicKey  []byte `json:"signature_public_key"`
	SignaturePrivateKey []byte `json:"signature_private_key"`
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
func (s *Storage) LoadOrCreateKeys() (*crypto.KeyPair, *crypto.SigningKeyPair, error) {
	keys, err := s.LoadKeys()
	if err != nil {
		return nil, nil, err
	}

	if keys != nil && len(keys.EncryptionPublicKey) > 0 && len(keys.SignaturePublicKey) > 0 {
		// Load encryption key
		var encKp crypto.KeyPair
		copy(encKp.PublicKey[:], keys.EncryptionPublicKey)
		copy(encKp.PrivateKey[:], keys.EncryptionPrivateKey)

		// Load signature key
		sigKp := &crypto.SigningKeyPair{
			PublicKey:  keys.SignaturePublicKey,
			PrivateKey: keys.SignaturePrivateKey,
		}

		return &encKp, sigKp, nil
	}

	// Generate new keys
	encKp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sigKp, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Save keys
	newKeys := &KeyStore{
		EncryptionPublicKey:  encKp.PublicKeyBytes(),
		EncryptionPrivateKey: encKp.PrivateKeyBytes(),
		SignaturePublicKey:   sigKp.PublicKey,
		SignaturePrivateKey:  sigKp.PrivateKey,
	}

	if err := s.SaveKeys(newKeys); err != nil {
		return nil, nil, err
	}

	return encKp, sigKp, nil
}

// HasCredentials checks if credentials exist
func (s *Storage) HasCredentials() bool {
	creds, _ := s.LoadCredentials()
	return creds != nil && creds.AccessToken != ""
}
