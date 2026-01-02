package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize = 12 // AES-GCM standard nonce size
	TagSize   = 16 // AES-GCM authentication tag size
)

var (
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidNonce     = errors.New("invalid nonce size")
)

// SessionCipher handles encryption/decryption for a chat session
type SessionCipher struct {
	sendKey    []byte
	recvKey    []byte
	sendCipher cipher.AEAD
	recvCipher cipher.AEAD
}

// NewSessionCipher creates a new cipher from shared secret
// isInitiator determines key derivation order (prevents key reuse)
func NewSessionCipher(sharedSecret []byte, isInitiator bool) (*SessionCipher, error) {
	// Derive two keys from shared secret using HKDF
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("logmessager-session-keys"))

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)

	if _, err := io.ReadFull(hkdfReader, key1); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdfReader, key2); err != nil {
		return nil, err
	}

	var sendKey, recvKey []byte
	if isInitiator {
		sendKey, recvKey = key1, key2
	} else {
		sendKey, recvKey = key2, key1
	}

	// Create AES-GCM ciphers
	sendCipher, err := createAESGCM(sendKey)
	if err != nil {
		return nil, err
	}

	recvCipher, err := createAESGCM(recvKey)
	if err != nil {
		return nil, err
	}

	return &SessionCipher{
		sendKey:    sendKey,
		recvKey:    recvKey,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
	}, nil
}

func createAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// Encrypt encrypts plaintext and returns (ciphertext, nonce)
func (sc *SessionCipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := sc.sendCipher.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using provided nonce
func (sc *SessionCipher) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	plaintext, err := sc.recvCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Destroy securely wipes keys from memory
func (sc *SessionCipher) Destroy() {
	for i := range sc.sendKey {
		sc.sendKey[i] = 0
	}
	for i := range sc.recvKey {
		sc.recvKey[i] = 0
	}
}
