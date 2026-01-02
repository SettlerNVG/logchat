package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

var (
	ErrInvalidKeySize = errors.New("invalid key size")
)

// KeyPair holds a Curve25519 key pair
type KeyPair struct {
	PublicKey  [KeySize]byte
	PrivateKey [KeySize]byte
}

// GenerateKeyPair creates a new Curve25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte

	// Generate random private key
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, err
	}

	// Derive public key using X25519 with basepoint
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var pubKey [KeySize]byte
	copy(pubKey[:], publicKey)

	return &KeyPair{
		PublicKey:  pubKey,
		PrivateKey: privateKey,
	}, nil
}

// GenerateEphemeralKeyPair creates a new ephemeral key pair for session
func GenerateEphemeralKeyPair() (*KeyPair, error) {
	return GenerateKeyPair()
}

// ComputeSharedSecret computes ECDH shared secret
func ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != KeySize || len(peerPublicKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, err
	}

	return shared, nil
}

// PublicKeyBytes returns public key as byte slice
func (kp *KeyPair) PublicKeyBytes() []byte {
	return kp.PublicKey[:]
}

// PrivateKeyBytes returns private key as byte slice
func (kp *KeyPair) PrivateKeyBytes() []byte {
	return kp.PrivateKey[:]
}
