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
	var publicKey [KeySize]byte

	// Generate random private key
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, err
	}

	// Clamp private key (as per Curve25519 spec)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PublicKey:  publicKey,
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

	var priv, pub, shared [KeySize]byte
	copy(priv[:], privateKey)
	copy(pub[:], peerPublicKey)

	curve25519.ScalarMult(&shared, &priv, &pub)

	return shared[:], nil
}

// PublicKeyBytes returns public key as byte slice
func (kp *KeyPair) PublicKeyBytes() []byte {
	return kp.PublicKey[:]
}

// PrivateKeyBytes returns private key as byte slice
func (kp *KeyPair) PrivateKeyBytes() []byte {
	return kp.PrivateKey[:]
}
