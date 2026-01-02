package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

// SigningKeyPair holds Ed25519 keys for signing
type SigningKeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateSigningKeyPair creates a new Ed25519 key pair
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &SigningKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// Sign signs a message with the private key
func (skp *SigningKeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(skp.PrivateKey, message)
}

// Verify verifies a signature against a public key
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// SignHandshake creates a signature for handshake data
func (skp *SigningKeyPair) SignHandshake(sessionToken string, ephemeralPublicKey []byte) []byte {
	data := append([]byte(sessionToken), ephemeralPublicKey...)
	return skp.Sign(data)
}

// VerifyHandshake verifies a handshake signature
func VerifyHandshake(publicKey []byte, sessionToken string, ephemeralPublicKey, signature []byte) bool {
	data := append([]byte(sessionToken), ephemeralPublicKey...)
	return Verify(publicKey, data, signature)
}
