package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Check key sizes
	if len(kp.PublicKey) != KeySize {
		t.Errorf("Public key size = %d, want %d", len(kp.PublicKey), KeySize)
	}
	if len(kp.PrivateKey) != KeySize {
		t.Errorf("Private key size = %d, want %d", len(kp.PrivateKey), KeySize)
	}

	// Keys should not be all zeros
	zeroKey := make([]byte, KeySize)
	if bytes.Equal(kp.PublicKey[:], zeroKey) {
		t.Error("Public key is all zeros")
	}
	if bytes.Equal(kp.PrivateKey[:], zeroKey) {
		t.Error("Private key is all zeros")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	if bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Two generated key pairs have same public key")
	}
	if bytes.Equal(kp1.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Two generated key pairs have same private key")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two key pairs
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Compute shared secrets
	aliceShared, err := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecret failed: %v", err)
	}

	bobShared, err := ComputeSharedSecret(bob.PrivateKeyBytes(), alice.PublicKeyBytes())
	if err != nil {
		t.Fatalf("Bob ComputeSharedSecret failed: %v", err)
	}

	// Shared secrets should be equal
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared secrets do not match")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != KeySize {
		t.Errorf("Shared secret size = %d, want %d", len(aliceShared), KeySize)
	}
}

func TestComputeSharedSecretInvalidKeySize(t *testing.T) {
	alice, _ := GenerateKeyPair()

	// Test with invalid private key size
	_, err := ComputeSharedSecret([]byte("short"), alice.PublicKeyBytes())
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}

	// Test with invalid public key size
	_, err = ComputeSharedSecret(alice.PrivateKeyBytes(), []byte("short"))
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}
}

func TestKeyPairBytes(t *testing.T) {
	kp, _ := GenerateKeyPair()

	pubBytes := kp.PublicKeyBytes()
	privBytes := kp.PrivateKeyBytes()

	if len(pubBytes) != KeySize {
		t.Errorf("PublicKeyBytes length = %d, want %d", len(pubBytes), KeySize)
	}
	if len(privBytes) != KeySize {
		t.Errorf("PrivateKeyBytes length = %d, want %d", len(privBytes), KeySize)
	}

	// Verify bytes match original keys
	if !bytes.Equal(pubBytes, kp.PublicKey[:]) {
		t.Error("PublicKeyBytes does not match PublicKey")
	}
	if !bytes.Equal(privBytes, kp.PrivateKey[:]) {
		t.Error("PrivateKeyBytes does not match PrivateKey")
	}
}
