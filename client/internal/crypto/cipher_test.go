package crypto

import (
	"bytes"
	"testing"
)

func TestNewSessionCipher(t *testing.T) {
	// Generate shared secret
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	// Create ciphers for both parties
	aliceCipher, err := NewSessionCipher(sharedSecret, true)
	if err != nil {
		t.Fatalf("NewSessionCipher for Alice failed: %v", err)
	}
	defer aliceCipher.Destroy()

	bobCipher, err := NewSessionCipher(sharedSecret, false)
	if err != nil {
		t.Fatalf("NewSessionCipher for Bob failed: %v", err)
	}
	defer bobCipher.Destroy()

	// Verify ciphers are created
	if aliceCipher.sendCipher == nil || aliceCipher.recvCipher == nil {
		t.Error("Alice cipher not properly initialized")
	}
	if bobCipher.sendCipher == nil || bobCipher.recvCipher == nil {
		t.Error("Bob cipher not properly initialized")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Setup
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	aliceCipher, _ := NewSessionCipher(sharedSecret, true)
	defer aliceCipher.Destroy()

	bobCipher, _ := NewSessionCipher(sharedSecret, false)
	defer bobCipher.Destroy()

	// Test message from Alice to Bob
	plaintext := []byte("Hello, Bob! This is a secret message.")

	ciphertext, nonce, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertext should be different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext equals plaintext")
	}

	// Nonce should be correct size
	if len(nonce) != NonceSize {
		t.Errorf("Nonce size = %d, want %d", len(nonce), NonceSize)
	}

	// Bob decrypts
	decrypted, err := bobCipher.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestBidirectionalEncryption(t *testing.T) {
	// Setup
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	aliceCipher, _ := NewSessionCipher(sharedSecret, true)
	defer aliceCipher.Destroy()

	bobCipher, _ := NewSessionCipher(sharedSecret, false)
	defer bobCipher.Destroy()

	// Alice sends to Bob
	aliceMsg := []byte("Hello Bob!")
	ct1, nonce1, _ := aliceCipher.Encrypt(aliceMsg)
	decrypted1, err := bobCipher.Decrypt(ct1, nonce1)
	if err != nil {
		t.Fatalf("Bob failed to decrypt Alice's message: %v", err)
	}
	if !bytes.Equal(decrypted1, aliceMsg) {
		t.Error("Bob got wrong message from Alice")
	}

	// Bob sends to Alice
	bobMsg := []byte("Hello Alice!")
	ct2, nonce2, _ := bobCipher.Encrypt(bobMsg)
	decrypted2, err := aliceCipher.Decrypt(ct2, nonce2)
	if err != nil {
		t.Fatalf("Alice failed to decrypt Bob's message: %v", err)
	}
	if !bytes.Equal(decrypted2, bobMsg) {
		t.Error("Alice got wrong message from Bob")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Setup two separate sessions
	alice1, _ := GenerateKeyPair()
	bob1, _ := GenerateKeyPair()
	sharedSecret1, _ := ComputeSharedSecret(alice1.PrivateKeyBytes(), bob1.PublicKeyBytes())

	alice2, _ := GenerateKeyPair()
	bob2, _ := GenerateKeyPair()
	sharedSecret2, _ := ComputeSharedSecret(alice2.PrivateKeyBytes(), bob2.PublicKeyBytes())

	cipher1, _ := NewSessionCipher(sharedSecret1, true)
	defer cipher1.Destroy()

	cipher2, _ := NewSessionCipher(sharedSecret2, false)
	defer cipher2.Destroy()

	// Encrypt with cipher1
	plaintext := []byte("Secret message")
	ciphertext, nonce, _ := cipher1.Encrypt(plaintext)

	// Try to decrypt with cipher2 (wrong key)
	_, err := cipher2.Decrypt(ciphertext, nonce)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptWithInvalidNonce(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	cipher, _ := NewSessionCipher(sharedSecret, true)
	defer cipher.Destroy()

	plaintext := []byte("Test message")
	ciphertext, _, _ := cipher.Encrypt(plaintext)

	// Try with wrong nonce size
	_, err := cipher.Decrypt(ciphertext, []byte("short"))
	if err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce, got %v", err)
	}
}

func TestDecryptWithTamperedCiphertext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	aliceCipher, _ := NewSessionCipher(sharedSecret, true)
	defer aliceCipher.Destroy()

	bobCipher, _ := NewSessionCipher(sharedSecret, false)
	defer bobCipher.Destroy()

	plaintext := []byte("Original message")
	ciphertext, nonce, _ := aliceCipher.Encrypt(plaintext)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	// Decryption should fail
	_, err := bobCipher.Decrypt(ciphertext, nonce)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed for tampered ciphertext, got %v", err)
	}
}

func TestDestroy(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	cipher, _ := NewSessionCipher(sharedSecret, true)

	// Store original key bytes
	sendKeyBefore := make([]byte, len(cipher.sendKey))
	copy(sendKeyBefore, cipher.sendKey)

	// Destroy
	cipher.Destroy()

	// Keys should be zeroed
	zeroKey := make([]byte, 32)
	if !bytes.Equal(cipher.sendKey, zeroKey) {
		t.Error("sendKey not zeroed after Destroy")
	}
	if !bytes.Equal(cipher.recvKey, zeroKey) {
		t.Error("recvKey not zeroed after Destroy")
	}
}

func TestUniqueNonces(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKeyBytes(), bob.PublicKeyBytes())

	cipher, _ := NewSessionCipher(sharedSecret, true)
	defer cipher.Destroy()

	plaintext := []byte("Test")
	nonces := make(map[string]bool)

	// Generate multiple nonces
	for i := 0; i < 100; i++ {
		_, nonce, _ := cipher.Encrypt(plaintext)
		nonceStr := string(nonce)
		if nonces[nonceStr] {
			t.Error("Duplicate nonce generated")
		}
		nonces[nonceStr] = true
	}
}
