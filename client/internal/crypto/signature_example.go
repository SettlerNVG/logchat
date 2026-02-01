package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Пример использования подписей в handshake

func ExampleSignatureFlow() {
	// === ALICE ===
	// 1. Генерирует identity ключи при регистрации
	aliceSignPub, aliceSignPriv, _ := ed25519.GenerateKey(rand.Reader)
	aliceEncKey, _ := GenerateKeyPair() // Curve25519 для шифрования
	
	fmt.Println("Alice регистрируется:")
	fmt.Printf("  Signature pubkey: %x...\n", aliceSignPub[:8])
	fmt.Printf("  Encryption pubkey: %x...\n", aliceEncKey.PublicKeyBytes()[:8])
	
	// === BOB ===
	bobSignPub, bobSignPriv, _ := ed25519.GenerateKey(rand.Reader)
	bobEncKey, _ := GenerateKeyPair()
	
	fmt.Println("\nBob регистрируется:")
	fmt.Printf("  Signature pubkey: %x...\n", bobSignPub[:8])
	fmt.Printf("  Encryption pubkey: %x...\n", bobEncKey.PublicKeyBytes()[:8])
	
	// === CHAT SESSION ===
	sessionToken := "session_abc123"
	
	// Alice генерирует ephemeral ключ
	aliceEphemeral, _ := GenerateEphemeralKeyPair()
	
	// Alice подписывает ephemeral ключ
	message := append(aliceEphemeral.PublicKeyBytes(), []byte(sessionToken)...)
	aliceSignature := ed25519.Sign(aliceSignPriv, message)
	
	fmt.Println("\n=== P2P Handshake ===")
	fmt.Println("Alice отправляет Bob:")
	fmt.Printf("  Ephemeral pubkey: %x...\n", aliceEphemeral.PublicKeyBytes()[:8])
	fmt.Printf("  Signature: %x...\n", aliceSignature[:8])
	fmt.Printf("  Session token: %s\n", sessionToken)
	
	// Bob проверяет подпись Alice
	message = append(aliceEphemeral.PublicKeyBytes(), []byte(sessionToken)...)
	valid := ed25519.Verify(aliceSignPub, message, aliceSignature)
	
	if valid {
		fmt.Println("\n✓ Bob: Подпись Alice валидна - это действительно Alice!")
	} else {
		fmt.Println("\n✗ Bob: АТАКА! Подпись невалидна!")
		return
	}
	
	// Bob отправляет свой ephemeral ключ с подписью
	bobEphemeral, _ := GenerateEphemeralKeyPair()
	message = append(bobEphemeral.PublicKeyBytes(), []byte(sessionToken)...)
	bobSignature := ed25519.Sign(bobSignPriv, message)
	
	// Alice проверяет подпись Bob
	valid = ed25519.Verify(bobSignPub, message, bobSignature)
	
	if valid {
		fmt.Println("✓ Alice: Подпись Bob валидна - это действительно Bob!")
	} else {
		fmt.Println("✗ Alice: АТАКА! Подпись невалидна!")
		return
	}
	
	// Теперь можно безопасно вычислить shared secret
	sharedSecret, _ := ComputeSharedSecret(
		aliceEphemeral.PrivateKeyBytes(),
		bobEphemeral.PublicKeyBytes(),
	)
	
	fmt.Println("\n✓ Handshake завершен успешно!")
	fmt.Printf("  Shared secret: %x...\n", sharedSecret[:8])
	fmt.Println("  Можно начинать зашифрованный чат")
	
	// === ПОПЫТКА АТАКИ ===
	fmt.Println("\n=== Попытка атаки ===")
	
	// Хакер пытается подменить ephemeral ключ
	hackerEphemeral, _ := GenerateEphemeralKeyPair()
	
	fmt.Println("Хакер отправляет Bob:")
	fmt.Printf("  Fake ephemeral: %x...\n", hackerEphemeral.PublicKeyBytes()[:8])
	fmt.Printf("  Stolen signature: %x...\n", aliceSignature[:8])
	
	// Bob проверяет
	message = append(hackerEphemeral.PublicKeyBytes(), []byte(sessionToken)...)
	valid = ed25519.Verify(aliceSignPub, message, aliceSignature)
	
	if !valid {
		fmt.Println("✓ Bob: АТАКА ОБНАРУЖЕНА! Подпись не совпадает с ключом")
		fmt.Println("  Соединение отклонено")
	}
}
