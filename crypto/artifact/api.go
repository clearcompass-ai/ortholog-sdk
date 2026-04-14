// Package artifact provides per-artifact AES-256-GCM encryption.
package artifact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	keySize   = 32 // AES-256
	nonceSize = 12 // GCM standard nonce
)

// ArtifactKey holds the AES-256 key and nonce for a single artifact.
type ArtifactKey struct {
	Key   [keySize]byte
	Nonce [nonceSize]byte
}

// EncryptArtifact encrypts plaintext with a freshly generated AES-256-GCM key and nonce.
// Key and nonce are generated internally from CSPRNG. Structurally prevents nonce reuse:
// each call generates a new key+nonce pair.
func EncryptArtifact(plaintext []byte) (ciphertext []byte, key ArtifactKey, err error) {
	// Generate fresh key.
	if _, err := io.ReadFull(rand.Reader, key.Key[:]); err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("generating key: %w", err)
	}
	// Generate fresh nonce.
	if _, err := io.ReadFull(rand.Reader, key.Nonce[:]); err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("generating nonce: %w", err)
	}

	block, err := aes.NewCipher(key.Key[:])
	if err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("creating GCM: %w", err)
	}

	ciphertext = gcm.Seal(nil, key.Nonce[:], plaintext, nil)
	return ciphertext, key, nil
}

// DecryptArtifact decrypts ciphertext with the provided key.
// Returns a structured "irrecoverable" error on failure (no panic).
// "Irrecoverable" is a normal condition when the key has been destroyed
// (cryptographic erasure per NIST SP 800-88).
func DecryptArtifact(ciphertext []byte, key ArtifactKey) ([]byte, error) {
	block, err := aes.NewCipher(key.Key[:])
	if err != nil {
		return nil, &IrrecoverableError{Cause: fmt.Errorf("creating cipher: %w", err)}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &IrrecoverableError{Cause: fmt.Errorf("creating GCM: %w", err)}
	}

	plaintext, err := gcm.Open(nil, key.Nonce[:], ciphertext, nil)
	if err != nil {
		return nil, &IrrecoverableError{Cause: fmt.Errorf("decryption failed: %w", err)}
	}
	return plaintext, nil
}

// ReEncryptArtifact decrypts with the old key and re-encrypts with a fresh key+nonce.
// Old key material should be zeroed by the caller after this returns.
func ReEncryptArtifact(ciphertext []byte, oldKey ArtifactKey) (newCiphertext []byte, newKey ArtifactKey, err error) {
	plaintext, err := DecryptArtifact(ciphertext, oldKey)
	if err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("re-encryption decrypt phase: %w", err)
	}

	newCiphertext, newKey, err = EncryptArtifact(plaintext)
	if err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("re-encryption encrypt phase: %w", err)
	}

	// Zero plaintext in memory.
	for i := range plaintext {
		plaintext[i] = 0
	}

	return newCiphertext, newKey, nil
}

// ZeroKey zeroes key material in memory.
func ZeroKey(key *ArtifactKey) {
	for i := range key.Key {
		key.Key[i] = 0
	}
	for i := range key.Nonce {
		key.Nonce[i] = 0
	}
}

// IrrecoverableError indicates the artifact cannot be decrypted.
// This is a normal condition when the key has been destroyed (cryptographic erasure).
type IrrecoverableError struct {
	Cause error
}

func (e *IrrecoverableError) Error() string {
	return fmt.Sprintf("irrecoverable: %v", e.Cause)
}

func (e *IrrecoverableError) Unwrap() error {
	return e.Cause
}

// IsIrrecoverable returns true if the error indicates the artifact
// cannot be decrypted (key destroyed or corrupted).
func IsIrrecoverable(err error) bool {
	var ie *IrrecoverableError
	return errors.As(err, &ie)
}
