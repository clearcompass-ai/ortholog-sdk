// Package artifact provides per-artifact AES-256-GCM encryption.
package artifact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
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

// -------------------------------------------------------------------------------------------------
// VerifyAndDecrypt — the ONLY correct consumption path
// -------------------------------------------------------------------------------------------------

// VerifyAndDecrypt is the canonical path for consuming an encrypted artifact
// fetched from any CAS backend. It composes three verification steps into one
// mandatory chain. No partial results. No skipping steps.
//
// Step 1: artifactCID.Verify(ciphertext) — storage integrity.
//
//	Confirms the ciphertext has not been corrupted or substituted in storage.
//	This re-hashes the ciphertext and compares against the CID's digest.
//
// Step 2: AES-256-GCM decrypt — produces plaintext.
//
//	GCM's authentication tag catches any ciphertext tampering that somehow
//	passed the CID check (defense in depth). IrrecoverableError if key wrong.
//
// Step 3: contentDigest.Verify(plaintext) — content integrity.
//
//	Confirms the decrypted content matches the expected digest. Catches
//	encrypt-then-replace attacks where a valid key encrypts wrong content.
//	Pass a zero CID to skip (only when no content digest is available,
//	e.g., legacy artifacts created before digest tracking).
//
// Fails on any mismatch. This is NOT optional. Every artifact consumption
// outside of migration tooling must go through this function.
func VerifyAndDecrypt(
	ciphertext []byte,
	key ArtifactKey,
	artifactCID storage.CID,
	contentDigest storage.CID,
) ([]byte, error) {
	// Step 1: storage integrity — CID matches ciphertext.
	if artifactCID.IsZero() {
		return nil, &IrrecoverableError{Cause: fmt.Errorf("artifact CID is zero (missing)")}
	}
	if !artifactCID.Verify(ciphertext) {
		return nil, &IrrecoverableError{
			Cause: fmt.Errorf("storage integrity failure: ciphertext does not match artifact CID %s", artifactCID),
		}
	}

	// Step 2: AES-256-GCM decrypt.
	plaintext, err := DecryptArtifact(ciphertext, key)
	if err != nil {
		return nil, err // Already an IrrecoverableError.
	}

	// Step 3: content integrity — plaintext matches expected digest.
	// Skip if contentDigest is zero (legacy artifacts without digest tracking).
	if !contentDigest.IsZero() {
		if !contentDigest.Verify(plaintext) {
			// Zero plaintext before returning — it failed integrity.
			for i := range plaintext {
				plaintext[i] = 0
			}
			return nil, &IrrecoverableError{
				Cause: fmt.Errorf("content integrity failure: plaintext does not match content digest %s", contentDigest),
			}
		}
	}

	return plaintext, nil
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
