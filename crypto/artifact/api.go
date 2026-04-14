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
	KeySize   = 32
	NonceSize = 12
)

type ArtifactKey struct {
	Key   [KeySize]byte
	Nonce [NonceSize]byte
}

func EncryptArtifact(plaintext []byte) (ciphertext []byte, key ArtifactKey, err error) {
	if _, err := io.ReadFull(rand.Reader, key.Key[:]); err != nil { return nil, ArtifactKey{}, fmt.Errorf("generating key: %w", err) }
	if _, err := io.ReadFull(rand.Reader, key.Nonce[:]); err != nil { return nil, ArtifactKey{}, fmt.Errorf("generating nonce: %w", err) }
	block, err := aes.NewCipher(key.Key[:]); if err != nil { return nil, ArtifactKey{}, err }
	gcm, err := cipher.NewGCM(block); if err != nil { return nil, ArtifactKey{}, err }
	ciphertext = gcm.Seal(nil, key.Nonce[:], plaintext, nil)
	return ciphertext, key, nil
}

func DecryptArtifact(ciphertext []byte, key ArtifactKey) ([]byte, error) {
	block, err := aes.NewCipher(key.Key[:]); if err != nil { return nil, &IrrecoverableError{Cause: err} }
	gcm, err := cipher.NewGCM(block); if err != nil { return nil, &IrrecoverableError{Cause: err} }
	plaintext, err := gcm.Open(nil, key.Nonce[:], ciphertext, nil)
	if err != nil { return nil, &IrrecoverableError{Cause: fmt.Errorf("decryption failed: %w", err)} }
	return plaintext, nil
}

func ReEncryptArtifact(ciphertext []byte, oldKey ArtifactKey) ([]byte, ArtifactKey, error) {
	plaintext, err := DecryptArtifact(ciphertext, oldKey)
	if err != nil { return nil, ArtifactKey{}, err }
	newCT, newKey, err := EncryptArtifact(plaintext)
	if err != nil { return nil, ArtifactKey{}, err }
	for i := range plaintext { plaintext[i] = 0 }
	return newCT, newKey, nil
}

func ZeroKey(key *ArtifactKey) {
	for i := range key.Key { key.Key[i] = 0 }
	for i := range key.Nonce { key.Nonce[i] = 0 }
}

func VerifyAndDecrypt(ciphertext []byte, key ArtifactKey, artifactCID storage.CID, contentDigest storage.CID) ([]byte, error) {
	if artifactCID.IsZero() { return nil, &IrrecoverableError{Cause: fmt.Errorf("artifact CID is zero")} }
	if !artifactCID.Verify(ciphertext) {
		return nil, &IrrecoverableError{Cause: fmt.Errorf("storage integrity failure: ciphertext does not match artifact CID %s", artifactCID)}
	}
	plaintext, err := DecryptArtifact(ciphertext, key)
	if err != nil { return nil, err }
	if !contentDigest.IsZero() {
		if !contentDigest.Verify(plaintext) {
			for i := range plaintext { plaintext[i] = 0 }
			return nil, &IrrecoverableError{Cause: fmt.Errorf("content integrity failure: plaintext does not match content digest %s", contentDigest)}
		}
	}
	return plaintext, nil
}

type IrrecoverableError struct { Cause error }
func (e *IrrecoverableError) Error() string { return fmt.Sprintf("irrecoverable: %v", e.Cause) }
func (e *IrrecoverableError) Unwrap() error { return e.Cause }

func IsIrrecoverable(err error) bool {
	var ie *IrrecoverableError; return errors.As(err, &ie)
}
