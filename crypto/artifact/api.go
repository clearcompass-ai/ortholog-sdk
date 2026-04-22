package artifact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"

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
	if _, err := io.ReadFull(rand.Reader, key.Key[:]); err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("generating key: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, key.Nonce[:]); err != nil {
		return nil, ArtifactKey{}, fmt.Errorf("generating nonce: %w", err)
	}
	block, err := aes.NewCipher(key.Key[:])
	if err != nil {
		return nil, ArtifactKey{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ArtifactKey{}, err
	}
	ciphertext = gcm.Seal(nil, key.Nonce[:], plaintext, nil)
	return ciphertext, key, nil
}

func DecryptArtifact(ciphertext []byte, key ArtifactKey) ([]byte, error) {
	block, err := aes.NewCipher(key.Key[:])
	if err != nil {
		return nil, NewIrrecoverableError(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewIrrecoverableError(err)
	}
	plaintext, err := gcm.Open(nil, key.Nonce[:], ciphertext, nil)
	if err != nil {
		return nil, NewIrrecoverableError(fmt.Errorf("decryption failed: %w", err))
	}
	return plaintext, nil
}

func ReEncryptArtifact(ciphertext []byte, oldKey ArtifactKey) ([]byte, ArtifactKey, error) {
	plaintext, err := DecryptArtifact(ciphertext, oldKey)
	if err != nil {
		return nil, ArtifactKey{}, err
	}

	// Cryptographic erasure of the cleartext intermediate.
	//
	// plaintext is the buffer DecryptArtifact returned — gcm.Open
	// allocates and returns its own slice, so zeroing it here zeroes
	// the actual backing array (no aliases outlive this frame).
	//
	// The defer is registered IMMEDIATELY after DecryptArtifact to
	// ensure every subsequent exit path (success, EncryptArtifact
	// failure, any future code added to this function) is covered
	// by the erasure. Moving this defer lower in the function breaks
	// the guarantee for code paths above it.
	//
	// runtime.KeepAlive prevents a future Go compiler from eliding
	// the zero-write loop after proving the slice is never read again.
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
		runtime.KeepAlive(plaintext)
	}()

	newCT, newKey, err := EncryptArtifact(plaintext)
	if err != nil {
		return nil, ArtifactKey{}, err
	}

	return newCT, newKey, nil
}

// ZeroKey clears both Key and Nonce in place. A nil receiver is a
// no-op so defer chains that cannot statically prove non-nil
// targets remain safe (mirrors crypto/escrow.ZeroArray32).
//
// runtime.KeepAlive prevents a future Go compiler from eliding
// the write loop after proving the slice is never read again.
//
//go:noinline
func ZeroKey(key *ArtifactKey) {
	if key == nil {
		return
	}
	for i := range key.Key {
		key.Key[i] = 0
	}
	for i := range key.Nonce {
		key.Nonce[i] = 0
	}
	runtime.KeepAlive(key)
}

func VerifyAndDecrypt(ciphertext []byte, key ArtifactKey, artifactCID storage.CID, contentDigest storage.CID) ([]byte, error) {
	if artifactCID.IsZero() {
		return nil, NewIrrecoverableError(errors.New("artifact CID is zero"))
	}
	if !artifactCID.Verify(ciphertext) {
		return nil, NewIrrecoverableError(fmt.Errorf("storage integrity failure: ciphertext does not match artifact CID %s", artifactCID))
	}
	plaintext, err := DecryptArtifact(ciphertext, key)
	if err != nil {
		return nil, err
	}
	if !contentDigest.IsZero() {
		if !contentDigest.Verify(plaintext) {
			for i := range plaintext {
				plaintext[i] = 0
			}
			return nil, NewIrrecoverableError(fmt.Errorf("content integrity failure: plaintext does not match content digest %s", contentDigest))
		}
	}
	return plaintext, nil
}

// IrrecoverableError marks a failure that retry cannot fix —
// AES key corruption, GCM tag failure, hash mismatch, etc.
// Used by callers that distinguish "transient (retry)" from
// "permanent (escalate)" via IsIrrecoverable / errors.As.
//
// Cause MUST be non-nil. Construct via NewIrrecoverableError to
// enforce this. Direct literal construction with a nil Cause is
// a programming error; Error() and Unwrap() are defended against
// the nil-Cause case so a misuse does not panic, and both surface
// ErrIrrecoverableNilCause symmetrically so errors.Is detects the
// misuse regardless of which construction path produced it.
type IrrecoverableError struct{ Cause error }

// ErrIrrecoverableNilCause is the sentinel substituted for a nil
// Cause. Surfaced by Error() and Unwrap() on any
// *IrrecoverableError whose Cause field is nil — whether built
// via NewIrrecoverableError(nil) or via the direct literal
// &IrrecoverableError{Cause: nil}. Callers that want to detect
// programming-error misuse explicitly can match on this sentinel.
var ErrIrrecoverableNilCause = errors.New("irrecoverable: nil cause (programming error)")

// NewIrrecoverableError wraps cause as an irrecoverable failure.
// A nil cause is replaced with ErrIrrecoverableNilCause rather
// than panicking — production callers should never pass nil, but
// the substitution prevents misuse from manifesting as a crash
// in the error path.
func NewIrrecoverableError(cause error) *IrrecoverableError {
	if cause == nil {
		cause = ErrIrrecoverableNilCause
	}
	return &IrrecoverableError{Cause: cause}
}

func (e *IrrecoverableError) Error() string {
	if e == nil || e.Cause == nil {
		return "irrecoverable: " + ErrIrrecoverableNilCause.Error()
	}
	return fmt.Sprintf("irrecoverable: %v", e.Cause)
}

// Unwrap surfaces the underlying cause for errors.Is / errors.As.
// On a nil Cause (only reachable via direct-literal misuse),
// Unwrap returns ErrIrrecoverableNilCause so detection is
// symmetric with Error(). Returning nil here would let
// errors.Is(err, ErrIrrecoverableNilCause) silently fail for the
// direct-literal misuse path.
func (e *IrrecoverableError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Cause == nil {
		return ErrIrrecoverableNilCause
	}
	return e.Cause
}

func IsIrrecoverable(err error) bool {
	var ie *IrrecoverableError
	return errors.As(err, &ie)
}
