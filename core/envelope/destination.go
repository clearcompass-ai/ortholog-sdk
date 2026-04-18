/*
FILE PATH:
    core/envelope/destination.go

DESCRIPTION:
    Destination-binding primitives. An Ortholog entry MUST be bound to the
    exchange DID that is its intended destination. This binding lives in the
    entry's Destination field and is included in the canonical hash via
    Serialize. The helpers here exist for:

      - Validating a destination DID string (non-empty, non-whitespace)
      - Computing a stable, length-safe commitment for the destination,
        used anywhere a destination-check needs a fixed-size digest rather
        than the DID string itself (e.g. SMT leaf keys scoped to a
        destination, cross-log anchoring, future protocol extensions).

KEY ARCHITECTURAL DECISIONS:
  - Destination is a DID string, stored verbatim on Entry. The canonical
    hash commits to the destination via Serialize — no separate magic.
  - DestinationCommitment is SHA-256 over a domain-tagged, length-prefixed
    encoding of the DID. Matches the existing canonical-hash scheme
    (SHA-256, length-prefixed fields). Deterministic across all platforms.
  - The domain tag "ortholog.v1.destination-binding" is FROZEN. Any change
    invalidates every destination-bound entry ever signed. Version bumps
    use a new tag (e.g. "ortholog.v2.destination-binding") in a future
    migration, never modify the v1 tag.
  - Empty destinations are rejected at every boundary. Fail-loud.

KEY DEPENDENCIES:
    - crypto/sha256 (standard library)
    - encoding/binary (length prefix)
*/
package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// -------------------------------------------------------------------------------------------------
// 1) Frozen constants
// -------------------------------------------------------------------------------------------------

// DestinationDomainTag is the fixed domain separator for destination
// commitments. Changing this value invalidates every destination-bound
// entry signed under the current scheme. For protocol migrations, define
// a new constant (e.g. DestinationDomainTagV2) and run a coordinated
// migration; do NOT modify this one.
const DestinationDomainTag = "ortholog.v1.destination-binding"

// MaxDestinationDIDLen caps the length of a destination DID string. The
// cap exists to keep the length prefix a uint16 and to reject pathological
// inputs at parse time. Real-world DIDs are well under 256 bytes.
const MaxDestinationDIDLen = 1024

// -------------------------------------------------------------------------------------------------
// 2) Errors
// -------------------------------------------------------------------------------------------------

var (
	ErrDestinationEmpty = errors.New("envelope: destination DID must not be empty")
	ErrDestinationTooLong = errors.New("envelope: destination DID exceeds maximum length")
	ErrDestinationWhitespace = errors.New("envelope: destination DID contains leading/trailing whitespace")
)

// -------------------------------------------------------------------------------------------------
// 3) Validation
// -------------------------------------------------------------------------------------------------

// ValidateDestination returns nil if the DID string is a well-formed
// destination value. Does NOT validate that the DID is resolvable — that's
// a separate concern. Validates only the syntactic properties the canonical
// hash depends on.
func ValidateDestination(destinationDID string) error {
	if destinationDID == "" {
		return ErrDestinationEmpty
	}
	if len(destinationDID) > MaxDestinationDIDLen {
		return fmt.Errorf("%w: got %d bytes, max %d",
			ErrDestinationTooLong, len(destinationDID), MaxDestinationDIDLen)
	}
	if strings.TrimSpace(destinationDID) != destinationDID {
		return ErrDestinationWhitespace
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 4) Commitment
// -------------------------------------------------------------------------------------------------

// DestinationCommitment returns a stable 32-byte commitment to a
// destination DID. Used anywhere a fixed-size destination digest is more
// convenient than the DID string (e.g. SMT key scoping, anchor payloads).
//
// Computation:
//     commitment = SHA-256(
//         DestinationDomainTag ||
//         uint16be(len(didBytes)) ||
//         didBytes
//     )
//
// The domain tag prevents collision with any other Ortholog commitment.
// The length prefix ensures distinct inputs produce distinct outputs
// regardless of DID string length.
func DestinationCommitment(destinationDID string) ([32]byte, error) {
	if err := ValidateDestination(destinationDID); err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte(DestinationDomainTag))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(destinationDID)))
	h.Write(lenBuf[:])
	h.Write([]byte(destinationDID))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// MustDestinationCommitment is the panicking variant for contexts where
// the destination has already been validated upstream (e.g. inside a
// builder after Config validation).
func MustDestinationCommitment(destinationDID string) [32]byte {
	c, err := DestinationCommitment(destinationDID)
	if err != nil {
		panic(fmt.Sprintf("envelope: MustDestinationCommitment: %v", err))
	}
	return c
}
