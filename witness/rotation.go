/*
witness/rotation.go — Witness set rotation verification and chain walking.

VerifyRotation: validates a single rotation message against the current
witness set. Supports dual-sign scheme transitions (Decision 41).

VerifyRotationChain: walks from genesis through N rotations, verifying
each step. Returns the final current witness set. Used by
bootstrap.go HardcodedGenesis method.

The rotation message is signed by the CURRENT set (K-of-N). The new set
is accepted only if the signatures are valid. This is the trust chain:
genesis → rotation₁ → rotation₂ → ... → current set.
*/
package witness

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrEmptyNewSet is returned when a rotation proposes an empty new key set.
var ErrEmptyNewSet = errors.New("witness/rotation: empty new key set")

// ErrEmptyRotationSigs is returned when no signatures are present.
var ErrEmptyRotationSigs = errors.New("witness/rotation: no rotation signatures")

// ErrDualSignMissingNewSigs is returned when a dual-sign rotation lacks
// new-scheme signatures.
var ErrDualSignMissingNewSigs = errors.New("witness/rotation: dual-sign requires new-scheme signatures")

// ErrRotationChainBroken is returned when a chain walk encounters an
// invalid rotation step.
var ErrRotationChainBroken = errors.New("witness/rotation: chain broken at step")

// ─────────────────────────────────────────────────────────────────────
// VerifyRotation — single rotation message verification
// ─────────────────────────────────────────────────────────────────────

// VerifyRotation validates a rotation message against the current witness
// set and returns the new set if valid.
//
// Verification:
//  1. Structural: non-empty new set, non-empty current sigs
//  2. Current set hash matches rotation.CurrentSetHash
//  3. Current signatures: K-of-N from currentSet verify the rotation message
//  4. Dual-sign (Decision 41): if scheme transition, verify new-scheme sigs too
//
// Returns the new witness set on success.
func VerifyRotation(
	rotation types.WitnessRotation,
	currentSet []types.WitnessPublicKey,
	quorumK int,
	blsVerifier signatures.BLSVerifier,
) ([]types.WitnessPublicKey, error) {
	// Structural validation.
	if len(rotation.NewSet) == 0 {
		return nil, ErrEmptyNewSet
	}
	if len(rotation.CurrentSignatures) == 0 {
		return nil, ErrEmptyRotationSigs
	}
	if len(currentSet) == 0 {
		return nil, ErrEmptyWitnessSet
	}
	if quorumK <= 0 {
		return nil, fmt.Errorf("witness/rotation: K must be positive, got %d", quorumK)
	}

	// Verify current set hash matches.
	computedHash := ComputeSetHash(currentSet)
	if computedHash != rotation.CurrentSetHash {
		return nil, fmt.Errorf("witness/rotation: set hash mismatch: computed %x, rotation claims %x",
			computedHash[:8], rotation.CurrentSetHash[:8])
	}

	// Build a cosigned tree head structure for the rotation message.
	// The "message" is the rotation's new set hash — signed by the current set.
	newSetHash := ComputeSetHash(rotation.NewSet)
	rotationHead := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: newSetHash,
			TreeSize: 0, // Rotation messages use TreeSize=0 convention.
		},
		SchemeTag:  rotation.SchemeTagOld,
		Signatures: rotation.CurrentSignatures,
	}

	// Verify current set signatures.
	_, err := signatures.VerifyWitnessCosignatures(rotationHead, currentSet, quorumK, blsVerifier)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: current set verification: %w", err)
	}

	// Dual-sign verification (Decision 41).
	// Check SchemeTagNew directly — IsDualSigned() checks signature presence,
	// but we need to catch the case where a scheme transition is declared
	// (SchemeTagNew != 0) but new-scheme signatures are missing.
	if rotation.SchemeTagNew != 0 && rotation.SchemeTagNew != rotation.SchemeTagOld {
		if len(rotation.NewSignatures) == 0 {
			return nil, ErrDualSignMissingNewSigs
		}
		// Verify new-scheme signatures against the NEW set.
		// The new set signs the same message with the new scheme.
		dualHead := types.CosignedTreeHead{
			TreeHead: types.TreeHead{
				RootHash: newSetHash,
				TreeSize: 0,
			},
			SchemeTag:  rotation.SchemeTagNew,
			Signatures: rotation.NewSignatures,
		}
		_, err := signatures.VerifyWitnessCosignatures(dualHead, rotation.NewSet, quorumK, blsVerifier)
		if err != nil {
			return nil, fmt.Errorf("witness/rotation: dual-sign new-scheme verification: %w", err)
		}
	}

	return rotation.NewSet, nil
}

// ─────────────────────────────────────────────────────────────────────
// VerifyRotationChain — genesis → N rotations → current set
// ─────────────────────────────────────────────────────────────────────

// VerifyRotationChain walks from a genesis witness set through a sequence
// of rotations, verifying each step. Returns the final current set.
//
// Used by bootstrap.go HardcodedGenesis method: compiled-in genesis set →
// fetch rotation history → verify chain → current set.
//
// Each rotation is verified against the set produced by the prior step.
// If any step fails, returns ErrRotationChainBroken with the step index.
func VerifyRotationChain(
	genesisSet []types.WitnessPublicKey,
	rotations []types.WitnessRotation,
	quorumK int,
	blsVerifier signatures.BLSVerifier,
) ([]types.WitnessPublicKey, error) {
	if len(genesisSet) == 0 {
		return nil, ErrEmptyWitnessSet
	}

	currentSet := genesisSet
	for i, rotation := range rotations {
		newSet, err := VerifyRotation(rotation, currentSet, quorumK, blsVerifier)
		if err != nil {
			return nil, fmt.Errorf("%w %d: %v", ErrRotationChainBroken, i, err)
		}
		currentSet = newSet
	}

	return currentSet, nil
}

// ─────────────────────────────────────────────────────────────────────
// ComputeSetHash — deterministic hash of a witness key set
// ─────────────────────────────────────────────────────────────────────

// ComputeSetHash computes a deterministic SHA-256 hash of a witness key set.
// Keys are hashed in order (caller must ensure canonical ordering if needed).
// Used for rotation message binding: "this rotation targets THIS specific set."
func ComputeSetHash(keys []types.WitnessPublicKey) [32]byte {
	h := sha256.New()
	for _, k := range keys {
		h.Write(k.ID[:])
		h.Write(k.PublicKey)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
