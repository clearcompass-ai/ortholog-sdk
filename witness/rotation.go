/*
FILE PATH:

	witness/rotation.go

DESCRIPTION:

	Witness set rotation verification and chain walking.

	VerifyRotation: validates a single rotation message against the
	current witness set. Supports dual-sign scheme transitions
	(Decision 41) — a rotation that changes the signing scheme
	carries signatures from both the old scheme (current set) and
	the new scheme (new set), each verified against the appropriate
	authority.

	VerifyRotationChain: walks from genesis through N rotations,
	verifying each step. Returns the final current witness set.
	Used by bootstrap.go HardcodedGenesis method.

	The rotation message is signed by the CURRENT set (K-of-N). The
	new set is accepted only if the signatures are valid. This is
	the trust chain: genesis → rotation₁ → rotation₂ → ... → current.

WAVE 2 CHANGE: Per-signature scheme enforcement

	Pre-Wave-2 this file constructed CosignedTreeHead literals with
	a head-level SchemeTag. After Wave 2, SchemeTag lives on each
	individual WitnessSignature.

	This file now enforces a strict invariant at the boundary:
	EVERY signature in rotation.CurrentSignatures must declare
	SchemeTag == rotation.SchemeTagOld, and EVERY signature in
	rotation.NewSignatures must declare SchemeTag ==
	rotation.SchemeTagNew. Any mismatch is a rejection with a
	typed error identifying the specific signature index and the
	scheme conflict.

	No defensive populate. No fallback. No "unknown scheme" lenience.
	If the rotation declares an old scheme of SchemeECDSA=0x01 and
	any CurrentSignature carries SchemeTag=0x00 or SchemeTag=0x02,
	the rotation is rejected.

	Rationale: operators submitting malformed rotation messages
	(e.g., forgetting to populate SchemeTag on every signature
	after Wave 2 migration) must get a loud, specific error rather
	than silent misdispatch. Mix-ups between the two signature
	sets in a dual-sign rotation could otherwise lead to the
	verifier accepting signatures against the wrong authority,
	which is a genuine correctness issue.
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

// ErrDualSignMissingNewSigs is returned when a dual-sign rotation
// lacks new-scheme signatures.
var ErrDualSignMissingNewSigs = errors.New("witness/rotation: dual-sign requires new-scheme signatures")

// ErrRotationChainBroken is returned when a chain walk encounters
// an invalid rotation step.
var ErrRotationChainBroken = errors.New("witness/rotation: chain broken at step")

// ErrRotationSchemeMismatch is returned when a signature in a
// rotation message declares a SchemeTag that does not match the
// rotation's declared scheme (SchemeTagOld for CurrentSignatures,
// SchemeTagNew for NewSignatures).
//
// This is a strict invariant added in Wave 2 — pre-Wave-2 the
// scheme was carried at the head level and could not drift, so
// this error could not occur. Post-Wave-2 every signature must
// declare its scheme explicitly and consistently.
var ErrRotationSchemeMismatch = errors.New("witness/rotation: signature SchemeTag mismatch")

// ─────────────────────────────────────────────────────────────────────
// VerifyRotation — single rotation message verification
// ─────────────────────────────────────────────────────────────────────

// VerifyRotation validates a rotation message against the current
// witness set and returns the new set if valid.
//
// # Verification sequence
//
//  1. Structural: non-empty new set, non-empty current sigs, K > 0.
//  2. Current set hash: must match rotation.CurrentSetHash
//     (binds the rotation to a specific authority set).
//  3. Per-signature scheme enforcement on CurrentSignatures:
//     every signature must declare SchemeTag == SchemeTagOld.
//  4. K-of-N quorum verification of CurrentSignatures against
//     currentSet (the signatures over the rotation message).
//  5. If dual-sign (SchemeTagNew != 0 and != SchemeTagOld):
//     a. Per-signature scheme enforcement on NewSignatures:
//     every signature must declare SchemeTag == SchemeTagNew.
//     b. K-of-N quorum verification of NewSignatures against
//     rotation.NewSet (the new authority attesting to itself).
//
// # Dual-sign (Decision 41)
//
// A rotation that changes the signing scheme — e.g., migrating
// from ECDSA to BLS — carries two sets of signatures. The current
// (old-scheme) authority signs the rotation message to attest
// "yes, we authorize this new set to take over." The new
// (new-scheme) authority also signs the rotation message to
// attest "yes, we accept this role and can produce valid
// signatures under our new scheme." Both attestations are
// required for the rotation to be accepted.
//
// # Returns
//
// The new witness set on success (the caller replaces its current
// set with this returned value). A typed error on any verification
// failure; the caller does not advance its state in this case.
func VerifyRotation(
	rotation types.WitnessRotation,
	currentSet []types.WitnessPublicKey,
	quorumK int,
	blsVerifier signatures.BLSVerifier,
) ([]types.WitnessPublicKey, error) {
	// ─────────────────────────────────────────────────────────────
	// Step 1: Structural validation
	// ─────────────────────────────────────────────────────────────
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

	// ─────────────────────────────────────────────────────────────
	// Step 2: Current set hash binding
	// ─────────────────────────────────────────────────────────────
	computedHash := ComputeSetHash(currentSet)
	if computedHash != rotation.CurrentSetHash {
		return nil, fmt.Errorf("witness/rotation: set hash mismatch: computed %x, rotation claims %x",
			computedHash[:8], rotation.CurrentSetHash[:8])
	}

	// The rotation message is a commitment to the new set, signed
	// by the current set. The "message" bytes are the new set's
	// hash packaged into a TreeHead shell (TreeSize=0 by convention).
	newSetHash := ComputeSetHash(rotation.NewSet)
	rotationHeadBody := types.TreeHead{
		RootHash: newSetHash,
		TreeSize: 0, // Rotation messages use TreeSize=0 convention.
	}

	// ─────────────────────────────────────────────────────────────
	// Step 3: Per-signature scheme enforcement on CurrentSignatures
	// ─────────────────────────────────────────────────────────────
	// Wave 2 invariant: every signature in CurrentSignatures must
	// declare SchemeTag == SchemeTagOld. Mismatch is a rejection.
	//
	// This check runs BEFORE cryptographic verification because a
	// mismatched tag is a structural rejection, not a signature
	// failure. Failing here produces a clearer error than letting
	// the dispatcher reject a per-signature scheme that isn't
	// consistent with the rotation's declared authority.
	for i, sig := range rotation.CurrentSignatures {
		if sig.SchemeTag != rotation.SchemeTagOld {
			return nil, fmt.Errorf(
				"%w: CurrentSignatures[%d] declares SchemeTag 0x%02x, "+
					"but rotation declares SchemeTagOld 0x%02x",
				ErrRotationSchemeMismatch, i, sig.SchemeTag, rotation.SchemeTagOld)
		}
	}

	// ─────────────────────────────────────────────────────────────
	// Step 4: Current set signature verification
	// ─────────────────────────────────────────────────────────────
	// Construct the cosigned head for the rotation message. Post-
	// Wave-2 there is no head-level SchemeTag; each signature
	// carries its own (enforced above to match SchemeTagOld).
	rotationHead := types.CosignedTreeHead{
		TreeHead:   rotationHeadBody,
		Signatures: rotation.CurrentSignatures,
	}
	_, err := signatures.VerifyWitnessCosignatures(rotationHead, currentSet, quorumK, blsVerifier)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: current set verification: %w", err)
	}

	// ─────────────────────────────────────────────────────────────
	// Step 5: Dual-sign verification (Decision 41)
	// ─────────────────────────────────────────────────────────────
	// Check SchemeTagNew directly. A rotation that does NOT change
	// the scheme has SchemeTagNew == SchemeTagOld (or zero, which
	// Wave 2 still accepts on the WitnessRotation struct as "no
	// new-scheme transition"). Only a genuine transition triggers
	// the dual-sign path.
	if rotation.SchemeTagNew != 0 && rotation.SchemeTagNew != rotation.SchemeTagOld {
		if len(rotation.NewSignatures) == 0 {
			return nil, ErrDualSignMissingNewSigs
		}

		// 5a: Per-signature scheme enforcement on NewSignatures.
		// Same strict invariant as CurrentSignatures, but targeting
		// SchemeTagNew.
		for i, sig := range rotation.NewSignatures {
			if sig.SchemeTag != rotation.SchemeTagNew {
				return nil, fmt.Errorf(
					"%w: NewSignatures[%d] declares SchemeTag 0x%02x, "+
						"but rotation declares SchemeTagNew 0x%02x",
					ErrRotationSchemeMismatch, i, sig.SchemeTag, rotation.SchemeTagNew)
			}
		}

		// 5b: Verify new-scheme signatures against the NEW set.
		// The new authority signs the same rotation message (the
		// new-set hash) under the new scheme — attesting that it
		// accepts the role and can produce valid signatures.
		dualHead := types.CosignedTreeHead{
			TreeHead:   rotationHeadBody,
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

// VerifyRotationChain walks from a genesis witness set through a
// sequence of rotations, verifying each step. Returns the final
// current set.
//
// Used by bootstrap.go HardcodedGenesis method: compiled-in genesis
// set → fetch rotation history → verify chain → current set.
//
// Each rotation is verified against the set produced by the prior
// step. If any step fails, returns ErrRotationChainBroken with the
// step index for diagnostic purposes.
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

// ComputeSetHash computes a deterministic SHA-256 hash of a witness
// key set. Keys are hashed in order (caller must ensure canonical
// ordering if needed). Used for rotation message binding: "this
// rotation targets THIS specific set."
//
// Not changed in Wave 2 — the set-hash convention binds the witness
// identity set, not the signing scheme.
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
