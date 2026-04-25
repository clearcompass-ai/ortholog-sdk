/*
Package witness provides higher-level witness operations over Phase 1
cryptographic primitives.

verify.go wraps signatures.VerifyWitnessCosignatures with:
  - Typed errors (ErrInsufficientWitnesses)
  - Quorum enforcement
  - Optional DID resolution for witness key discovery
  - BLS verifier passthrough

The builder and operator infrastructure (head_sync.go, equivocation_monitor.go)
live in ortholog-operator/witness/. This SDK package is for verification —
consumed by cross_log.go, bootstrap.go, and domain verification code.
*/
package witness

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrInsufficientWitnesses is returned when fewer than K valid signatures
// are present on a cosigned tree head.
var ErrInsufficientWitnesses = errors.New("witness: insufficient valid signatures")

// ErrNoSignatures is returned when a cosigned tree head has zero signatures.
var ErrNoSignatures = errors.New("witness: no cosignatures present")

// ErrEmptyWitnessSet is returned when the witness key set is empty.
var ErrEmptyWitnessSet = errors.New("witness: empty witness key set")

// ─────────────────────────────────────────────────────────────────────
// VerifyTreeHead — K-of-N cosignature verification
// ─────────────────────────────────────────────────────────────────────

// VerifyResult holds the outcome of tree head verification.
type VerifyResult struct {
	ValidCount int
	Total      int
	QuorumK    int
	Details    []SignerResult
}

// SignerResult holds per-signer verification status.
type SignerResult struct {
	PubKeyID [32]byte
	Valid    bool
	Err      error
}

// VerifyTreeHead verifies that a cosigned tree head has at least K valid
// signatures from the given witness key set. Dispatches on SchemeTag
// (ECDSA or BLS).
//
// This is the primary verification entry point for tree heads. Called by:
//   - cross_log.go steps 1 and 4
//   - bootstrap.go (all methods verify at least one head)
//   - domain verification code
func VerifyTreeHead(
	head types.CosignedTreeHead,
	witnessKeys []types.WitnessPublicKey,
	quorumK int,
	blsVerifier signatures.BLSVerifier,
) (*VerifyResult, error) {
	if quorumK <= 0 {
		return nil, fmt.Errorf("witness/verify: K must be positive, got %d", quorumK)
	}
	if len(witnessKeys) == 0 {
		return nil, ErrEmptyWitnessSet
	}
	if len(head.Signatures) == 0 {
		return nil, ErrNoSignatures
	}
	// Gate: muEnableWitnessQuorumCount (verify_mutation_switches.go).
	// Off lets undersized witness sets fall through to the Phase-1
	// primitive, where the failure mode depends on signature shape.
	if muEnableWitnessQuorumCount {
		if len(witnessKeys) < quorumK {
			return nil, fmt.Errorf("witness/verify: witness set size %d < quorum %d", len(witnessKeys), quorumK)
		}
	}

	result, err := signatures.VerifyWitnessCosignatures(head, witnessKeys, quorumK, blsVerifier)
	if err != nil {
		// Wrap the Phase 1 error with our typed error if it's a quorum failure.
		if result != nil && result.ValidCount < quorumK {
			return &VerifyResult{
				ValidCount: result.ValidCount,
				Total:      result.Total,
				QuorumK:    quorumK,
				Details:    convertDetails(result.Results),
			}, fmt.Errorf("%w: %d of %d valid (need %d)",
				ErrInsufficientWitnesses, result.ValidCount, result.Total, quorumK)
		}
		return nil, fmt.Errorf("witness/verify: %w", err)
	}

	// Group 8.3 — post-verify uniqueness and membership checks.
	// Both operate on the Phase-1 primitive's per-signature result
	// table, deduplicating to a canonical unique-valid count.
	uniqueValid := countValidUnique(result, witnessKeys)
	if muEnableUniqueSigners || muEnableWitnessKeyMembership {
		if uniqueValid < quorumK {
			return &VerifyResult{
				ValidCount: uniqueValid,
				Total:      result.Total,
				QuorumK:    quorumK,
				Details:    convertDetails(result.Results),
			}, fmt.Errorf("%w: %d unique valid of %d (need %d)",
				ErrInsufficientWitnesses, uniqueValid, result.Total, quorumK)
		}
	}

	return &VerifyResult{
		ValidCount: result.ValidCount,
		Total:      result.Total,
		QuorumK:    quorumK,
		Details:    convertDetails(result.Results),
	}, nil
}

// countValidUnique post-processes the Phase-1 per-signature result
// table to derive a canonical unique-valid count under the Group 8.3
// gates. The two gates compose:
//
//   - muEnableUniqueSigners: the same PubKeyID appearing in multiple
//     result rows counts at most once.
//   - muEnableWitnessKeyMembership: a successful row whose PubKeyID
//     is not in witnessKeys does not count at all.
//
// When either gate is off, its contribution to the count is dropped
// (duplicates admitted, non-members admitted). Both off yields
// result.ValidCount unchanged, matching pre-Group-8.3 semantics.
func countValidUnique(r *signatures.WitnessVerifyResult, witnessKeys []types.WitnessPublicKey) int {
	if r == nil {
		return 0
	}
	var membershipSet map[[32]byte]bool
	if muEnableWitnessKeyMembership {
		membershipSet = make(map[[32]byte]bool, len(witnessKeys))
		for _, wk := range witnessKeys {
			membershipSet[wk.ID] = true
		}
	}
	seen := make(map[[32]byte]bool, len(r.Results))
	count := 0
	for _, row := range r.Results {
		if !row.Valid {
			continue
		}
		if muEnableWitnessKeyMembership && !membershipSet[row.PubKeyID] {
			continue
		}
		if muEnableUniqueSigners {
			if seen[row.PubKeyID] {
				continue
			}
			seen[row.PubKeyID] = true
		}
		count++
	}
	return count
}

// ─────────────────────────────────────────────────────────────────────
// VerifyTreeHeadWithResolution — DID → witness keys → verify
// ─────────────────────────────────────────────────────────────────────

// EndpointResolver resolves a log DID to its witness key set.
// Satisfied by did.DIDResolver (Phase 4 Step 1) via structural typing.
// Defined here so the witness package compiles independently of did/.
type EndpointResolver interface {
	ResolveWitnessKeys(logDID string) ([]types.WitnessPublicKey, int, error)
}

// VerifyTreeHeadWithResolution resolves a log DID to discover its witness
// keys and quorum K, then verifies the cosigned tree head.
//
// Used by cross_log.go step 4: verify source log's tree head using
// the source log's own witness set (discovered via DID resolution).
func VerifyTreeHeadWithResolution(
	head types.CosignedTreeHead,
	logDID string,
	resolver EndpointResolver,
	blsVerifier signatures.BLSVerifier,
) (*VerifyResult, error) {
	if resolver == nil {
		return nil, errors.New("witness/verify: nil resolver")
	}

	witnessKeys, quorumK, err := resolver.ResolveWitnessKeys(logDID)
	if err != nil {
		return nil, fmt.Errorf("witness/verify: resolve %s: %w", logDID, err)
	}

	return VerifyTreeHead(head, witnessKeys, quorumK, blsVerifier)
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func convertDetails(results []signatures.WitnessSignerResult) []SignerResult {
	out := make([]SignerResult, len(results))
	for i, r := range results {
		out[i] = SignerResult{
			PubKeyID: r.PubKeyID,
			Valid:    r.Valid,
			Err:      r.Err,
		}
	}
	return out
}
