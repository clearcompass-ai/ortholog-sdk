/*
verifier/cross_log.go — Cross-log reference verification.

A cross-log reference proves that an entry in a foreign (source) log
is included in a locally-anchored tree head. The 4-step protocol:

  Step 1: Fetch source entry, compute its hash.
  Step 2: Verify source entry inclusion in source tree head (Merkle proof).
  Step 3: Verify source tree head has valid witness cosignatures.
  Step 4: Verify anchor entry inclusion in local tree head (Merkle proof).

VerifyCrossLogProof: verifies a pre-built types.CrossLogProof.
BuildCrossLogProof: collects evidence from fetcher + provers, builds proof.

Consumed by:
  - Domain verification flows (verify foreign credential)
  - Exchange protocol (verify counterparty's entry)
  - Monitoring services (cross-log consistency checks)
*/
package verifier

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var ErrSourceEntryNotFound = errors.New("verifier/cross_log: source entry not found")
var ErrSourceInclusionFailed = errors.New("verifier/cross_log: source inclusion proof failed")
var ErrSourceHeadInvalid = errors.New("verifier/cross_log: source tree head invalid")
var ErrAnchorMismatch = errors.New("verifier/cross_log: anchor tree head ref mismatch")
var ErrLocalInclusionFailed = errors.New("verifier/cross_log: local inclusion proof failed")
var ErrAnchorEntryNotFound = errors.New("verifier/cross_log: anchor entry not found")

// ─────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────

// MerkleProver generates inclusion proofs for log entries.
// Satisfied by smt.StubMerkleTree (tests) and operator's TesseraAdapter
// (production, after parsing response into types.MerkleProof).
type MerkleProver interface {
	InclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
}

// EntryFetcher fetches log entries by position.
// Structurally identical to builder.EntryFetcher — no import needed.
type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// ─────────────────────────────────────────────────────────────────────
// VerifyCrossLogProof — verify a completed CrossLogProof
// ─────────────────────────────────────────────────────────────────────

// VerifyCrossLogProof verifies all components of a cross-log proof.
//
// Checks (in order):
//  1. SourceEntryHash is non-zero
//  2. SourceInclusion proof verifies against SourceTreeHead.RootHash
//  3. SourceTreeHead has valid K-of-N witness cosignatures
//  4. AnchorTreeHeadRef matches hash(SourceTreeHead)
//  5. LocalInclusion proof verifies against LocalTreeHead.RootHash
//
// All five checks must pass. If any fails, the specific error identifies
// which step failed for diagnostics.
func VerifyCrossLogProof(
	proof types.CrossLogProof,
	sourceWitnessKeys []types.WitnessPublicKey,
	sourceQuorumK int,
	blsVerifier signatures.BLSVerifier,
) error {
	// 1. Source entry hash must be non-zero.
	if proof.SourceEntryHash == [32]byte{} {
		return fmt.Errorf("%w: zero source entry hash", ErrSourceInclusionFailed)
	}

	// 2. Verify source inclusion.
	if err := smt.VerifyMerkleInclusion(&proof.SourceInclusion, proof.SourceTreeHead.RootHash); err != nil {
		return fmt.Errorf("%w: %v", ErrSourceInclusionFailed, err)
	}

	// 3. Verify source tree head witness signatures.
	_, err := witness.VerifyTreeHead(proof.SourceTreeHead, sourceWitnessKeys, sourceQuorumK, blsVerifier)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSourceHeadInvalid, err)
	}

	// 4. Anchor tree head ref must match hash of source tree head.
	expectedRef := TreeHeadHash(proof.SourceTreeHead.TreeHead)
	if proof.AnchorTreeHeadRef != expectedRef {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrAnchorMismatch, expectedRef[:8], proof.AnchorTreeHeadRef[:8])
	}

	// 5. Verify local inclusion.
	if err := smt.VerifyMerkleInclusion(&proof.LocalInclusion, proof.LocalTreeHead.RootHash); err != nil {
		return fmt.Errorf("%w: %v", ErrLocalInclusionFailed, err)
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────
// BuildCrossLogProof — collect evidence and assemble proof
// ─────────────────────────────────────────────────────────────────────

// BuildCrossLogProof fetches entries and inclusion proofs, then assembles
// a complete CrossLogProof. The caller provides:
//
//   - sourceRef: position of the entry in the foreign log
//   - anchorRef: position of the anchor entry in the local log
//   - fetcher: capable of fetching entries from both logs
//   - sourceProver/localProver: generate Merkle inclusion proofs
//   - sourceHead/localHead: cosigned tree heads for both logs
func BuildCrossLogProof(
	sourceRef types.LogPosition,
	anchorRef types.LogPosition,
	fetcher EntryFetcher,
	sourceProver MerkleProver,
	localProver MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
) (*types.CrossLogProof, error) {
	// Step 1: Fetch source entry and compute hash.
	sourceEntry, err := fetcher.Fetch(sourceRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSourceEntryNotFound, err)
	}
	sourceEntryHash := sha256.Sum256(sourceEntry.CanonicalBytes)

	// Step 2: Get source inclusion proof.
	sourceInclusion, err := sourceProver.InclusionProof(sourceRef.Sequence, sourceHead.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("%w: source proof: %v", ErrSourceInclusionFailed, err)
	}

	// Step 3: Fetch anchor entry and compute hash.
	anchorEntry, err := fetcher.Fetch(anchorRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnchorEntryNotFound, err)
	}
	anchorEntryHash := sha256.Sum256(anchorEntry.CanonicalBytes)

	// Step 4: Get local inclusion proof for anchor.
	localInclusion, err := localProver.InclusionProof(anchorRef.Sequence, localHead.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("%w: local proof: %v", ErrLocalInclusionFailed, err)
	}

	// Compute anchor tree head reference.
	anchorTreeHeadRef := TreeHeadHash(sourceHead.TreeHead)

	return &types.CrossLogProof{
		SourceEntry:       sourceRef,
		SourceEntryHash:   sourceEntryHash,
		SourceTreeHead:    sourceHead,
		SourceInclusion:   *sourceInclusion,
		AnchorEntry:       anchorRef,
		AnchorEntryHash:   anchorEntryHash,
		AnchorTreeHeadRef: anchorTreeHeadRef,
		LocalTreeHead:     localHead,
		LocalInclusion:    *localInclusion,
	}, nil
}
