/*
verifier/cross_log.go — Cross-log reference verification.

A cross-log reference proves that an entry in a foreign (source) log
is included in a tree head, and that the tree head is itself anchored
by an entry in the local log. The verifier checks both halves.

PROTOCOL:

	Step 1: Fetch source entry, compute its RFC 6962 leaf hash.
	Step 2: Verify source inclusion proof against source tree head,
	        with leaf hash bound to claimed source entry hash.
	Step 3: Verify source tree head has valid K-of-N witness cosignatures.
	Step 4: Verify local inclusion proof against local tree head, with
	        leaf hash bound to claimed anchor entry hash.
	Step 5: Verify the canonical bytes carried in the proof match the
	        proven anchor entry hash to prevent byte substitution.
	Step 6: Deserialize the anchor entry, extract the embedded tree head
	        ref from its payload, and verify it matches hash(SourceTreeHead).

KEY ARCHITECTURAL DECISIONS:
  - Hash type: RFC 6962 leaf hash (SHA-256(0x00 || canonical)) via
    envelope.EntryLeafHashBytes. NOT SHA-256(canonical) — that's
    EntryIdentity, used for dedup, not for Merkle proofs.
  - Binding checks: every claimed entry hash in CrossLogProof is
    verified to equal the inclusion proof's LeafHash.
  - Anchor payload binding: The proof carries the physical CanonicalBytes
    of the anchor entry. The verifier hashes them, ensures they match the
    inclusion proof, deserializes them, and invokes a domain-provided
    extractor. This keeps the verifier as a pure function (no network I/O)
    while maintaining strict domain separation (the SDK doesn't parse JSON).

CONSUMED BY:
  - Domain verification flows (verify foreign credential)
  - Exchange protocol (verify counterparty's entry)
  - Monitoring services (cross-log consistency checks)
*/
package verifier

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	ErrSourceEntryNotFound   = errors.New("verifier/cross_log: source entry not found")
	ErrSourceInclusionFailed = errors.New("verifier/cross_log: source inclusion proof failed")
	ErrSourceHeadInvalid     = errors.New("verifier/cross_log: source tree head invalid")
	ErrAnchorMismatch        = errors.New("verifier/cross_log: anchor tree head ref mismatch")
	ErrLocalInclusionFailed  = errors.New("verifier/cross_log: local inclusion proof failed")
	ErrAnchorEntryNotFound   = errors.New("verifier/cross_log: anchor entry not found")

	// ErrExtractorRequired is returned when VerifyCrossLogProof is
	// called with a nil AnchorPayloadExtractor. Without an extractor,
	// the step 9 payload content-binding check cannot run, and a
	// proof whose AnchorEntryCanonical bytes hash correctly but whose
	// DomainPayload does not commit to the source tree head would
	// silently verify. This would re-open the Forged Anchor Attack.
	// The extractor is a mandatory dependency, not an option.
	ErrExtractorRequired = errors.New("verifier/cross_log: anchor payload extractor required")
)

// ─────────────────────────────────────────────────────────────────────
// Interfaces & Types
// ─────────────────────────────────────────────────────────────────────

// MerkleProver generates inclusion proofs for log entries.
// Satisfied by smt.StubMerkleTree (tests) and operator's TesseraAdapter
// (production, after parsing response into types.MerkleProof).
//
// Implementations should populate MerkleProof.LeafHash when the leaf
// bytes are available. Callers that compute the leaf hash themselves
// (e.g., from pre-fetched canonical bytes) overwrite this field
// explicitly before handing the proof to a consumer.
type MerkleProver interface {
	InclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
}

// AnchorPayloadExtractor parses the opaque DomainPayload of an anchor entry
// and returns the 32-byte tree head reference it claims to anchor.
// Provided by the domain application to keep the SDK payload-agnostic.
type AnchorPayloadExtractor func(domainPayload []byte) ([32]byte, error)

// ─────────────────────────────────────────────────────────────────────
// VerifyCrossLogProof — verify a completed CrossLogProof
// ─────────────────────────────────────────────────────────────────────

// VerifyCrossLogProof verifies all components of a cross-log proof.
//
// Checks (in order):
//  1. SourceEntryHash is non-zero
//  2. SourceInclusion.LeafHash matches SourceEntryHash         [binding]
//  3. SourceInclusion verifies against SourceTreeHead.RootHash
//  4. SourceTreeHead has valid K-of-N witness cosignatures
//  5. LocalInclusion.LeafHash matches AnchorEntryHash          [binding]
//  6. LocalInclusion verifies against LocalTreeHead.RootHash
//  7. AnchorEntryCanonical hashes to AnchorEntryHash           [binding]
//  8. AnchorEntryCanonical deserializes to a valid entry
//  9. DomainPayload explicitly commits to hash(SourceTreeHead) [binding]
func VerifyCrossLogProof(
	proof types.CrossLogProof,
	sourceWitnessKeys []types.WitnessPublicKey,
	sourceQuorumK int,
	blsVerifier signatures.BLSVerifier,
	extractAnchor AnchorPayloadExtractor,
) error {
	// Guard: extractor is mandatory. Gate: muEnableExtractorRequired
	// (Group 8.2). A nil extractor would make the content-binding
	// check (step 9) reachable only via a nil-deref panic, which is
	// a degenerate failure mode. Fail-fast with a typed error so
	// callers can distinguish "misuse of the verifier" from "proof
	// actually invalid."
	if muEnableExtractorRequired && extractAnchor == nil {
		return ErrExtractorRequired
	}

	// 1. Source entry hash must be non-zero.
	// Gate: muEnableSourceEntryNonZero (Group 8.2).
	if muEnableSourceEntryNonZero && proof.SourceEntryHash == [32]byte{} {
		return fmt.Errorf("%w: zero source entry hash", ErrSourceInclusionFailed)
	}

	// 2. Bind source inclusion proof to claimed source entry hash.
	// Gate: muEnableSourceInclusionBinding (Group 8.2).
	if muEnableSourceInclusionBinding && proof.SourceInclusion.LeafHash != proof.SourceEntryHash {
		return fmt.Errorf("%w: inclusion leaf hash %x does not match claimed source entry hash %x",
			ErrSourceInclusionFailed,
			proof.SourceInclusion.LeafHash[:8],
			proof.SourceEntryHash[:8])
	}

	// 3. Verify source inclusion proof against source tree head root.
	// Gate: muEnableSourceInclusionVerify (Group 8.2).
	if muEnableSourceInclusionVerify {
		if err := smt.VerifyMerkleInclusion(&proof.SourceInclusion, proof.SourceTreeHead.RootHash); err != nil {
			return fmt.Errorf("%w: %v", ErrSourceInclusionFailed, err)
		}
	}

	// 4. Verify source tree head has valid witness cosignatures.
	// Gate: muEnableSourceHeadCosigVerify (Group 8.2).
	if muEnableSourceHeadCosigVerify {
		if _, err := witness.VerifyTreeHead(proof.SourceTreeHead, sourceWitnessKeys, sourceQuorumK, blsVerifier); err != nil {
			return fmt.Errorf("%w: %v", ErrSourceHeadInvalid, err)
		}
	}

	// 5. Bind local inclusion proof to claimed anchor entry hash.
	// Gate: muEnableLocalInclusionBinding (Group 8.2).
	if muEnableLocalInclusionBinding && proof.LocalInclusion.LeafHash != proof.AnchorEntryHash {
		return fmt.Errorf("%w: inclusion leaf hash %x does not match claimed anchor entry hash %x",
			ErrLocalInclusionFailed,
			proof.LocalInclusion.LeafHash[:8],
			proof.AnchorEntryHash[:8])
	}

	// 6. Verify local inclusion proof against local tree head root.
	// Gate: muEnableLocalInclusionVerify (Group 8.2).
	if muEnableLocalInclusionVerify {
		if err := smt.VerifyMerkleInclusion(&proof.LocalInclusion, proof.LocalTreeHead.RootHash); err != nil {
			return fmt.Errorf("%w: %v", ErrLocalInclusionFailed, err)
		}
	}

	// ─────────────────────────────────────────────────────────────
	// ANCHOR PAYLOAD BINDING
	// ─────────────────────────────────────────────────────────────

	// 7. Defend against byte substitution: verify the bytes carried in the
	// proof actually hash to the AnchorEntryHash that was proven in Step 6.
	// Gate: muEnableAnchorBytesHashBinding (Group 8.2).
	actualAnchorHash := envelope.EntryLeafHashBytes(proof.AnchorEntryCanonical)
	if muEnableAnchorBytesHashBinding && actualAnchorHash != proof.AnchorEntryHash {
		return fmt.Errorf("%w: canonical bytes do not match proven anchor hash", ErrAnchorMismatch)
	}

	// 8. Deserialize the physical entry to inspect its contents.
	anchorEntry, err := envelope.Deserialize(proof.AnchorEntryCanonical)
	if err != nil {
		return fmt.Errorf("verifier/cross_log: failed to deserialize anchor entry: %w", err)
	}

	// 9. Extract the tree head reference from the physical DomainPayload.
	// Gate: muEnableAnchorPayloadExtraction (Group 8.2).
	var embeddedRef [32]byte
	if extractAnchor != nil {
		var extractErr error
		embeddedRef, extractErr = extractAnchor(anchorEntry.DomainPayload)
		if muEnableAnchorPayloadExtraction && extractErr != nil {
			return fmt.Errorf("verifier/cross_log: failed to extract anchor reference from payload: %w", extractErr)
		}
	}

	// 10. Does the explicitly written payload match the source tree head?
	// Gate: muEnableAnchorContentBinding (Group 8.2).
	expectedRef := TreeHeadHash(proof.SourceTreeHead.TreeHead)
	if muEnableAnchorContentBinding && embeddedRef != expectedRef {
		return fmt.Errorf("%w: payload embedded ref %x does not match actual source tree head %x",
			ErrAnchorMismatch, embeddedRef[:8], expectedRef[:8])
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────
// BuildCrossLogProof — collect evidence and assemble proof
// ─────────────────────────────────────────────────────────────────────

// BuildCrossLogProof fetches entries and inclusion proofs, then assembles
// a complete CrossLogProof.
//
// Hash discipline: both SourceEntryHash and AnchorEntryHash are RFC 6962
// leaf hashes (envelope.EntryLeafHashBytes), NOT SHA-256(canonical).
//
// The builder explicitly sets MerkleProof.LeafHash on both inclusion
// proofs. This is defensive against prover implementations that leave it zero.
func BuildCrossLogProof(
	sourceRef types.LogPosition,
	anchorRef types.LogPosition,
	fetcher types.EntryFetcher,
	sourceProver MerkleProver,
	localProver MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
) (*types.CrossLogProof, error) {
	// Step 1: Fetch source entry and compute its RFC 6962 leaf hash.
	sourceEntry, err := fetcher.Fetch(sourceRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSourceEntryNotFound, err)
	}
	sourceEntryHash := envelope.EntryLeafHashBytes(sourceEntry.CanonicalBytes)

	// Step 2: Get source inclusion proof, bind leaf hash explicitly.
	sourceInclusion, err := sourceProver.InclusionProof(sourceRef.Sequence, sourceHead.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("%w: source proof: %v", ErrSourceInclusionFailed, err)
	}
	sourceInclusion.LeafHash = sourceEntryHash

	// Step 3: Fetch anchor entry and compute its RFC 6962 leaf hash.
	anchorEntry, err := fetcher.Fetch(anchorRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnchorEntryNotFound, err)
	}
	anchorEntryHash := envelope.EntryLeafHashBytes(anchorEntry.CanonicalBytes)

	// Step 4: Get local inclusion proof, bind leaf hash explicitly.
	localInclusion, err := localProver.InclusionProof(anchorRef.Sequence, localHead.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("%w: local proof: %v", ErrLocalInclusionFailed, err)
	}
	localInclusion.LeafHash = anchorEntryHash

	return &types.CrossLogProof{
		SourceEntry:          sourceRef,
		SourceEntryHash:      sourceEntryHash,
		SourceTreeHead:       sourceHead,
		SourceInclusion:      *sourceInclusion,
		AnchorEntry:          anchorRef,
		AnchorEntryHash:      anchorEntryHash,
		AnchorEntryCanonical: anchorEntry.CanonicalBytes,
		LocalTreeHead:        localHead,
		LocalInclusion:       *localInclusion,
	}, nil
}
