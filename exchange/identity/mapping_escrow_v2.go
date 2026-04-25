// Package identity — mapping_escrow_v2.go extends MappingEscrow with
// the v7.75 Phase C (ADR-005 §4) V2 Pedersen VSS path, adding atomic
// commitment-entry emission alongside the share split.
//
// Why a separate method. The V1 StoreMapping flow is frozen for
// backward compatibility: V1 GF(256) Shamir shares have no Pedersen
// commitments, the SplitID is random (not derived from dealer DID +
// nonce), and existing callers depend on the current return shape.
// Introducing V2 as a new method (StoreMappingV2) preserves those
// invariants while giving new callers access to the
// cryptographically-verified share surface and the on-log commitment
// entry.
//
// Atomic-emission invariant (ADR-005 §4). StoreMappingV2 either
// returns shares + a non-nil CommitmentEntry, or it returns an error.
// No path emits shares without a corresponding commitment entry. The
// invariant is gated by muEnableCommitmentEmissionAtomic in the
// lifecycle layer's commitment_atomic.go; the lifecycle gate is the
// registered mutation-audit target. Here we carry the invariant over
// the package boundary via an explicit assertion that fails fast if
// the return shape drifts.
package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrV2MissingDealerDID is returned by StoreMappingV2 when
	// DealerDID is empty. V2 binds the SplitID deterministically to
	// (dealerDID, nonce); an empty dealer DID would produce a
	// SplitID indistinguishable from any other empty-DID call.
	ErrV2MissingDealerDID = errors.New("identity/escrow_v2: dealer DID must not be empty")

	// ErrV2MissingDestination is returned when Destination is empty.
	// The commitment entry is destination-bound; a zero destination
	// would let it replay across exchanges.
	ErrV2MissingDestination = errors.New("identity/escrow_v2: destination must not be empty")

	// ErrV2AtomicEmissionViolated is returned when shares are
	// produced but the commitment entry is nil — should be
	// unreachable under muEnableCommitmentEmissionAtomic=true, but
	// surfaces as an explicit error if the mutation probe flips the
	// switch off.
	ErrV2AtomicEmissionViolated = errors.New(
		"identity/escrow_v2: atomic emission invariant violated: shares without commitment entry",
	)
)

// ─────────────────────────────────────────────────────────────────────
// V2 types
// ─────────────────────────────────────────────────────────────────────

// StoredMappingV2 is the V2-aware counterpart to StoredMapping. Adds
// the nonce used to derive the deterministic SplitID so a later
// VerifyEscrowSplitCommitment can recompute the binding.
//
// All fields are non-secret. The nonce is not a secret under V2's
// threat model — a malicious dealer already knows it, and a verifier
// with the nonce + dealer DID reconstructs the SplitID to gate on
// the on-log commitment.
type StoredMappingV2 struct {
	CID         storage.CID
	Nonce       [12]byte   // AES-GCM IV, public by design.
	K           int        // Threshold (M).
	N           int        // Total shares.
	SplitID     [32]byte   // Deterministic: ComputeEscrowSplitID(dealerDID, splitNonce).
	SplitNonce  [32]byte   // 32-byte nonce bound into SplitID.
	DealerDID   string     // Dealer identity bound into SplitID.
	IdentityTag [32]byte   // SHA-256(identity_hash) for index lookup.
	CreatedAt   int64
}

// StoreMappingV2Config carries the V2-specific inputs to
// StoreMappingV2: dealer identity, destination, and optional nonce
// source (for determinism in tests).
type StoreMappingV2Config struct {
	// DealerDID is the dealer's DID. Required; bound into SplitID.
	DealerDID string

	// Destination is the DID of the target exchange. Required;
	// validated by envelope.ValidateDestination.
	Destination string

	// EventTime stamps the commitment entry. Zero means "no event
	// time" — the entry carries the caller-supplied value verbatim.
	EventTime int64

	// NonceReader optionally overrides crypto/rand for the 32-byte
	// SplitID nonce. nil means crypto/rand. Tests use this for
	// byte-reproducible fixtures; production callers leave it nil.
	NonceReader io.Reader
}

// StoreMappingV2Result bundles the outputs of StoreMappingV2. Shares
// are non-nil if and only if CommitmentEntry is non-nil. This is the
// structural expression of the atomic-emission invariant.
type StoreMappingV2Result struct {
	Stored          *StoredMappingV2
	EncShares       []EncryptedShare
	Commitment      *escrow.EscrowSplitCommitment
	CommitmentEntry *envelope.Entry
}

// ─────────────────────────────────────────────────────────────────────
// StoreMappingV2
// ─────────────────────────────────────────────────────────────────────

// StoreMappingV2 is the V2 Pedersen-VSS counterpart to StoreMapping.
// Splits the encryption key via escrow.SplitV2 (producing a commitment
// set), wraps the shares via ECIES exactly like V1, and emits the
// signed escrow-split-commitment-v1 entry atomically. The commitment
// entry is returned on the result; the caller submits it to the log
// alongside the share distribution.
//
// Invariants:
//
//   - Exactly TotalShares nodes; each with a non-empty DID and
//     non-nil PubKey.
//   - The dealerDID in cfg is bound into the SplitID and the
//     commitment. The commitment verifies against (dealerDID, nonce).
//   - Plaintext shares are zeroized before return regardless of
//     success or failure (same contract as V1).
//   - Atomic emission: shares and commitment entry either both exist
//     or neither does.
//
// Returns ErrV2MissingDealerDID, ErrV2MissingDestination,
// ErrNodeCountMismatch, ErrInvalidIdentity, ErrInvalidCredentialRef,
// ErrInvalidNode, or wrapped escrow/ECIES errors. Rollback behavior
// mirrors V1: on any failure past the ciphertext push, the ciphertext
// is deleted.
func (me *MappingEscrow) StoreMappingV2(
	record MappingRecord,
	nodes []EscrowNode,
	cfg StoreMappingV2Config,
) (*StoreMappingV2Result, error) {
	if err := envelope.ValidateDestination(cfg.Destination); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrV2MissingDestination, err)
	}
	if cfg.DealerDID == "" {
		return nil, ErrV2MissingDealerDID
	}
	if record.IdentityHash == [32]byte{} {
		return nil, ErrInvalidIdentity
	}
	if record.CredentialRef.LogDID == "" {
		return nil, ErrInvalidCredentialRef
	}
	if len(nodes) != me.cfg.TotalShares {
		return nil, fmt.Errorf(
			"%w: got %d nodes, expected %d",
			ErrNodeCountMismatch, len(nodes), me.cfg.TotalShares,
		)
	}
	for i, n := range nodes {
		if n.DID == "" {
			return nil, fmt.Errorf("%w: node %d has empty DID", ErrInvalidNode, i)
		}
		if n.PubKey == nil {
			return nil, fmt.Errorf(
				"%w: node %d (%s) has nil PubKey", ErrInvalidNode, i, n.DID,
			)
		}
	}

	return me.storeMappingV2Inner(record, nodes, cfg)
}

// storeMappingV2Inner runs the post-validation V2 flow. Split out
// so the input-validation surface above stays shallow and the
// failure-rollback chain below is linear.
func (me *MappingEscrow) storeMappingV2Inner(
	record MappingRecord,
	nodes []EscrowNode,
	cfg StoreMappingV2Config,
) (*StoreMappingV2Result, error) {
	// 1. Serialize and encrypt the mapping record.
	plaintext, err := marshalMappingRecord(record)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: marshal: %w", err)
	}
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: encrypt: %w", err)
	}
	nonce := artKey.Nonce

	// 2. Draw a fresh SplitID nonce from the caller-supplied reader
	//    (or crypto/rand if nil).
	var splitNonce [32]byte
	r := cfg.NonceReader
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, splitNonce[:]); err != nil {
		zeroArtKey(&artKey)
		return nil, fmt.Errorf("identity/escrow_v2: read nonce: %w", err)
	}

	// 3. V2 split: produces shares + commitment set + deterministic SplitID.
	shares, commitments, splitID, err := escrow.SplitV2(
		artKey.Key[:],
		me.cfg.ShareThreshold,
		me.cfg.TotalShares,
		cfg.DealerDID,
		splitNonce,
	)
	if err != nil {
		zeroArtKey(&artKey)
		return nil, fmt.Errorf("identity/escrow_v2: split key: %w", err)
	}
	zeroArtKey(&artKey)
	defer escrow.ZeroizeShares(shares)

	// 4. Build the EscrowSplitCommitment wire struct at the RAM/wire boundary.
	commitment, err := escrow.NewEscrowSplitCommitmentFromVSS(
		splitID, me.cfg.ShareThreshold, me.cfg.TotalShares, cfg.DealerDID, commitments,
	)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: build commitment: %w", err)
	}
	if err := escrow.VerifyEscrowSplitCommitment(commitment, splitNonce); err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: self-verify commitment: %w", err)
	}

	// 5. Build the signed commitment entry. Signer = dealer.
	commitmentEntry, err := builder.BuildEscrowSplitCommitmentEntry(builder.EscrowSplitCommitmentEntryParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.DealerDID,
		Commitment:  commitment,
		EventTime:   cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: build commitment entry: %w", err)
	}

	// 6. Push the ciphertext.
	cid := storage.Compute(ciphertext)
	if err := me.store.Push(cid, ciphertext); err != nil {
		return nil, fmt.Errorf("identity/escrow_v2: push: %w", err)
	}

	// 7. ECIES-wrap each share, rolling back the ciphertext on any failure.
	encShares, err := me.wrapSharesOrRollback(cid, shares, nodes)
	if err != nil {
		return nil, err
	}

	// 8. Build and index the StoredMappingV2.
	identityTag := hashBytes32(record.IdentityHash[:])
	stored := &StoredMappingV2{
		CID:         cid,
		Nonce:       nonce,
		K:           me.cfg.ShareThreshold,
		N:           me.cfg.TotalShares,
		SplitID:     splitID,
		SplitNonce:  splitNonce,
		DealerDID:   cfg.DealerDID,
		IdentityTag: identityTag,
		CreatedAt:   record.CreatedAt,
	}
	me.indexV2(identityTag, stored)

	result := &StoreMappingV2Result{
		Stored:          stored,
		EncShares:       encShares,
		Commitment:      commitment,
		CommitmentEntry: commitmentEntry,
	}

	// Atomic-emission invariant. Routed through assertV2AtomicEmission
	// (mapping_escrow_v2_helpers.go) so the gate has an observable
	// binding test on the pathological (shares > 0, entry == nil)
	// tuple that the production happy path never produces.
	if err := assertV2AtomicEmission(result.EncShares, result.CommitmentEntry); err != nil {
		return nil, err
	}
	return result, nil
}
