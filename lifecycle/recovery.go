/*
Package lifecycle — recovery.go implements three-phase key escrow recovery
for the Ortholog protocol. Used when an exchange fails, a holder's keys
are lost or compromised, or an identity migrates to a new credentialing
authority.

# Overview

There are three identity-recovery TYPES, determined by DID method:

	did:web   → in-place succession. The institution updates its hosted
	            did.json and publishes a Succession Entry. The identifier
	            is stable; only the authorized key changes.
	did:pkh   → new-wallet succession via escrow-proof. The holder proves
	            they owned the old wallet by decrypting the mapping_escrow,
	            then a Succession Entry links the new wallet to the old
	            wallet's history.
	did:key   → no recovery. Self-certifying ephemeral identifiers do not
	            survive key loss. A new did:key is generated and the
	            holder starts over.

There are two execution MECHANISMS:

	cooperative → M-of-N cryptographic escrow. The holder's AES key was
	              previously split via Shamir-style secret sharing and
	              each share was ECIES-wrapped for an independent escrow
	              node. Recovery collects and reconstructs the shares.
	              InitiateRecovery → CollectShares → ExecuteRecovery
	              implements this pathway.
	arbitrated  → consensus override. When escrow nodes refuse to
	              cooperate or the holder's keys are stolen, the
	              AuthoritySet votes. A supermajority of administrators
	              plus an independent witness can authorize the override
	              without escrow cooperation. EvaluateArbitration
	              implements this pathway.

# Scheme-agnosticism (V1/V2 escrow)

This file calls only scheme-agnostic escrow API:

	escrow.ValidateShareFormat  — per-share structural check
	escrow.Reconstruct          — threshold reconstruction
	escrow.ZeroBytes            — elision-proof byte-slice zeroization
	escrow.ZeroArray32          — elision-proof [32]byte zeroization

V1 (current) implements GF(256) Shamir. V2 (reserved) will implement
Pedersen VSS over secp256k1. Both emit 32-byte secrets (AES-256 keys),
and both route through the named functions above. When V2 ships, the
escrow package gains version dispatch internally and this file requires
zero changes.

# Architectural boundary: nonce placement

V1 escrow splits ONLY the 32-byte AES key — the secret portion of
ArtifactKey. The 12-byte AES-GCM nonce is non-secret metadata and lives
domain-side alongside the Key in the ArtifactKeyStore. The nonce does
NOT appear in EscrowPackage and is NOT reconstructed from shares.

The recovery orchestrator (the caller of ExecuteRecovery) is responsible
for retrieving the nonce from the pre-recovery ArtifactKeyStore (or its
backup) and supplying it via ExecuteRecoveryParams.Nonce. This function
combines the reconstructed 32-byte Key with the caller-supplied 12-byte
Nonce to re-form the full ArtifactKey for re-encryption under the new
authority.

# BUG-009 preservation

EvaluateArbitration contains three validation fixes that close a
specific attack where a compromised escrow operator could fabricate
override authorization:

	Fix 1: Witness-cosignature deserialize errors block authorization
	       (do not silently tolerate malformed bytes).
	Fix 2: Witness cosignature is bound to the recovery request position
	       via verifier.IsCosignatureOf (any other cosignature target
	       does not satisfy).
	Fix 3: Witness signer must not be in p.EscrowNodeSet (independence
	       requirement).

A configuration guard requires EscrowNodeSet to be non-empty whenever
the schema declares OverrideRequiresIndependentWitness=true — silently
skipping the independence check when the set is missing was the
pre-fix behavior.

# Destination binding

Every public Params struct that produces an entry carries a Destination
field (the DID of the target exchange). lifecycle validates it via
envelope.ValidateDestination and threads it into every builder.*Params
literal so the canonical hash commits to the destination.

# Error model

ExecuteRecovery returns a hard error only for fail-fast conditions
(invalid destination, no shares, missing nonce, reconstruction failure).
Partial-success states — some artifacts re-encrypted, others failed; or
succession-entry construction failed after successful re-encryption —
are surfaced via RecoveryResult.ArtifactErrors and .SuccessionError
rather than discarding the partial result.

# Five-layer architecture

Recovery ripples through every layer of the Ortholog trust stack:

	Layer 1 (Origin)     — new key signs the Succession Entry (ECDSA/Ed25519)
	Layer 2 (Structural) — log operator appends, SMT AuthorityTip shifts
	Layer 3 (Consensus)  — witnesses cosign the new state (BLS/ECDSA)
	Layer 4 (Federated)  — cross-log proofs bundle SMT + witness cosigs
	Layer 5 (Semantic)   — domain rules (e.g. did:pkh mapping escrow)
	                        validate the real-world identity claim

This file sits at Layers 1-2 of the recovery pathway. Layer 3 is
handled by the witness subsystem; Layers 4-5 are handled by federation
and domain code respectively.

# Consumed by

  - judicial-network/migration/ungraceful.go
    InitiateRecovery → CollectShares → ExecuteRecovery
  - Exchange migration tooling
  - Governance body recovery coordination
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
//
// Sentinel errors for typed callers (errors.Is dispatching). Wrapped
// errors preserve call-site context; unwrapped sentinels are returned
// directly when no additional context is useful.
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrRecoveryNotInitiated is returned when a recovery operation
	// runs before InitiateRecovery has published its request entry.
	ErrRecoveryNotInitiated = fmt.Errorf("lifecycle/recovery: recovery not initiated")

	// ErrInsufficientShares is returned when ExecuteRecovery is called
	// with fewer shares than needed. The escrow package enforces the
	// actual threshold; this sentinel guards the empty-input case.
	ErrInsufficientShares = fmt.Errorf("lifecycle/recovery: insufficient valid shares")

	// ErrShareValidationFailed wraps per-share validation errors
	// surfaced during CollectShares. Individual failure reasons appear
	// in CollectedShares.InvalidReasons.
	ErrShareValidationFailed = fmt.Errorf("lifecycle/recovery: share validation failed")

	// ErrReconstructionFailed wraps errors from escrow.Reconstruct
	// (below-threshold, split-id mismatch, version mismatch, etc.).
	ErrReconstructionFailed = fmt.Errorf("lifecycle/recovery: key reconstruction failed")

	// ErrArbitrationRequired signals that a custody dispute cannot be
	// resolved via cooperative recovery and must go through
	// EvaluateArbitration.
	ErrArbitrationRequired = fmt.Errorf("lifecycle/recovery: custody dispute requires arbitration")

	// ErrInsufficientOverride is returned when an arbitration override
	// falls below the schema-declared supermajority threshold.
	ErrInsufficientOverride = fmt.Errorf("lifecycle/recovery: override requires schema-declared supermajority")

	// ErrMissingWitnessCosig is returned when the schema requires an
	// independent identity witness and no witness cosignature was
	// supplied.
	ErrMissingWitnessCosig = fmt.Errorf("lifecycle/recovery: schema requires independent identity witness cosignature")

	// ErrMissingEscrowNodeSet is returned when
	// OverrideRequiresIndependentWitness=true and EscrowNodeSet is
	// empty. The independence check (BUG-009 fix 3) requires the set
	// to be populated; silently skipping the check was the pre-fix
	// behavior.
	ErrMissingEscrowNodeSet = fmt.Errorf("lifecycle/recovery: OverrideRequiresIndependentWitness requires EscrowNodeSet")

	// ErrMissingNonce is returned when ExecuteRecovery is called with a
	// zero-valued Nonce. Escrow reconstructs only the 32-byte AES key;
	// the AES-GCM nonce lives domain-side in the ArtifactKeyStore and
	// is the caller's responsibility to supply. A zero nonce is almost
	// certainly a caller bug (uninitialized field), not an intentional
	// choice.
	ErrMissingNonce = fmt.Errorf("lifecycle/recovery: ExecuteRecovery requires non-zero Nonce (supplied by caller from ArtifactKeyStore)")

	// ErrInvalidEscrowNodeCount is returned when TotalEscrowNodes is
	// not a positive integer. A zero or negative N makes the threshold
	// undefined.
	ErrInvalidEscrowNodeCount = fmt.Errorf("lifecycle/recovery: TotalEscrowNodes must be positive")
)

// ─────────────────────────────────────────────────────────────────────
// Phase 1: InitiateRecovery
//
// Publishes a commentary entry declaring the intent to recover. Escrow
// nodes watch for this entry and begin releasing shares to the holder's
// new key after their own domain-defined policy checks pass.
// ─────────────────────────────────────────────────────────────────────

// InitiateRecoveryParams configures a recovery request.
type InitiateRecoveryParams struct {
	// Destination is the DID of the target exchange. Required.
	Destination string

	// NewExchangeDID is the DID authorized to execute the recovery —
	// typically the holder's new key or the successor exchange.
	NewExchangeDID string

	// HolderDID identifies the subject of recovery. May equal
	// NewExchangeDID in the individual-key-rotation case, or differ
	// in the institutional-succession case.
	HolderDID string

	// Reason is a free-text human-readable description (e.g.
	// "lost YubiKey", "compromised wallet", "staff transition").
	Reason string

	// EscrowPackageCID locates the holder's escrow package in the
	// content-addressed store. The package carries the M-of-N
	// configuration and the per-node ECIES-wrapped shares.
	EscrowPackageCID storage.CID

	// EventTime is the microsecond-precision timestamp. Zero means
	// "use current time".
	EventTime int64
}

// InitiateRecoveryResult holds the recovery request entry.
type InitiateRecoveryResult struct {
	// RequestEntry is the built, unsigned commentary entry. The caller
	// is responsible for signing and submitting it to the log.
	RequestEntry *envelope.Entry

	// RequestPayload is the decoded payload carried inside
	// RequestEntry. Provided so callers can log or audit without
	// re-parsing the entry.
	RequestPayload map[string]any
}

// InitiateRecovery builds the recovery request commentary entry.
//
// The caller is responsible for signing and submitting the returned
// entry. This function does not sign — the signer DID may not be
// reachable at construction time (e.g. air-gapped recovery).
func InitiateRecovery(p InitiateRecoveryParams) (*InitiateRecoveryResult, error) {
	if err := envelope.ValidateDestination(p.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: %w", err)
	}
	if p.NewExchangeDID == "" {
		return nil, fmt.Errorf("lifecycle/recovery: empty new exchange DID")
	}
	if p.HolderDID == "" {
		return nil, fmt.Errorf("lifecycle/recovery: empty holder DID")
	}

	eventTime := p.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	payload := map[string]any{
		"recovery_type":      "escrow_key_recovery",
		"holder_did":         p.HolderDID,
		"reason":             p.Reason,
		"escrow_package_cid": p.EscrowPackageCID.String(),
	}

	entry, err := builder.BuildRecoveryRequest(builder.RecoveryRequestParams{
		Destination: p.Destination,
		SignerDID:   p.NewExchangeDID,
		Payload:     mustMarshalJSON(payload),
		EventTime:   eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: build request: %w", err)
	}

	return &InitiateRecoveryResult{
		RequestEntry:   entry,
		RequestPayload: payload,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Phase 2: CollectShares
//
// Validates individual shares as they arrive from escrow nodes. This is
// the pre-reconstruction gate — shares that fail here are surfaced to
// the caller with a specific reason, and valid shares are accumulated
// toward the reconstruction threshold.
// ─────────────────────────────────────────────────────────────────────

// CollectSharesParams configures share collection.
type CollectSharesParams struct {
	// EscrowPackageCID locates the holder's escrow package. Held for
	// audit and cross-reference; not required for validation.
	EscrowPackageCID storage.CID

	// ContentStore provides access to the escrow package if deeper
	// validation is needed. Not used by this function directly; held
	// for symmetry with InitiateRecoveryParams.
	ContentStore storage.ContentStore

	// DecryptedShares are the plaintext shares, already unwrapped from
	// their per-node ECIES envelopes by the caller. The caller holds
	// the node-private-keys; this function does not.
	DecryptedShares []escrow.Share

	// RequiredThreshold is M — the minimum valid shares needed to
	// reconstruct. Typically taken from the escrow package metadata.
	// CollectShares reports SufficientForRecovery against this value
	// as an early-warning signal; the escrow package also enforces
	// threshold at Reconstruct time.
	RequiredThreshold int
}

// CollectedShares holds the validated shares ready for reconstruction.
type CollectedShares struct {
	// ValidShares are the shares that passed structural validation and
	// duplicate-index detection. Ordered by arrival (stable).
	ValidShares []escrow.Share

	// InvalidCount is len(DecryptedShares) - len(ValidShares).
	InvalidCount int

	// InvalidReasons maps the input index of each rejected share to a
	// human-readable failure reason. Useful for operator dashboards
	// and post-mortem analysis.
	InvalidReasons map[int]string

	// SufficientForRecovery is true when len(ValidShares) >= Threshold.
	// This is an early-warning signal, not a substitute for the
	// threshold enforcement inside escrow.Reconstruct.
	SufficientForRecovery bool

	// Threshold mirrors CollectSharesParams.RequiredThreshold for
	// convenience.
	Threshold int
}

// CollectShares validates individual shares as they arrive from escrow
// nodes and reports which ones are eligible for reconstruction.
//
// Per-share validation delegates to escrow.ValidateShareFormat, which
// is scheme-agnostic: under V1 it enforces GF(256) Shamir invariants;
// under V2 (when it ships) it will additionally verify Pedersen
// commitments.
//
// Duplicate-index detection happens at this layer because the caller's
// view spans multiple nodes (each of which might return the same index
// through misconfiguration or replay). The escrow package's own
// duplicate detection runs at Reconstruct time; early detection here
// gives a clearer error surface.
//
// This function never returns a hard error — invalid shares are
// surfaced via InvalidReasons. A caller that receives
// SufficientForRecovery=false from this function should continue
// collecting; a caller that receives SufficientForRecovery=true may
// proceed to ExecuteRecovery.
func CollectShares(p CollectSharesParams) (*CollectedShares, error) {
	result := &CollectedShares{
		InvalidReasons: make(map[int]string),
		Threshold:      p.RequiredThreshold,
	}

	seen := make(map[byte]bool, len(p.DecryptedShares))
	for i, share := range p.DecryptedShares {
		if err := escrow.ValidateShareFormat(share); err != nil {
			result.InvalidCount++
			result.InvalidReasons[i] = err.Error()
			continue
		}

		if seen[share.Index] {
			result.InvalidCount++
			result.InvalidReasons[i] = fmt.Sprintf("duplicate share index %d", share.Index)
			continue
		}
		seen[share.Index] = true
		result.ValidShares = append(result.ValidShares, share)
	}

	result.SufficientForRecovery = len(result.ValidShares) >= result.Threshold
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Phase 3: ExecuteRecovery
//
// Reconstructs the holder's AES-256 key from the collected shares,
// combines it with the caller-supplied AES-GCM nonce, and re-encrypts
// the holder's artifacts under fresh per-artifact keys. Optionally
// publishes a Succession Entry binding the recovery to the new
// authority.
// ─────────────────────────────────────────────────────────────────────

// ExecuteRecoveryParams configures key reconstruction and re-encryption.
type ExecuteRecoveryParams struct {
	// Destination is the DID of the target exchange. Required.
	Destination string

	// Shares are the M-of-N escrow shares, already decrypted from
	// their per-node ECIES envelopes. Must meet the threshold declared
	// in Shares[0].Threshold; escrow.Reconstruct enforces this and
	// returns ErrBelowThreshold otherwise.
	Shares []escrow.Share

	// Nonce is the AES-GCM nonce for the artifacts being recovered.
	//
	// Escrow splits ONLY the 32-byte AES key. The 12-byte AES-GCM
	// nonce is non-secret metadata and lives domain-side in the
	// ArtifactKeyStore. The caller retrieves the nonce from the
	// pre-recovery ArtifactKeyStore (or its backup) and passes it
	// here. ExecuteRecovery combines the reconstructed Key with
	// this Nonce to re-form the full ArtifactKey.
	//
	// A zero-valued Nonce is rejected with ErrMissingNonce — a zero
	// IV is almost certainly an uninitialized caller field rather
	// than an intentional choice.
	Nonce [12]byte

	// ArtifactCIDs are the content-addressed IDs of the artifacts to
	// re-encrypt. Each is re-encrypted under a fresh key derived by
	// ReEncryptWithGrant; the mapping from old CID to new CID is
	// returned in RecoveryResult.ReEncryptedArtifacts.
	ArtifactCIDs []storage.CID

	// ContentStore provides read/write access to artifact ciphertext.
	ContentStore storage.ContentStore

	// KeyStore is the destination for re-encrypted artifact keys. May
	// be nil if the caller does not want ExecuteRecovery to persist
	// new keys (e.g. in a dry-run). When non-nil, each successfully
	// re-encrypted artifact's new key is stored before the CID
	// mapping is added to the result.
	KeyStore ArtifactKeyStore

	// NewExchangeDID is the signer of the Succession Entry. When
	// empty, no Succession Entry is built and SuccessionEntry in the
	// result is nil.
	NewExchangeDID string

	// TargetRoot is the log position anchoring the succession. When
	// nil, no Succession Entry is built.
	TargetRoot *types.LogPosition

	// EventTime is the microsecond-precision timestamp for the
	// Succession Entry. Zero means "use current time". Ignored when
	// no Succession Entry is built.
	EventTime int64
}

// RecoveryResult holds the outcome of key reconstruction and
// re-encryption.
//
// Partial-success semantics: if some artifacts fail to re-encrypt, the
// successful ones appear in ReEncryptedArtifacts and the failures
// appear in ArtifactErrors. If succession-entry construction fails
// after successful re-encryption, SuccessionEntry is nil and
// SuccessionError is non-nil.
//
// The reconstructed key material is NOT exposed on this struct — it is
// zeroized before ExecuteRecovery returns. Callers with a legitimate
// need for the raw material should derive it themselves from their
// own share management code.
type RecoveryResult struct {
	// ReEncryptedArtifacts maps original CID → new CID for artifacts
	// that were successfully re-encrypted under the recovered key.
	ReEncryptedArtifacts map[string]storage.CID

	// ArtifactErrors maps original CID → error for artifacts that
	// failed to re-encrypt. A non-empty ArtifactErrors alongside a
	// non-empty ReEncryptedArtifacts indicates partial success.
	ArtifactErrors map[string]error

	// SuccessionEntry is the built, unsigned Succession Entry. Nil
	// when no succession was requested (TargetRoot==nil or
	// NewExchangeDID=="") or when succession construction failed
	// (in which case SuccessionError is non-nil).
	SuccessionEntry *envelope.Entry

	// SuccessionError records the error, if any, from attempting to
	// build the Succession Entry. Non-nil SuccessionError with
	// non-empty ReEncryptedArtifacts indicates a re-encryption
	// success followed by a succession-construction failure.
	SuccessionError error
}

// ExecuteRecovery reconstructs the holder's AES-256 key from the
// collected escrow shares, combines it with the caller-supplied
// AES-GCM nonce, re-encrypts the listed artifacts under fresh keys,
// and (optionally) builds a Succession Entry.
//
// # Scheme-agnosticism
//
// escrow.Reconstruct dispatches internally on the share Version byte.
// Under V1 it performs GF(256) Lagrange interpolation; under V2 (when
// reserved) it will perform Pedersen VSS reconstruction. Both schemes
// return a 32-byte secret (AES-256 key), so this function's contract
// is identical across schemes.
//
// # Nonce architecture
//
// The caller supplies the AES-GCM nonce via p.Nonce. See the doc
// comment on ExecuteRecoveryParams.Nonce for the full boundary
// argument. A zero-valued Nonce is rejected with ErrMissingNonce.
//
// # Zeroization
//
// The reconstructed key bytes and the assembled ArtifactKey fields are
// zeroized via escrow.ZeroBytes and escrow.ZeroArray32 before return.
// These primitives are elision-proof: they use //go:noinline and
// runtime.KeepAlive to prevent the Go compiler from optimizing away
// zero-writes to memory that appears unused.
//
// # Error model
//
// Returns a hard error (and nil result) only for fail-fast conditions:
// invalid destination, empty share set, missing nonce, reconstruction
// failure, or reconstructed-size mismatch. Partial-success states
// (some artifacts failed to re-encrypt; succession failed after
// re-encryption) are reported inside the returned RecoveryResult.
func ExecuteRecovery(p ExecuteRecoveryParams) (*RecoveryResult, error) {
	if err := envelope.ValidateDestination(p.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: %w", err)
	}
	if len(p.Shares) == 0 {
		return nil, ErrInsufficientShares
	}
	if p.Nonce == ([12]byte{}) {
		return nil, ErrMissingNonce
	}

	// Reconstruct the AES key from shares. escrow.Reconstruct enforces
	// threshold, SplitID binding, version consistency, and per-share
	// structural validity internally. Under V1 this is GF(256) Shamir;
	// under V2 it will be Pedersen VSS — same contract, same return
	// size.
	keyBytes, err := escrow.Reconstruct(p.Shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReconstructionFailed, err)
	}

	// Defensive: Reconstruct is contracted to return exactly
	// artifact.KeySize (32) bytes. Assert the invariant rather than
	// trust it silently — a future bug here would flow a wrong-sized
	// key into AES-GCM and surface as a confusing encryption error
	// far from the root cause.
	if len(keyBytes) != artifact.KeySize {
		escrow.ZeroBytes(keyBytes)
		return nil, fmt.Errorf("%w: reconstructed %d bytes, expected %d",
			ErrReconstructionFailed, len(keyBytes), artifact.KeySize)
	}

	// Zeroize the reconstructed key bytes when we return. Registered
	// before any other work so we can't leak through an early return.
	defer escrow.ZeroBytes(keyBytes)

	// Assemble the ArtifactKey from reconstructed key + caller-supplied
	// nonce. Zeroize both fields on return.
	var oldKey artifact.ArtifactKey
	copy(oldKey.Key[:], keyBytes)
	oldKey.Nonce = p.Nonce
	defer escrow.ZeroArray32(&oldKey.Key)
	defer escrow.ZeroBytes(oldKey.Nonce[:])

	result := &RecoveryResult{
		ReEncryptedArtifacts: make(map[string]storage.CID, len(p.ArtifactCIDs)),
		ArtifactErrors:       make(map[string]error),
	}

	// Re-encrypt each artifact. Per-artifact failures are recorded
	// in result.ArtifactErrors rather than aborting the whole loop —
	// a caller retrying against a large set wants to know which
	// artifacts succeeded so they can focus retries on failures.
	for _, oldCID := range p.ArtifactCIDs {
		cidStr := oldCID.String()

		reResult, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
			OldCID:              oldCID,
			KeyStore:            &recoveryKeyAdapter{key: oldKey, targetCID: oldCID},
			ContentStore:        p.ContentStore,
			DeleteOldCiphertext: false,
		})
		if err != nil {
			result.ArtifactErrors[cidStr] = fmt.Errorf("re-encrypt: %w", err)
			continue
		}

		if p.KeyStore != nil {
			if err := p.KeyStore.Store(reResult.NewCID, reResult.NewKey); err != nil {
				result.ArtifactErrors[cidStr] = fmt.Errorf("store new key: %w", err)
				continue
			}
		}

		result.ReEncryptedArtifacts[cidStr] = reResult.NewCID
	}

	// Optional Succession Entry. Built only when both TargetRoot and
	// NewExchangeDID are provided — either alone is insufficient.
	// Failures here do not invalidate the re-encryption results.
	if p.TargetRoot != nil && p.NewExchangeDID != "" {
		eventTime := p.EventTime
		if eventTime == 0 {
			eventTime = time.Now().UTC().UnixMicro()
		}

		succEntry, err := builder.BuildSuccession(builder.SuccessionParams{
			Destination:  p.Destination,
			SignerDID:    p.NewExchangeDID,
			TargetRoot:   *p.TargetRoot,
			NewSignerDID: p.NewExchangeDID,
			Payload: mustMarshalJSON(map[string]any{
				"succession_type":       "escrow_recovery",
				"artifacts_reencrypted": len(result.ReEncryptedArtifacts),
				"artifacts_failed":      len(result.ArtifactErrors),
			}),
			EventTime: eventTime,
		})
		if err != nil {
			result.SuccessionError = fmt.Errorf("lifecycle/recovery: build succession: %w", err)
		} else {
			result.SuccessionEntry = succEntry
		}
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Custody Dispute Arbitration (EvaluateArbitration)
//
// When cooperative recovery fails — escrow nodes refuse to release
// shares, or the holder's keys are stolen and an incumbent exchange
// contests the recovery — the AuthoritySet can authorize an override.
// This path DOES NOT require escrow cooperation. It requires:
//
//   1. A schema-declared supermajority of escrow-node cosignatures
//      on the RecoveryRequest (typically ⌈2N/3⌉).
//   2. (Optional, schema-dependent) An independent-witness
//      cosignature: a DID not in the escrow-node set, cosigning the
//      RecoveryRequest position.
//
// EvaluateArbitration validates both conditions and reports whether
// OverrideAuthorized can proceed.
// ─────────────────────────────────────────────────────────────────────

// ArbitrationParams configures an escrow arbitration override.
type ArbitrationParams struct {
	// RecoveryRequestPos is the log position of the InitiateRecovery
	// entry. Escrow approvals and the witness cosignature must all
	// reference this position (BUG-009 binding requirement).
	RecoveryRequestPos types.LogPosition

	// EscrowApprovals are cosignature entries from escrow nodes
	// approving the override. Typically discovered via
	// QueryByCosignatureOf on the RecoveryRequest entry.
	//
	// The count of UNIQUE signers among these approvals is what's
	// checked against the supermajority threshold. Multiple
	// cosignatures from the same signer do not multiply.
	EscrowApprovals []types.EntryWithMetadata

	// TotalEscrowNodes is N — the total number of escrow nodes for
	// this holder. Defines the denominator for supermajority
	// calculation.
	TotalEscrowNodes int

	// EscrowNodeSet is the set of escrow-node DIDs for this holder.
	// Required when SchemaParams.OverrideRequiresIndependentWitness
	// is true; EvaluateArbitration returns ErrMissingEscrowNodeSet
	// if the field is empty in that configuration.
	//
	// Used for BUG-009 fix 3: the witness cosigner's DID must NOT
	// appear in this set.
	EscrowNodeSet map[string]bool

	// WitnessCosignature is the independent-identity-witness
	// cosignature, required when SchemaParams.OverrideRequiresIndependentWitness
	// is true. Must reference RecoveryRequestPos (BUG-009 fix 2) and
	// must be signed by a DID outside EscrowNodeSet (fix 3).
	WitnessCosignature *types.EntryWithMetadata

	// SchemaParams provides the override policy. Nil means defaults:
	// two-thirds threshold, no witness requirement.
	SchemaParams *types.SchemaParameters
}

// ArbitrationResult holds the outcome of arbitration evaluation.
type ArbitrationResult struct {
	// OverrideAuthorized is true when all policy checks pass.
	OverrideAuthorized bool

	// ApprovalCount is the number of UNIQUE escrow-node signers that
	// cosigned the recovery request.
	ApprovalCount int

	// RequiredCount is the schema-declared minimum unique approvals.
	RequiredCount int

	// HasWitnessCosig is true when a valid, independent, bound
	// witness cosignature was supplied. False when either no witness
	// was required, or a witness was required but failed validation.
	HasWitnessCosig bool

	// Reason is a human-readable explanation of the decision,
	// including the threshold math and the specific failure mode
	// when OverrideAuthorized is false.
	Reason string
}

// EvaluateArbitration checks whether an escrow arbitration override has
// sufficient approvals and (when required) a valid independent witness
// cosignature bound to the specific recovery request.
//
// # BUG-009 FIXES (preserved)
//
// Three distinct validation holes are closed here. An override is
// authorized only when all three gates pass:
//
//	Gate 1: Witness-cosignature deserialize errors are fatal. A
//	        malformed witness does not silently pass as "no witness
//	        available, fall through" (which was the pre-fix behavior).
//	Gate 2: Witness cosignature must reference p.RecoveryRequestPos
//	        via verifier.IsCosignatureOf. Any other cosignature
//	        target fails this gate.
//	Gate 3: Witness signer must not appear in p.EscrowNodeSet. A
//	        witness that is itself an escrow node violates the
//	        independence requirement.
//
// # Configuration guard
//
// When the schema declares OverrideRequiresIndependentWitness=true,
// EscrowNodeSet must be non-empty. An empty set would silently skip
// Gate 3; we fail fast with ErrMissingEscrowNodeSet rather than allow
// silent degradation.
//
// # Loop style
//
// The EscrowApprovals loop uses verifier.IsCosignatureOf for
// SDK-wide consistency. This loop was already binding correctly
// pre-fix; the style alignment does not change behavior.
func EvaluateArbitration(p ArbitrationParams) (*ArbitrationResult, error) {
	if p.TotalEscrowNodes <= 0 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidEscrowNodeCount, p.TotalEscrowNodes)
	}

	// Resolve schema-declared override policy. A nil SchemaParams
	// means "defaults" — zero-value OverrideThresholdRule (two-thirds)
	// and no witness requirement.
	var threshold types.OverrideThresholdRule
	requiresWitness := false
	if p.SchemaParams != nil {
		threshold = p.SchemaParams.OverrideThreshold
		requiresWitness = p.SchemaParams.OverrideRequiresIndependentWitness
	}
	required := threshold.RequiredApprovals(p.TotalEscrowNodes)

	// Configuration sanity: witness requirement demands an escrow node
	// set for the independence check. Fail fast rather than silently
	// skipping.
	if requiresWitness && len(p.EscrowNodeSet) == 0 {
		return nil, ErrMissingEscrowNodeSet
	}

	// Count UNIQUE escrow-node approvals. Each approval must cosign
	// the exact RecoveryRequest position — an approval cosigning some
	// other entry does not count.
	seen := make(map[string]bool, len(p.EscrowApprovals))
	for _, meta := range p.EscrowApprovals {
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		if !verifier.IsCosignatureOf(entry, p.RecoveryRequestPos) {
			continue
		}
		if seen[entry.Header.SignerDID] {
			continue
		}
		seen[entry.Header.SignerDID] = true
	}
	approvalCount := len(seen)

	result := &ArbitrationResult{
		ApprovalCount: approvalCount,
		RequiredCount: required,
	}

	if approvalCount < required {
		result.Reason = fmt.Sprintf(
			"%d of %d escrow approvals (threshold %s requires %d)",
			approvalCount, p.TotalEscrowNodes, threshold.String(), required,
		)
		return result, nil
	}

	// Witness-cosignature gate. All three BUG-009 fixes run inside
	// this block; each establishes an invariant that must hold before
	// OverrideAuthorized can flip true.
	if requiresWitness {
		if p.WitnessCosignature == nil {
			result.Reason = "supermajority met but independent witness cosignature required"
			return result, nil
		}

		// Gate 1: deserialize errors are fatal.
		witnessEntry, err := envelope.Deserialize(p.WitnessCosignature.CanonicalBytes)
		if err != nil {
			result.Reason = fmt.Sprintf("witness cosignature deserialize failed: %v", err)
			return result, nil
		}

		// Gate 2: witness cosig must reference the recovery request.
		if !verifier.IsCosignatureOf(witnessEntry, p.RecoveryRequestPos) {
			result.Reason = "witness cosignature does not reference recovery request position"
			return result, nil
		}

		// Gate 3: witness must be independent of escrow.
		if p.EscrowNodeSet[witnessEntry.Header.SignerDID] {
			result.Reason = fmt.Sprintf(
				"witness %s is an escrow node; independence requirement violated",
				witnessEntry.Header.SignerDID,
			)
			return result, nil
		}

		result.HasWitnessCosig = true
	}

	result.OverrideAuthorized = true
	result.Reason = fmt.Sprintf(
		"override authorized: %d of %d escrow approvals (threshold %s requires %d)",
		approvalCount, p.TotalEscrowNodes, threshold.String(), required,
	)
	if requiresWitness {
		result.Reason += " + independent witness cosignature"
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal: recoveryKeyAdapter
//
// Adapts a single ArtifactKey to the ArtifactKeyStore interface so
// ReEncryptWithGrant can read it via its normal KeyStore.Get path.
// Only the Get method is functional; Store and Delete are no-ops
// because ReEncryptWithGrant does not write to the adapter.
//
// The caller's real KeyStore (p.KeyStore in ExecuteRecoveryParams) is
// the actual write destination for re-encrypted keys.
// ─────────────────────────────────────────────────────────────────────

type recoveryKeyAdapter struct {
	key       artifact.ArtifactKey
	targetCID storage.CID
}

// Get returns the wrapped key when the requested CID matches
// targetCID; otherwise returns (nil, nil). ReEncryptWithGrant treats
// the nil-key case as "key not found" and surfaces an error to the
// caller, which is the behavior we want if anything ever asks for a
// CID other than the one this adapter was instantiated with.
func (a *recoveryKeyAdapter) Get(cid storage.CID) (*artifact.ArtifactKey, error) {
	if cid.Equal(a.targetCID) {
		k := a.key
		return &k, nil
	}
	return nil, nil
}

// Store is a no-op. ReEncryptWithGrant does not write to the adapter;
// the caller's KeyStore receives new keys via
// ExecuteRecovery's own Store call.
func (a *recoveryKeyAdapter) Store(_ storage.CID, _ artifact.ArtifactKey) error {
	return nil
}

// Delete is a no-op for the same reason Store is.
func (a *recoveryKeyAdapter) Delete(_ storage.CID) error {
	return nil
}
