/*
Package lifecycle — recovery.go implements identity-key recovery for the
Ortholog protocol. Used when a holder loses their hardware token,
discovers key compromise, or needs to migrate to a new credentialing
authority.

# Scope: what escrow recovers

Escrow recovers the 32-byte MASTER IDENTITY KEY. Not an artifact-
encryption key, not a delegation key. The master identity key is the
private key behind the holder's DID — the key they use to sign entries,
authorize successions, and unwrap any identity-scoped secrets stored
for them elsewhere.

The M-of-N escrow pathway exists because losing a hardware token means
losing the ability to authenticate to the network. Without authority
to authenticate, the holder cannot sign a Succession Entry; without a
Succession Entry, no other party can bind their authority to a new key.
Cryptographic escrow is the mechanism that gets the holder back into
the system.

# Scope: what escrow does NOT recover

Escrow does not touch artifacts. Three consequences flow from this:

 1. ExecuteRecovery takes no ContentStore, no ArtifactKeyStore, no
    ArtifactCIDs. Those belong to the domain application's access-
    control plane, not to identity recovery.

 2. ExecuteRecovery takes no AES-GCM nonce. Nonces live domain-side
    in the ArtifactKeyStore alongside the artifact-encryption keys
    they apply to. After identity recovery, the holder uses their
    recovered master key to authenticate to the domain and retrieve
    artifact keys and nonces through normal domain channels.

 3. Re-encrypting artifacts (if required) is a SEPARATE operation the
    domain orchestrates after identity recovery, by looping over its
    own artifact CIDs and calling lifecycle.ReEncryptWithGrant per
    artifact. ExecuteRecovery does not know or care about this loop.

# Three phases

	InitiateRecovery → builds the recovery-request commentary entry
	CollectShares    → validates M-of-N shares as they arrive
	ExecuteRecovery  → reconstructs the 32-byte master identity key,
	                   optionally builds a Succession Entry

# Arbitration pathway

EvaluateArbitration handles the case where escrow nodes refuse to
cooperate or the holder's key is stolen. A schema-declared supermajority
of escrow-node cosignatures on the recovery request (typically ⌈2N/3⌉)
plus an optional independent-identity-witness cosignature authorizes
the override without escrow cooperation. All three BUG-009 validation
fixes are preserved in this file; see EvaluateArbitration for details.

# Scheme-agnosticism (V1/V2 escrow)

This file calls only scheme-agnostic escrow API:

	escrow.ValidateShareFormat — per-share structural check
	escrow.Reconstruct         — threshold reconstruction
	escrow.ZeroBytes           — elision-proof slice zeroization
	escrow.ZeroArray32         — elision-proof [32]byte zeroization

V1 (current) uses GF(256) Shamir. V2 (reserved) will use Pedersen VSS
over secp256k1. Both return a 32-byte secret and route through the
named functions above. When V2 ships, the escrow package gains version
dispatch internally and this file requires zero changes.

# Destination binding

InitiateRecovery and ExecuteRecovery both produce entries (a recovery
request and an optional Succession Entry). Both validate Destination
via envelope.ValidateDestination and thread it into every builder.*
Params literal, so the canonical hash commits to the destination and
cross-exchange replay is cryptographically impossible.

# Consumed by

  - judicial-network/migration/ungraceful.go — orchestrates full recovery
  - Exchange migration tooling
  - Governance body recovery coordination
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
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
	// with an empty share set. The escrow package enforces the actual
	// threshold; this sentinel guards the empty-input case that
	// escrow.Reconstruct would otherwise surface as a threshold error.
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
	// falls below the schema-declared supermajority threshold. Defined
	// for typed errors.Is dispatching by arbitration callers.
	ErrInsufficientOverride = fmt.Errorf("lifecycle/recovery: override requires schema-declared supermajority")

	// ErrMissingWitnessCosig is returned when the schema requires an
	// independent identity witness and no witness cosignature was
	// supplied. Defined for typed errors.Is dispatching.
	ErrMissingWitnessCosig = fmt.Errorf("lifecycle/recovery: schema requires independent identity witness cosignature")

	// ErrMissingEscrowNodeSet is returned when
	// OverrideRequiresIndependentWitness=true and EscrowNodeSet is
	// empty. The independence check (BUG-009 fix 3) requires the set
	// to be populated; silently skipping it was the pre-fix behavior.
	ErrMissingEscrowNodeSet = fmt.Errorf("lifecycle/recovery: OverrideRequiresIndependentWitness requires EscrowNodeSet")

	// ErrInvalidEscrowNodeCount is returned when TotalEscrowNodes is
	// zero or negative. A non-positive N makes the threshold
	// undefined.
	ErrInvalidEscrowNodeCount = fmt.Errorf("lifecycle/recovery: TotalEscrowNodes must be positive")

	// ErrReconstructedSizeMismatch is returned when escrow.Reconstruct
	// returns a secret whose size is not escrow.SecretSize. Defensive
	// invariant — escrow.Reconstruct is contracted to return exactly
	// 32 bytes, but asserting surfaces any future contract violation
	// at the lifecycle boundary rather than far downstream.
	ErrReconstructedSizeMismatch = fmt.Errorf("lifecycle/recovery: reconstructed secret size mismatch")
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
	// Destination is the DID of the target exchange (the log the
	// recovery request is being published to). Required. Validated by
	// envelope.ValidateDestination.
	Destination string

	// NewExchangeDID is the DID authorized to execute the recovery —
	// typically the holder's new key or the successor exchange.
	NewExchangeDID string

	// HolderDID identifies the subject of recovery. May equal
	// NewExchangeDID in the individual-key-rotation case, or differ
	// in the institutional-succession case.
	HolderDID string

	// Reason is free-text, human-readable, e.g. "lost YubiKey",
	// "compromised wallet", "staff transition". Recorded in the
	// request payload for audit.
	Reason string

	// EscrowPackageCID locates the holder's escrow package in the
	// content-addressed store. The package carries the M-of-N
	// configuration and per-node ECIES-wrapped shares.
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
	// RequestEntry, provided so callers can log or audit without
	// re-parsing the entry.
	RequestPayload map[string]any
}

// InitiateRecovery builds the recovery-request commentary entry.
//
// The caller signs and submits the returned entry. This function does
// not sign — the signer key may not be reachable at construction time
// (e.g. air-gapped recovery, HSM coordination delay).
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
// the caller with a specific reason; valid shares accumulate toward the
// reconstruction threshold.
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
	// their per-node ECIES envelopes by the caller (who holds the
	// node-private-keys). This function does not decrypt.
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

	// InvalidCount is len(DecryptedShares) − len(ValidShares).
	InvalidCount int

	// InvalidReasons maps the input index of each rejected share to a
	// human-readable failure reason. Useful for operator dashboards
	// and post-mortem analysis.
	InvalidReasons map[int]string

	// SufficientForRecovery is true when len(ValidShares) >= Threshold.
	// Early-warning signal, not a substitute for the threshold check
	// inside escrow.Reconstruct.
	SufficientForRecovery bool

	// Threshold mirrors CollectSharesParams.RequiredThreshold for
	// convenience.
	Threshold int
}

// CollectShares validates individual shares as they arrive from escrow
// nodes and reports which are eligible for reconstruction.
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
// surfaced via InvalidReasons. A caller receiving
// SufficientForRecovery=false should continue collecting; a caller
// receiving SufficientForRecovery=true may proceed to ExecuteRecovery.
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
// Reconstructs the holder's 32-byte Master Identity Key from the
// collected escrow shares. Optionally builds a Succession Entry binding
// the recovery to a new authority. Does NOT touch artifacts — artifact
// re-encryption, if needed, is the domain layer's responsibility via
// ReEncryptWithGrant (see artifact_access.go).
// ─────────────────────────────────────────────────────────────────────

// ExecuteRecoveryParams configures key reconstruction.
//
// The parameter set is deliberately minimal: this function is the
// identity-key reconstruction primitive, not an artifact orchestrator.
// Artifact-layer concerns (ContentStore, ArtifactKeyStore, nonces,
// artifact CIDs) are domain-layer responsibilities that live OUTSIDE
// the SDK identity boundary.
type ExecuteRecoveryParams struct {
	// Destination is the DID of the target exchange — the log the
	// Succession Entry will be published to, if one is built.
	// Required. Validated by envelope.ValidateDestination even when
	// no succession is requested (catches misconfiguration early).
	Destination string

	// Shares are the M-of-N escrow shares, already decrypted from
	// their per-node ECIES envelopes. Must meet the threshold declared
	// in Shares[0].Threshold; escrow.Reconstruct enforces this and
	// returns a wrapped ErrReconstructionFailed otherwise.
	Shares []escrow.Share

	// NewExchangeDID is the signer of the Succession Entry. Empty
	// means "do not build a Succession Entry".
	NewExchangeDID string

	// TargetRoot is the log position anchoring the succession. Nil
	// means "do not build a Succession Entry".
	TargetRoot *types.LogPosition

	// EventTime is the microsecond-precision timestamp for the
	// Succession Entry. Zero means "use current time". Ignored when
	// no Succession Entry is built.
	EventTime int64
}

// RecoveryResult holds the reconstructed Master Identity Key and any
// optional Succession Entry.
//
// # Secret handling
//
// MasterKey holds raw private-key material. Callers MUST zeroize the
// field when done — either by calling Zeroize() or by passing &MasterKey
// to escrow.ZeroArray32. Any copy of RecoveryResult (value assignment,
// JSON marshaling, logging) propagates the secret. Treat this type as
// ephemeral and short-lived.
//
// The idiomatic usage is:
//
//	result, err := lifecycle.ExecuteRecovery(params)
//	if err != nil {
//	    return err
//	}
//	defer result.Zeroize()
//	// use result.MasterKey to sign the Succession Entry, unwrap
//	// delegation-key wrappers, authenticate to the domain, etc.
//
// # Partial-success semantics
//
// Reconstruction itself is all-or-nothing. Succession-entry construction
// is separate: if it was requested (NewExchangeDID and TargetRoot both
// set) and failed, SuccessionEntry is nil and SuccessionError is
// non-nil. In that case, MasterKey is still valid — the caller can
// retry succession without re-running escrow.
type RecoveryResult struct {
	// MasterKey is the reconstructed 32-byte Master Identity Key.
	// Callers MUST zeroize via Zeroize() after use. See the struct
	// doc comment for the idiomatic pattern.
	MasterKey [32]byte

	// SuccessionEntry is the built, unsigned Succession Entry when
	// succession was requested and succeeded. Nil in every other case
	// (not requested, or construction failed — check SuccessionError).
	SuccessionEntry *envelope.Entry

	// SuccessionError records the error from attempting to build the
	// Succession Entry, when one was requested. Nil when succession
	// was not requested or when it succeeded.
	SuccessionError error
}

// Zeroize clears MasterKey using the elision-proof escrow primitive.
// Safe to call on a nil *RecoveryResult (no-op) and safe to call
// multiple times (idempotent). Callers should defer Zeroize immediately
// after a successful ExecuteRecovery return.
func (r *RecoveryResult) Zeroize() {
	if r == nil {
		return
	}
	escrow.ZeroArray32(&r.MasterKey)
}

// ExecuteRecovery reconstructs the holder's 32-byte Master Identity Key
// from the collected escrow shares, and (optionally) builds a
// Succession Entry binding the new authority.
//
// # Scheme-agnosticism
//
// escrow.Reconstruct dispatches internally on the share Version byte.
// Under V1 it performs GF(256) Lagrange interpolation; under V2 (when
// reserved) it will perform Pedersen VSS reconstruction. Both return
// a 32-byte secret, so this function's contract is identical across
// schemes.
//
// # Scope boundary
//
// This function recovers the Master Identity Key — the private key
// behind the holder's DID. It does NOT recover artifact-encryption
// keys, does NOT take a ContentStore or ArtifactKeyStore, and does
// NOT re-encrypt artifacts. Artifact re-encryption (if required) is
// orchestrated by the domain layer AFTER this function returns, by
// looping over its own artifact CIDs and calling ReEncryptWithGrant
// per artifact.
//
// # Error model
//
// Returns a hard error (and nil result) only for fail-fast conditions:
// invalid destination, empty share set, or reconstruction failure
// (including size-mismatch defensive check). Succession-entry failures
// after successful reconstruction are surfaced inside the returned
// RecoveryResult via SuccessionError — the caller keeps the MasterKey
// and can retry succession without re-running the M-of-N math.
//
// # Zeroization contract
//
// On success, the caller owns the returned MasterKey and MUST zeroize
// it after use (see RecoveryResult.Zeroize). This function zeroizes
// all intermediate buffers internally.
func ExecuteRecovery(p ExecuteRecoveryParams) (*RecoveryResult, error) {
	if err := envelope.ValidateDestination(p.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: %w", err)
	}
	if len(p.Shares) == 0 {
		return nil, ErrInsufficientShares
	}

	// Reconstruct the master identity key from shares.
	// escrow.Reconstruct enforces threshold, SplitID binding, version
	// consistency, and per-share structural validity internally.
	keyBytes, err := escrow.Reconstruct(p.Shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReconstructionFailed, err)
	}

	// Zeroize the intermediate slice no matter how we return. Must be
	// registered before any code path that can return with keyBytes
	// still populated.
	defer escrow.ZeroBytes(keyBytes)

	// Defensive invariant: escrow.Reconstruct is contracted to return
	// exactly escrow.SecretSize (32) bytes. Asserting surfaces any
	// future contract violation at the lifecycle boundary rather than
	// far downstream as a confusing cryptographic failure.
	if len(keyBytes) != escrow.SecretSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d",
			ErrReconstructedSizeMismatch, len(keyBytes), escrow.SecretSize)
	}

	result := &RecoveryResult{}
	copy(result.MasterKey[:], keyBytes)

	// Optional Succession Entry. Built only when both NewExchangeDID
	// and TargetRoot are provided — either alone is insufficient.
	// Failure here does NOT invalidate result.MasterKey; the caller
	// can retry succession without re-running the M-of-N math.
	if p.TargetRoot != nil && p.NewExchangeDID != "" {
		eventTime := p.EventTime
		if eventTime == 0 {
			eventTime = time.Now().UTC().UnixMicro()
		}

		succEntry, sErr := builder.BuildSuccession(builder.SuccessionParams{
			Destination:  p.Destination,
			SignerDID:    p.NewExchangeDID,
			TargetRoot:   *p.TargetRoot,
			NewSignerDID: p.NewExchangeDID,
			Payload: mustMarshalJSON(map[string]any{
				"succession_type": "escrow_recovery",
			}),
			EventTime: eventTime,
		})
		if sErr != nil {
			result.SuccessionError = fmt.Errorf("lifecycle/recovery: build succession: %w", sErr)
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
// the override can proceed.
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
	// cosignature, required when
	// SchemaParams.OverrideRequiresIndependentWitness is true. Must
	// reference RecoveryRequestPos (BUG-009 fix 2) and must be signed
	// by a DID outside EscrowNodeSet (fix 3).
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
//	        available, fall through" (the pre-fix behavior).
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

	// Resolve schema-declared override policy. A nil SchemaParams means
	// "defaults" — zero-value OverrideThresholdRule (two-thirds) and no
	// witness requirement.
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
