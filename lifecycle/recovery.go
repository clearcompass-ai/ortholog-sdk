/*
Package lifecycle — recovery.go implements three-phase key escrow recovery
for the Ortholog protocol. Used when an exchange fails or a holder migrates.

Three phases:

	InitiateRecovery: publishes a recovery request commentary entry
	CollectShares: gathers M-of-N escrow shares, validates field tags
	ExecuteRecovery: reconstructs keys, re-encrypts artifacts, publishes
	  succession entries

Additionally: EvaluateArbitration for custody disputes where the
incumbent exchange contests the recovery. Requires schema-declared
supermajority (default ⌈2N/3⌉, per OverrideThresholdRule) of escrow
nodes plus optional independent identity witness cosignature (when
override_requires_independent_witness is true in the schema).

BUG-009 FIX (this revision):

	EvaluateArbitration had three independent holes in its witness
	cosignature validation path, all of which enabled a compromised
	escrow operator to fabricate override authorization:

	  1. Deserialize error was silently tolerated — malformed witness
	     bytes did not block OverrideAuthorized.

	  2. Witness cosignature was not bound to the recovery request —
	     any cosignature of any entry satisfied the witness requirement.

	  3. Independence check was absent — a witness signed by an escrow
	     node was accepted, defeating the independence requirement.

	All three fixes land in the requiresWitness block. The fix also
	adds ArbitrationParams.EscrowNodeSet as a new required field when
	the schema declares OverrideRequiresIndependentWitness=true.

	The EscrowApprovals loop was already semantically correct (it did
	bind via .Equal()); this revision refactors it to use
	IsCosignatureOf for SDK-wide consistency, but behavior is unchanged.

Destination binding: every public Params struct that produces an entry
carries a Destination field (DID of the target exchange). The lifecycle
validates it via envelope.ValidateDestination and threads it into every
builder.*Params literal so the canonical hash commits to the destination.

Consumed by:
  - judicial-network/migration/ungraceful.go → InitiateRecovery → CollectShares → ExecuteRecovery
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
// ─────────────────────────────────────────────────────────────────────

var (
	ErrRecoveryNotInitiated  = fmt.Errorf("lifecycle/recovery: recovery not initiated")
	ErrInsufficientShares    = fmt.Errorf("lifecycle/recovery: insufficient valid shares")
	ErrShareValidationFailed = fmt.Errorf("lifecycle/recovery: share validation failed")
	ErrReconstructionFailed  = fmt.Errorf("lifecycle/recovery: key reconstruction failed")
	ErrArbitrationRequired   = fmt.Errorf("lifecycle/recovery: custody dispute requires arbitration")
	ErrInsufficientOverride  = fmt.Errorf("lifecycle/recovery: override requires schema-declared supermajority")
	ErrMissingWitnessCosig   = fmt.Errorf("lifecycle/recovery: schema requires independent identity witness cosignature")
	ErrMissingEscrowNodeSet  = fmt.Errorf("lifecycle/recovery: OverrideRequiresIndependentWitness requires EscrowNodeSet")
)

// ─────────────────────────────────────────────────────────────────────
// Phase 1: InitiateRecovery
// ─────────────────────────────────────────────────────────────────────

// InitiateRecoveryParams configures a recovery request.
type InitiateRecoveryParams struct {
	Destination      string
	NewExchangeDID   string
	HolderDID        string
	Reason           string
	EscrowPackageCID storage.CID
	EventTime        int64
}

// InitiateRecoveryResult holds the recovery request entry.
type InitiateRecoveryResult struct {
	RequestEntry   *envelope.Entry
	RequestPayload map[string]any
}

// InitiateRecovery publishes a recovery request commentary entry.
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
// ─────────────────────────────────────────────────────────────────────

// CollectSharesParams configures share collection.
type CollectSharesParams struct {
	EscrowPackageCID  storage.CID
	ContentStore      storage.ContentStore
	DecryptedShares   []escrow.Share
	RequiredThreshold int
}

// CollectedShares holds the validated shares ready for reconstruction.
type CollectedShares struct {
	ValidShares           []escrow.Share
	InvalidCount          int
	InvalidReasons        map[int]string
	SufficientForRecovery bool
	Threshold             int
}

// CollectShares validates individual shares as they arrive from escrow nodes.
func CollectShares(p CollectSharesParams) (*CollectedShares, error) {
	result := &CollectedShares{
		InvalidReasons: make(map[int]string),
		Threshold:      p.RequiredThreshold,
	}

	seen := make(map[byte]bool)
	for i, share := range p.DecryptedShares {
		if err := escrow.VerifyShare(share); err != nil {
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
// ─────────────────────────────────────────────────────────────────────

// ExecuteRecoveryParams configures key reconstruction and re-encryption.
type ExecuteRecoveryParams struct {
	Destination    string
	Shares         []escrow.Share
	ArtifactCIDs   []storage.CID
	ContentStore   storage.ContentStore
	KeyStore       ArtifactKeyStore
	NewExchangeDID string
	TargetRoot     *types.LogPosition
	EventTime      int64
}

// RecoveryResult holds the outcome of key reconstruction and re-encryption.
type RecoveryResult struct {
	ReconstructedKeyMaterial  []byte
	ReEncryptedArtifacts      map[string]storage.CID
	SuccessionEntry           *envelope.Entry
	VendorDIDMappingRecovered bool
}

// ExecuteRecovery reconstructs the holder's keys from escrow shares and
// re-encrypts all artifacts under new keys.
func ExecuteRecovery(p ExecuteRecoveryParams) (*RecoveryResult, error) {
	if err := envelope.ValidateDestination(p.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: %w", err)
	}
	if len(p.Shares) == 0 {
		return nil, ErrInsufficientShares
	}

	keyMaterial, err := escrow.ReconstructGF256(p.Shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReconstructionFailed, err)
	}

	if len(keyMaterial) != artifact.KeySize+artifact.NonceSize {
		return nil, fmt.Errorf("%w: reconstructed %d bytes, expected %d",
			ErrReconstructionFailed, len(keyMaterial), artifact.KeySize+artifact.NonceSize)
	}
	var oldKey artifact.ArtifactKey
	copy(oldKey.Key[:], keyMaterial[:artifact.KeySize])
	copy(oldKey.Nonce[:], keyMaterial[artifact.KeySize:])

	result := &RecoveryResult{
		ReconstructedKeyMaterial: keyMaterial,
		ReEncryptedArtifacts:     make(map[string]storage.CID),
	}

	for _, oldCID := range p.ArtifactCIDs {
		reResult, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
			OldCID:              oldCID,
			KeyStore:            &recoveryKeyAdapter{key: oldKey, targetCID: oldCID},
			ContentStore:        p.ContentStore,
			DeleteOldCiphertext: false,
		})
		if err != nil {
			continue
		}

		if p.KeyStore != nil {
			if err := p.KeyStore.Store(reResult.NewCID, reResult.NewKey); err != nil {
				continue
			}
		}

		result.ReEncryptedArtifacts[oldCID.String()] = reResult.NewCID
	}

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
			}),
			EventTime: eventTime,
		})
		if err == nil {
			result.SuccessionEntry = succEntry
		}
	}

	// Zero reconstructed key material.
	for i := range keyMaterial {
		keyMaterial[i] = 0
	}
	for i := range oldKey.Key {
		oldKey.Key[i] = 0
	}
	for i := range oldKey.Nonce {
		oldKey.Nonce[i] = 0
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Custody Dispute Arbitration
// ─────────────────────────────────────────────────────────────────────

// ArbitrationParams configures an escrow arbitration override.
//
// # BUG-009 API change
//
// EscrowNodeSet is new in this revision. When the schema declares
// OverrideRequiresIndependentWitness=true, this field MUST be
// populated with the set of escrow node DIDs so that the
// independence check can run. An empty set in that configuration
// is rejected with ErrMissingEscrowNodeSet — a missing escrow-node
// set would silently disable the independence check, which was the
// pre-fix behavior.
type ArbitrationParams struct {
	// RecoveryRequestPos is the position of the InitiateRecovery entry.
	RecoveryRequestPos types.LogPosition

	// EscrowApprovals are cosignature entries from escrow nodes
	// approving the override. Discovered via QueryByCosignatureOf.
	EscrowApprovals []types.EntryWithMetadata

	// TotalEscrowNodes is N (total escrow nodes for this holder).
	TotalEscrowNodes int

	// EscrowNodeSet is the set of escrow node DIDs for this holder.
	// Required when SchemaParams.OverrideRequiresIndependentWitness
	// is true. If nil/empty in that configuration,
	// EvaluateArbitration returns ErrMissingEscrowNodeSet.
	EscrowNodeSet map[string]bool

	// WitnessCosignature is the independent identity witness cosignature.
	// Required when the schema declares override_requires_independent_witness.
	WitnessCosignature *types.EntryWithMetadata

	// SchemaParams provides the override policy. Nil means defaults
	// (two-thirds threshold, no witness requirement).
	SchemaParams *types.SchemaParameters
}

// ArbitrationResult holds the outcome of arbitration evaluation.
type ArbitrationResult struct {
	OverrideAuthorized bool
	ApprovalCount      int
	RequiredCount      int
	HasWitnessCosig    bool
	Reason             string
}

// EvaluateArbitration checks whether an escrow arbitration override has
// sufficient approvals and a valid independent witness cosignature
// bound to the specific recovery request.
//
// # BUG-009 FIXES APPLIED HERE
//
// Fix 1 — Deserialize error blocks authorization. Previously a
// malformed witness cosignature was silently tolerated.
//
// Fix 2 — Witness cosignature bound to p.RecoveryRequestPos via
// IsCosignatureOf. Previously any non-nil CosignatureOf satisfied.
//
// Fix 3 — Independence check: witness signer must not be in
// p.EscrowNodeSet. Previously no such check existed.
//
// Configuration guard: if OverrideRequiresIndependentWitness=true and
// EscrowNodeSet is empty, returns ErrMissingEscrowNodeSet. A missing
// set in that configuration silently disables fix 3, so we fail fast
// instead.
//
// The EscrowApprovals loop uses IsCosignatureOf for SDK-wide
// consistency; this loop's binding check was already correct pre-fix,
// so only the style changes.
func EvaluateArbitration(p ArbitrationParams) (*ArbitrationResult, error) {
	if p.TotalEscrowNodes <= 0 {
		return nil, fmt.Errorf("lifecycle/recovery: invalid escrow node count %d", p.TotalEscrowNodes)
	}

	// Resolve schema-declared override policy.
	var threshold types.OverrideThresholdRule
	requiresWitness := false
	if p.SchemaParams != nil {
		threshold = p.SchemaParams.OverrideThreshold
		requiresWitness = p.SchemaParams.OverrideRequiresIndependentWitness
	}
	required := threshold.RequiredApprovals(p.TotalEscrowNodes)

	// Configuration sanity: witness requirement demands an escrow node set
	// for the independence check. Fail fast rather than silently skipping.
	if requiresWitness && len(p.EscrowNodeSet) == 0 {
		return nil, ErrMissingEscrowNodeSet
	}

	// Count unique escrow node approvals. Uses IsCosignatureOf for
	// SDK-wide consistency; behavior is unchanged from pre-fix
	// (this loop was already binding correctly).
	seen := make(map[string]bool)
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
		result.Reason = fmt.Sprintf("%d of %d escrow approvals (threshold %s requires %d)",
			approvalCount, p.TotalEscrowNodes, threshold.String(), required)
		return result, nil
	}

	// Witness cosignature checks — this is where the three BUG-009
	// fixes land.
	if requiresWitness {
		if p.WitnessCosignature == nil {
			result.Reason = "supermajority met but independent witness cosignature required"
			return result, nil
		}

		// BUG-009 fix 1: deserialize error blocks authorization.
		witnessEntry, err := envelope.Deserialize(p.WitnessCosignature.CanonicalBytes)
		if err != nil {
			result.Reason = fmt.Sprintf("witness cosignature deserialize failed: %v", err)
			return result, nil
		}

		// BUG-009 fix 2: witness cosig must reference the recovery request.
		// BUG-009 fix 2: witness cosig must reference the recovery request.
		if !verifier.IsCosignatureOf(witnessEntry, p.RecoveryRequestPos) {
			result.Reason = "witness cosignature does not reference recovery request position"
			return result, nil
		}

		// BUG-009 fix 3: witness must be independent of escrow.
		if p.EscrowNodeSet[witnessEntry.Header.SignerDID] {
			result.Reason = fmt.Sprintf(
				"witness %s is an escrow node; independence requirement violated",
				witnessEntry.Header.SignerDID)
			return result, nil
		}

		result.HasWitnessCosig = true
	}

	result.OverrideAuthorized = true
	result.Reason = fmt.Sprintf("override authorized: %d of %d escrow approvals (threshold %s requires %d)",
		approvalCount, p.TotalEscrowNodes, threshold.String(), required)
	if requiresWitness {
		result.Reason += " + independent witness cosignature"
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// recoveryKeyAdapter — satisfies ArtifactKeyStore for single-key recovery
// ─────────────────────────────────────────────────────────────────────

type recoveryKeyAdapter struct {
	key       artifact.ArtifactKey
	targetCID storage.CID
}

func (a *recoveryKeyAdapter) Get(cid storage.CID) (*artifact.ArtifactKey, error) {
	if cid.Equal(a.targetCID) {
		k := a.key
		return &k, nil
	}
	return nil, nil
}

func (a *recoveryKeyAdapter) Store(_ storage.CID, _ artifact.ArtifactKey) error { return nil }
func (a *recoveryKeyAdapter) Delete(_ storage.CID) error                        { return nil }
