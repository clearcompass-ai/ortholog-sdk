/*
Package lifecycle — recovery.go implements three-phase key escrow recovery
for the Ortholog protocol. Used when an exchange fails or a holder migrates.

Three phases:

	InitiateRecovery: publishes a recovery request commentary entry
	CollectShares: gathers M-of-N escrow shares, validates field tags
	ExecuteRecovery: reconstructs keys, re-encrypts artifacts, publishes
	  succession entries

Additionally: EscalateToArbitration for custody disputes where the
incumbent exchange contests the recovery. Requires schema-declared
supermajority (default ⌈2N/3⌉, per OverrideThresholdRule) of escrow
nodes plus optional independent identity witness cosignature (when
override_requires_independent_witness is true in the schema).

Naming fix #1: uses ReconstructGF256 (the real Phase 1 function name),
not "escrow.CombineShares".

Naming fix #2: uses escrow.VerifyShare for per-share validation during
collection, instead of inlining the tag check.

Wave 2: the hardcoded ⌈2N/3⌉ in EvaluateArbitration is now schema-driven
via SchemaParams.OverrideThreshold. Default (missing field) remains
two-thirds, preserving all pre-Wave-2 behavior.

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
)

// ─────────────────────────────────────────────────────────────────────
// Phase 1: InitiateRecovery
// ─────────────────────────────────────────────────────────────────────

// InitiateRecoveryParams configures a recovery request.
type InitiateRecoveryParams struct {
	// Destination is the DID of the target exchange for the produced
	// entry. Required. Validated by envelope.ValidateDestination.
	Destination string

	// NewExchangeDID is the DID of the exchange initiating recovery.
	NewExchangeDID string

	// HolderDID is the holder whose keys are being recovered.
	HolderDID string

	// Reason describes why recovery is needed (exchange failure, migration).
	Reason string

	// EscrowPackageCID is the CID of the holder's escrow package on CAS.
	EscrowPackageCID storage.CID

	// EventTime is the entry timestamp (Unix microseconds).
	EventTime int64
}

// InitiateRecoveryResult holds the recovery request entry.
type InitiateRecoveryResult struct {
	// RequestEntry is the commentary entry to submit to the operator.
	RequestEntry *envelope.Entry

	// RequestPayload is the parsed payload for reference.
	RequestPayload map[string]any
}

// InitiateRecovery publishes a recovery request commentary entry.
// The entry signals to escrow nodes that M-of-N share reconstruction
// is needed. Each escrow node discovers this via monitoring (ScanFromPosition
// or QueryByCosignatureOf) and decides whether to participate.
//
// Returns the entry for the caller to submit to the operator.
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
	// EscrowPackageCID is the CID of the escrowed package on CAS.
	EscrowPackageCID storage.CID

	// ContentStore fetches the escrow package from CAS.
	ContentStore storage.ContentStore

	// DecryptedShares are the shares decrypted by each escrow node.
	// Each node fetches the package, decrypts their share using their
	// private key (ECIES), and provides the plaintext share.
	// The caller collects these off-chain or from cosignature entries.
	DecryptedShares []escrow.Share

	// RequiredThreshold is the M in M-of-N. If zero, reads from the
	// escrow package metadata.
	RequiredThreshold int
}

// CollectedShares holds the validated shares ready for reconstruction.
type CollectedShares struct {
	// ValidShares are shares that passed VerifyShare validation.
	ValidShares []escrow.Share

	// InvalidCount is the number of shares that failed validation.
	InvalidCount int

	// InvalidReasons maps share index to validation error.
	InvalidReasons map[int]string

	// SufficientForRecovery is true when ValidShares >= RequiredThreshold.
	SufficientForRecovery bool

	// Threshold is the M from M-of-N.
	Threshold int
}

// CollectShares validates individual shares as they arrive from escrow
// nodes. Uses escrow.VerifyShare (naming fix #2) for per-share validation.
//
// The caller collects shares from escrow nodes (off-chain or via
// cosignature entries on the log). Each share is validated:
//  1. Field tag = 0x01 (GF(256)) — escrow.VerifyShare
//  2. Index != 0 (reserved)
//  3. Value length = 32 bytes
//  4. No duplicate indices
//
// Invalid shares are recorded but do not block collection. Recovery
// proceeds as soon as M valid shares are available.
func CollectShares(p CollectSharesParams) (*CollectedShares, error) {
	result := &CollectedShares{
		InvalidReasons: make(map[int]string),
		Threshold:      p.RequiredThreshold,
	}

	seen := make(map[byte]bool)
	for i, share := range p.DecryptedShares {
		// Validate using escrow.VerifyShare (naming fix #2).
		if err := escrow.VerifyShare(share); err != nil {
			result.InvalidCount++
			result.InvalidReasons[i] = err.Error()
			continue
		}

		// Deduplicate by index.
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
	// Destination is the DID of the target exchange for any succession
	// entry produced. Required. Validated by envelope.ValidateDestination.
	Destination string

	// Shares are the validated shares from CollectShares.
	Shares []escrow.Share

	// ArtifactCIDs are the CIDs of artifacts to re-encrypt under the new key.
	// Callers re-encrypt any artifacts whose keys were derived from the
	// reconstructed material. The list is domain-specific; the SDK treats
	// the CIDs opaquely.
	ArtifactCIDs []storage.CID

	// ContentStore fetches and pushes artifacts during re-encryption.
	ContentStore storage.ContentStore

	// KeyStore stores new artifact keys after re-encryption.
	KeyStore ArtifactKeyStore

	// NewExchangeDID is the signer for succession entries.
	NewExchangeDID string

	// TargetRoot is the holder's entity position for succession.
	TargetRoot *types.LogPosition

	// EventTime is the entry timestamp.
	EventTime int64
}

// RecoveryResult holds the outcome of key reconstruction and re-encryption.
type RecoveryResult struct {
	// ReconstructedKeyMaterial is the raw reconstructed secret (44 bytes:
	// 32-byte AES key + 12-byte nonce). Zeroed after re-encryption.
	// Exposed for the caller to verify before proceeding.
	ReconstructedKeyMaterial []byte

	// ReEncryptedArtifacts maps old CID → new CID for each re-encrypted artifact.
	ReEncryptedArtifacts map[string]storage.CID

	// SuccessionEntry is the optional succession entry for the holder's entity.
	// The caller submits this to the operator.
	SuccessionEntry *envelope.Entry

	// VendorDIDMappingRecovered is retained for backward compatibility
	// with callers that inspected it. The SDK does not set it (domain
	// concern); domain code may populate it after inspecting its own
	// artifact list.
	VendorDIDMappingRecovered bool
}

// ExecuteRecovery reconstructs the holder's keys from escrow shares and
// re-encrypts all artifacts under new keys.
//
// Naming fix #1: uses escrow.ReconstructGF256 (the real name), not
// "escrow.CombineShares".
//
// Steps:
//  1. Reconstruct key material via escrow.ReconstructGF256
//  2. Parse the 44-byte secret into ArtifactKey (32-byte key + 12-byte nonce)
//  3. For each artifact CID:
//     a. Fetch ciphertext from ContentStore
//     b. Decrypt with old key
//     c. Re-encrypt with new key
//     d. Push new ciphertext, store new key
//     e. Delete old key (cryptographic erasure)
//  4. Build succession entry for the holder's entity
//  5. Zero reconstructed key material
func ExecuteRecovery(p ExecuteRecoveryParams) (*RecoveryResult, error) {
	if err := envelope.ValidateDestination(p.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/recovery: %w", err)
	}
	if len(p.Shares) == 0 {
		return nil, ErrInsufficientShares
	}

	// 1. Reconstruct key material (naming fix #1: ReconstructGF256).
	keyMaterial, err := escrow.ReconstructGF256(p.Shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReconstructionFailed, err)
	}

	// 2. Parse into ArtifactKey.
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

	// 3. Re-encrypt each artifact.
	for _, oldCID := range p.ArtifactCIDs {
		reResult, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
			OldCID:              oldCID,
			KeyStore:            &recoveryKeyAdapter{key: oldKey, targetCID: oldCID},
			ContentStore:        p.ContentStore,
			DeleteOldCiphertext: false, // Preserve old ciphertext during recovery.
		})
		if err != nil {
			// Non-fatal: some artifacts may be unreachable (CAS loss).
			// Record the failure but continue with other artifacts.
			continue
		}

		// Store new key in the caller's key store.
		if p.KeyStore != nil {
			if err := p.KeyStore.Store(reResult.NewCID, reResult.NewKey); err != nil {
				continue
			}
		}

		result.ReEncryptedArtifacts[oldCID.String()] = reResult.NewCID
	}

	// 4. Build succession entry.
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

	// 5. Zero reconstructed key material.
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
// Custody Dispute Escalation
// ─────────────────────────────────────────────────────────────────────

// ArbitrationParams configures an escrow arbitration override.
type ArbitrationParams struct {
	// RecoveryRequestPos is the position of the InitiateRecovery entry.
	RecoveryRequestPos types.LogPosition

	// EscrowApprovals are cosignature entries from escrow nodes
	// approving the override. Discovered via QueryByCosignatureOf.
	EscrowApprovals []types.EntryWithMetadata

	// TotalEscrowNodes is N (total escrow nodes for this holder).
	TotalEscrowNodes int

	// WitnessCosignature is the independent identity witness cosignature.
	// Required when the schema declares override_requires_independent_witness.
	// Nil if not required.
	WitnessCosignature *types.EntryWithMetadata

	// SchemaParams provides the override policy. Two fields are read:
	//   - OverrideThreshold: schema-declared supermajority rule
	//     (default ThresholdTwoThirdsMajority = ⌈2N/3⌉)
	//   - OverrideRequiresIndependentWitness: requires witness cosig when true
	// Nil SchemaParams means both defaults apply.
	SchemaParams *types.SchemaParameters
}

// ArbitrationResult holds the outcome of arbitration evaluation.
type ArbitrationResult struct {
	// OverrideAuthorized is true when the supermajority is met and
	// all required cosignatures are present.
	OverrideAuthorized bool

	// ApprovalCount is the number of valid escrow node approvals.
	ApprovalCount int

	// RequiredCount is the schema-declared supermajority (default ⌈2N/3⌉).
	RequiredCount int

	// HasWitnessCosig is true if an independent witness cosigned.
	HasWitnessCosig bool

	// Reason describes why the override was or wasn't authorized.
	Reason string
}

// EvaluateArbitration checks whether an escrow arbitration override has
// sufficient approvals. The threshold is schema-declared via
// SchemaParams.OverrideThreshold; the SDK default (two-thirds) applies
// when SchemaParams is nil or when the schema omits the field.
// If the schema declares override_requires_independent_witness, an
// additional identity witness cosignature is required.
func EvaluateArbitration(p ArbitrationParams) (*ArbitrationResult, error) {
	if p.TotalEscrowNodes <= 0 {
		return nil, fmt.Errorf("lifecycle/recovery: invalid escrow node count %d", p.TotalEscrowNodes)
	}

	// Resolve schema-declared override policy. Nil SchemaParams or a
	// zero-valued OverrideThreshold both map to ThresholdTwoThirdsMajority
	// via the enum's zero-value semantics — no additional guards needed.
	var threshold types.OverrideThresholdRule
	requiresWitness := false
	if p.SchemaParams != nil {
		threshold = p.SchemaParams.OverrideThreshold
		requiresWitness = p.SchemaParams.OverrideRequiresIndependentWitness
	}
	required := threshold.RequiredApprovals(p.TotalEscrowNodes)

	// Count unique escrow node approvals.
	seen := make(map[string]bool)
	for _, meta := range p.EscrowApprovals {
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		if entry.Header.CosignatureOf == nil {
			continue
		}
		if !entry.Header.CosignatureOf.Equal(p.RecoveryRequestPos) {
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

	// Check witness cosignature if required.
	if requiresWitness {
		if p.WitnessCosignature == nil {
			result.Reason = "supermajority met but independent witness cosignature required"
			return result, nil
		}
		// Verify the witness is NOT an escrow node (independence requirement).
		witnessEntry, err := envelope.Deserialize(p.WitnessCosignature.CanonicalBytes)
		if err == nil && witnessEntry.Header.CosignatureOf != nil {
			result.HasWitnessCosig = true
		}
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

// recoveryKeyAdapter wraps a single reconstructed key to satisfy
// ArtifactKeyStore for ReEncryptWithGrant. Used internally during
// ExecuteRecovery when we have the old key but not a full key store.
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
