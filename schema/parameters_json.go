/*
Package schema — parameters_json.go implements the default JSON-based
SchemaParameterExtractor.

Reads all 13 well-known fields from a schema entry's Domain Payload:
  activation_delay, cosignature_threshold, maturation_epoch,
  credential_validity_period, override_requires_witness, migration_policy,
  predecessor_schema, artifact_encryption, grant_entry_required,
  re_encryption_threshold, grant_authorization_mode,
  grant_requires_audit_entry, override_threshold.

Unknown fields are silently ignored (forward-compatible).
Missing artifact fields default to aes_gcm / false / nil.
Missing grant authorization fields default to open / false.
Missing override_threshold defaults to two_thirds (pre-Wave-2 behavior).
Every other Phase 5+ file consumes this.

KEY ARCHITECTURAL DECISIONS:
  - Domain Payload is opaque to builder (SDK-D6). Only verifiers and
    domain code read it.
  - Durations encoded as seconds (int64) in JSON.
  - MigrationPolicy as string: "strict", "forward", "amendment".
  - ArtifactEncryption as string: "aes_gcm", "umbral_pre".
  - GrantAuthorizationMode as string: "open", "restricted", "sealed".
  - OverrideThreshold as string: "two_thirds", "simple_majority", "unanimity".
  - PredecessorSchema as JSON object with log_did + sequence.
  - ReEncryptionThreshold as JSON object with m + n.
  - Malformed JSON and empty payload produce errors.
*/
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// JSONParameterExtractor reads SchemaParameters from JSON Domain Payload.
// Satisfies the SchemaParameterExtractor interface.
type JSONParameterExtractor struct{}

// NewJSONParameterExtractor creates a JSON-based parameter extractor.
func NewJSONParameterExtractor() *JSONParameterExtractor {
	return &JSONParameterExtractor{}
}

// jsonSchemaPayload is the intermediate JSON structure for deserialization.
// Field names match the protocol's snake_case convention.
type jsonSchemaPayload struct {
	ActivationDelay          *int64               `json:"activation_delay"`
	CosignatureThreshold     *int                 `json:"cosignature_threshold"`
	MaturationEpoch          *int64               `json:"maturation_epoch"`
	CredentialValidityPeriod *int64               `json:"credential_validity_period"`
	OverrideRequiresWitness  *bool                `json:"override_requires_witness"`
	MigrationPolicy          *string              `json:"migration_policy"`
	PredecessorSchema        *jsonLogPosition     `json:"predecessor_schema"`
	ArtifactEncryption       *string              `json:"artifact_encryption"`
	GrantEntryRequired       *bool                `json:"grant_entry_required"`
	ReEncryptionThreshold    *jsonThresholdConfig `json:"re_encryption_threshold"`

	// Phase 6 additions: grant authorization policy.
	// JSON string "open" | "restricted" | "sealed" → typed enum.
	// Same parsing pattern as artifact_encryption and migration_policy.
	GrantAuthorizationMode  *string `json:"grant_authorization_mode"`
	GrantRequiresAuditEntry *bool   `json:"grant_requires_audit_entry"`

	// Wave 2 addition: override threshold rule.
	// JSON string "two_thirds" | "simple_majority" | "unanimity" → typed enum.
	// Missing or absent value means the SDK default (two-thirds), preserving
	// pre-Wave-2 behavior for every schema that predates this field.
	OverrideThreshold *string `json:"override_threshold"`

	// v7.5: CommutativeOperations moves here from ControlHeader.
	// Absent, null, and empty array all mean "strict OCC" (no
	// commutative operations); non-empty enables Δ-window OCC. Pointer
	// type lets MarshalParameters distinguish "omit the field" from
	// "emit explicit []" if that ever matters for bytewise round-trip
	// — currently both decode to the same empty slice in Extract.
	CommutativeOperations *[]uint32 `json:"commutative_operations"`
}

// jsonLogPosition is the JSON representation of types.LogPosition.
type jsonLogPosition struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

// jsonThresholdConfig is the JSON representation of types.ThresholdConfig.
type jsonThresholdConfig struct {
	M int `json:"m"`
	N int `json:"n"`
}

// Extract reads all 13 well-known fields from the schema entry's Domain Payload.
// Unknown fields are silently ignored. Missing optional fields use defaults.
//
// Defaults for artifact fields:
//   - artifact_encryption: EncryptionAESGCM (aes_gcm)
//   - grant_entry_required: false
//   - re_encryption_threshold: nil
//
// Defaults for grant authorization fields:
//   - grant_authorization_mode: GrantAuthOpen (open) — no restriction
//   - grant_requires_audit_entry: false
//
// Default for override threshold (Wave 2):
//   - override_threshold: ThresholdTwoThirdsMajority (⌈2N/3⌉) — preserves
//     pre-Wave-2 behavior for every existing schema.
//
// Errors:
//   - Empty Domain Payload → error
//   - Malformed JSON → error
//   - Unknown enum value for any mode field → error (fail-closed on bad config)
func (e *JSONParameterExtractor) Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error) {
	if schemaEntry == nil {
		return nil, errors.New("schema/parameters_json: nil schema entry")
	}
	if len(schemaEntry.DomainPayload) == 0 {
		return nil, errors.New("schema/parameters_json: empty domain payload")
	}

	var raw jsonSchemaPayload
	if err := json.Unmarshal(schemaEntry.DomainPayload, &raw); err != nil {
		return nil, fmt.Errorf("schema/parameters_json: malformed JSON: %w", err)
	}

	params := &types.SchemaParameters{
		// Artifact defaults.
		ArtifactEncryption: types.EncryptionAESGCM,
		GrantEntryRequired: false,
		// Grant authorization defaults (Phase 6).
		// GrantAuthOpen is the zero value (0), so no explicit assignment needed,
		// but we include it for documentation clarity.
		GrantAuthorizationMode:  types.GrantAuthOpen,
		GrantRequiresAuditEntry: false,
		// Override threshold default (Wave 2).
		// ThresholdTwoThirdsMajority is the zero value. Explicit assignment
		// documents the intent — a reader shouldn't need to know which
		// enum constant happens to be zero.
		OverrideThreshold: types.ThresholdTwoThirdsMajority,
		// v7.5 invariant: CommutativeOperations is never nil after
		// Extract. Callers test len(v) == 0 without nil-checking.
		CommutativeOperations: []uint32{},
	}

	// ── Protocol-mechanical fields ───────────────────────────────────

	if raw.ActivationDelay != nil {
		params.ActivationDelay = time.Duration(*raw.ActivationDelay) * time.Second
	}

	if raw.CosignatureThreshold != nil {
		params.CosignatureThreshold = *raw.CosignatureThreshold
	}

	if raw.MaturationEpoch != nil {
		params.MaturationEpoch = time.Duration(*raw.MaturationEpoch) * time.Second
	}

	if raw.CredentialValidityPeriod != nil {
		// -1 is the Marshal-side sentinel for "no expiry" (nil
		// *time.Duration). Preserves the round-trip invariant when
		// MarshalParameters emits every field unconditionally. A
		// real schema MUST NOT set negative validity; production
		// inputs either omit the field or specify a positive
		// duration, and this branch is invisible to them.
		if *raw.CredentialValidityPeriod == credentialValidityPeriodNilSentinel {
			params.CredentialValidityPeriod = nil
		} else {
			d := time.Duration(*raw.CredentialValidityPeriod) * time.Second
			params.CredentialValidityPeriod = &d
		}
	}

	if raw.OverrideRequiresWitness != nil {
		params.OverrideRequiresIndependentWitness = *raw.OverrideRequiresWitness
	}

	if raw.MigrationPolicy != nil {
		switch *raw.MigrationPolicy {
		case "":
			// Marshal-side sentinel for "unset MigrationPolicy."
			// Preserves the round-trip when a caller constructs
			// SchemaParameters without setting the field. Leaves
			// the struct's zero value intact (params already
			// zero-initialised).
		case "strict":
			params.MigrationPolicy = types.MigrationStrict
		case "forward":
			params.MigrationPolicy = types.MigrationForward
		case "amendment":
			params.MigrationPolicy = types.MigrationAmendment
		default:
			return nil, fmt.Errorf("schema/parameters_json: unknown migration_policy %q", *raw.MigrationPolicy)
		}
	}

	if raw.PredecessorSchema != nil {
		pos := types.LogPosition{
			LogDID:   raw.PredecessorSchema.LogDID,
			Sequence: raw.PredecessorSchema.Sequence,
		}
		params.PredecessorSchema = &pos
	}

	// ── Operational artifact fields ──────────────────────────────────

	if raw.ArtifactEncryption != nil {
		switch *raw.ArtifactEncryption {
		case "aes_gcm":
			params.ArtifactEncryption = types.EncryptionAESGCM
		case "umbral_pre":
			params.ArtifactEncryption = types.EncryptionUmbralPRE
		default:
			return nil, fmt.Errorf("schema/parameters_json: unknown artifact_encryption %q", *raw.ArtifactEncryption)
		}
	}

	if raw.GrantEntryRequired != nil {
		params.GrantEntryRequired = *raw.GrantEntryRequired
	}

	if raw.ReEncryptionThreshold != nil {
		params.ReEncryptionThreshold = &types.ThresholdConfig{
			M: raw.ReEncryptionThreshold.M,
			N: raw.ReEncryptionThreshold.N,
		}
	}

	// ── Operational grant authorization fields (Phase 6) ─────────────
	//
	// Same parsing pattern as artifact_encryption and migration_policy:
	// JSON string → typed enum. Unknown values produce an error (fail-closed).
	// Missing field → default (GrantAuthOpen / false).

	if raw.GrantAuthorizationMode != nil {
		switch *raw.GrantAuthorizationMode {
		case "open":
			params.GrantAuthorizationMode = types.GrantAuthOpen
		case "restricted":
			params.GrantAuthorizationMode = types.GrantAuthRestricted
		case "sealed":
			params.GrantAuthorizationMode = types.GrantAuthSealed
		default:
			return nil, fmt.Errorf("schema/parameters_json: unknown grant_authorization_mode %q", *raw.GrantAuthorizationMode)
		}
	}

	if raw.GrantRequiresAuditEntry != nil {
		params.GrantRequiresAuditEntry = *raw.GrantRequiresAuditEntry
	}

	// ── Wave 2: override threshold ──────────────────────────────────
	//
	// Same fail-closed parsing pattern. Missing field → default
	// (ThresholdTwoThirdsMajority, already assigned above).

	if raw.OverrideThreshold != nil {
		switch *raw.OverrideThreshold {
		case "two_thirds":
			params.OverrideThreshold = types.ThresholdTwoThirdsMajority
		case "simple_majority":
			params.OverrideThreshold = types.ThresholdSimpleMajority
		case "unanimity":
			params.OverrideThreshold = types.ThresholdUnanimity
		default:
			return nil, fmt.Errorf("schema/parameters_json: unknown override_threshold %q", *raw.OverrideThreshold)
		}
	}

	// ── v7.5: Commutative operations ────────────────────────────────
	//
	// Absent and null both preserve the "strict OCC" default set
	// above (empty slice). An explicit non-empty array is copied
	// verbatim; an explicit empty array also collapses to the shared
	// empty default (no difference on the verifier side).
	if raw.CommutativeOperations != nil && len(*raw.CommutativeOperations) > 0 {
		params.CommutativeOperations = append(params.CommutativeOperations, (*raw.CommutativeOperations)...)
	}

	return params, nil
}

// ─────────────────────────────────────────────────────────────────────
// MarshalParameters — canonical inverse of Extract
// ─────────────────────────────────────────────────────────────────────

// marshalShape is the on-wire JSON struct MarshalParameters writes.
// Every scalar field is emitted unconditionally (Option A, D1 in the
// v7.5 plan). This eliminates "field absent" vs "field set to default"
// ambiguity — the round-trip invariant (Extract(Marshal(p)) == p)
// becomes trivially true for every valid p.
//
// CredentialValidityPeriod uses a -1 sentinel for nil because the
// field decodes through *int64 in jsonSchemaPayload: a JSON null
// yields nil, but Option A requires unconditional emission, and
// emitting 0 would collide with "zero duration." -1 is documented
// here and at the pointer's load point in Extract.
//
// PredecessorSchema and ReEncryptionThreshold keep their pointer-to-
// struct shape; JSON null is their natural empty encoding.
type marshalShape struct {
	ActivationDelay                int64                `json:"activation_delay"`
	CosignatureThreshold           int                  `json:"cosignature_threshold"`
	MaturationEpoch                int64                `json:"maturation_epoch"`
	CredentialValidityPeriod       int64                `json:"credential_validity_period"`
	OverrideRequiresWitness        bool                 `json:"override_requires_witness"`
	MigrationPolicy                string               `json:"migration_policy"`
	PredecessorSchema              *jsonLogPosition     `json:"predecessor_schema"`
	ArtifactEncryption             string               `json:"artifact_encryption"`
	GrantEntryRequired             bool                 `json:"grant_entry_required"`
	ReEncryptionThreshold          *jsonThresholdConfig `json:"re_encryption_threshold"`
	GrantAuthorizationMode         string               `json:"grant_authorization_mode"`
	GrantRequiresAuditEntry        bool                 `json:"grant_requires_audit_entry"`
	OverrideThreshold              string               `json:"override_threshold"`
	CommutativeOperations          []uint32             `json:"commutative_operations"`
}

const credentialValidityPeriodNilSentinel = int64(-1)

// MarshalParameters produces canonical JSON bytes from a
// *types.SchemaParameters. Inverse of Extract.
//
// Round-trip invariant: for every valid p, Extract(Marshal(p))
// reflect-equals p. The round-trip test in
// parameters_json_roundtrip_test.go is the permanent regression
// gate on this property.
//
// Enum defaults (MigrationPolicy, ArtifactEncryption,
// GrantAuthorizationMode, OverrideThreshold) emit their canonical
// string form. CredentialValidityPeriod nil emits -1 sentinel
// (documented on marshalShape). PredecessorSchema and
// ReEncryptionThreshold emit JSON null when nil. CommutativeOperations
// emits [] when empty (never nil on the wire).
func MarshalParameters(p *types.SchemaParameters) ([]byte, error) {
	if p == nil {
		return nil, errors.New("schema/parameters_json: nil params")
	}
	shape := marshalShape{
		ActivationDelay:         int64(p.ActivationDelay / time.Second),
		CosignatureThreshold:    p.CosignatureThreshold,
		MaturationEpoch:         int64(p.MaturationEpoch / time.Second),
		OverrideRequiresWitness: p.OverrideRequiresIndependentWitness,
		GrantEntryRequired:      p.GrantEntryRequired,
		GrantRequiresAuditEntry: p.GrantRequiresAuditEntry,
	}

	if p.CredentialValidityPeriod == nil {
		shape.CredentialValidityPeriod = credentialValidityPeriodNilSentinel
	} else {
		shape.CredentialValidityPeriod = int64(*p.CredentialValidityPeriod / time.Second)
	}

	switch p.MigrationPolicy {
	case 0:
		// The MigrationPolicyType enum starts at 1. Zero means
		// "unset" — neither strict, forward, nor amendment was
		// declared. Emit an empty string; Extract interprets "" as
		// the same unset state so the round-trip holds.
		shape.MigrationPolicy = ""
	case types.MigrationStrict:
		shape.MigrationPolicy = "strict"
	case types.MigrationForward:
		shape.MigrationPolicy = "forward"
	case types.MigrationAmendment:
		shape.MigrationPolicy = "amendment"
	default:
		return nil, fmt.Errorf("schema/parameters_json: unknown MigrationPolicy %d", p.MigrationPolicy)
	}

	if p.PredecessorSchema != nil {
		shape.PredecessorSchema = &jsonLogPosition{
			LogDID:   p.PredecessorSchema.LogDID,
			Sequence: p.PredecessorSchema.Sequence,
		}
	}

	switch p.ArtifactEncryption {
	case types.EncryptionAESGCM:
		shape.ArtifactEncryption = "aes_gcm"
	case types.EncryptionUmbralPRE:
		shape.ArtifactEncryption = "umbral_pre"
	default:
		return nil, fmt.Errorf("schema/parameters_json: unknown ArtifactEncryption %d", p.ArtifactEncryption)
	}

	if p.ReEncryptionThreshold != nil {
		shape.ReEncryptionThreshold = &jsonThresholdConfig{
			M: p.ReEncryptionThreshold.M,
			N: p.ReEncryptionThreshold.N,
		}
	}

	switch p.GrantAuthorizationMode {
	case types.GrantAuthOpen:
		shape.GrantAuthorizationMode = "open"
	case types.GrantAuthRestricted:
		shape.GrantAuthorizationMode = "restricted"
	case types.GrantAuthSealed:
		shape.GrantAuthorizationMode = "sealed"
	default:
		return nil, fmt.Errorf("schema/parameters_json: unknown GrantAuthorizationMode %d", p.GrantAuthorizationMode)
	}

	switch p.OverrideThreshold {
	case types.ThresholdTwoThirdsMajority:
		shape.OverrideThreshold = "two_thirds"
	case types.ThresholdSimpleMajority:
		shape.OverrideThreshold = "simple_majority"
	case types.ThresholdUnanimity:
		shape.OverrideThreshold = "unanimity"
	default:
		return nil, fmt.Errorf("schema/parameters_json: unknown OverrideThreshold %d", p.OverrideThreshold)
	}

	// Always emit a non-nil slice so JSON output is "[]" not "null".
	// Keeps the wire format byte-stable between a freshly-constructed
	// empty schema and one whose CommutativeOperations was explicitly
	// [] in the input.
	if p.CommutativeOperations == nil {
		shape.CommutativeOperations = []uint32{}
	} else {
		shape.CommutativeOperations = append([]uint32{}, p.CommutativeOperations...)
	}

	return json.Marshal(&shape)
}
