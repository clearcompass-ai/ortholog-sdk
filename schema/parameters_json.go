/*
Package schema — parameters_json.go implements the default JSON-based
SchemaParameterExtractor.

Reads all 12 well-known fields from a schema entry's Domain Payload:
  activation_delay, cosignature_threshold, maturation_epoch,
  credential_validity_period, override_requires_witness, migration_policy,
  predecessor_schema, artifact_encryption, grant_entry_required,
  re_encryption_threshold, grant_authorization_mode,
  grant_requires_audit_entry.

Unknown fields are silently ignored (forward-compatible).
Missing artifact fields default to aes_gcm / false / nil.
Missing grant authorization fields default to open / false.
Every other Phase 5+ file consumes this.

KEY ARCHITECTURAL DECISIONS:
  - Domain Payload is opaque to builder (SDK-D6). Only verifiers and
    domain code read it.
  - Durations encoded as seconds (int64) in JSON.
  - MigrationPolicy as string: "strict", "forward", "amendment".
  - ArtifactEncryption as string: "aes_gcm", "umbral_pre".
  - GrantAuthorizationMode as string: "open", "restricted", "sealed".
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
	ActivationDelay          *int64              `json:"activation_delay"`
	CosignatureThreshold     *int                `json:"cosignature_threshold"`
	MaturationEpoch          *int64              `json:"maturation_epoch"`
	CredentialValidityPeriod *int64              `json:"credential_validity_period"`
	OverrideRequiresWitness  *bool               `json:"override_requires_witness"`
	MigrationPolicy          *string             `json:"migration_policy"`
	PredecessorSchema        *jsonLogPosition     `json:"predecessor_schema"`
	ArtifactEncryption       *string             `json:"artifact_encryption"`
	GrantEntryRequired       *bool               `json:"grant_entry_required"`
	ReEncryptionThreshold    *jsonThresholdConfig `json:"re_encryption_threshold"`

	// Phase 6 additions: grant authorization policy.
	// JSON string "open" | "restricted" | "sealed" → typed enum.
	// Same parsing pattern as artifact_encryption and migration_policy.
	GrantAuthorizationMode  *string `json:"grant_authorization_mode"`
	GrantRequiresAuditEntry *bool   `json:"grant_requires_audit_entry"`
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

// Extract reads all 12 well-known fields from the schema entry's Domain Payload.
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
		d := time.Duration(*raw.CredentialValidityPeriod) * time.Second
		params.CredentialValidityPeriod = &d
	}

	if raw.OverrideRequiresWitness != nil {
		params.OverrideRequiresIndependentWitness = *raw.OverrideRequiresWitness
	}

	if raw.MigrationPolicy != nil {
		switch *raw.MigrationPolicy {
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

	return params, nil
}
