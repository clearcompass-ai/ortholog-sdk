package types

import "time"

// MigrationPolicyType declares how schema succession is evaluated.
type MigrationPolicyType uint8

const (
	MigrationStrict    MigrationPolicyType = 1 // No backward compatibility
	MigrationForward   MigrationPolicyType = 2 // Forward migration only
	MigrationAmendment MigrationPolicyType = 3 // Amendment-based migration
)

// EncryptionScheme selects the artifact access control model.
// AES-256-GCM is ALWAYS storage encryption (permanent). This field selects
// the ACCESS CONTROL model on top.
//
//   - EncryptionAESGCM: exchange-mediated re-encryption (exchange sees plaintext
//     during re-encryption). Default for existing schemas.
//   - EncryptionUmbralPRE: M-of-N threshold proxy re-encryption with DLEQ proofs.
//     Exchange never sees plaintext.
//
// Builder NEVER reads this field (SDK-D6).
type EncryptionScheme int

const (
	EncryptionAESGCM    EncryptionScheme = iota // default
	EncryptionUmbralPRE                         // threshold PRE
)

// ThresholdConfig specifies M-of-N parameters for threshold operations.
// Used by ReEncryptionThreshold: same M-of-N escrow nodes as Shamir.
// nil for aes_gcm schemas.
type ThresholdConfig struct {
	M int
	N int
}

// SchemaParameters holds domain-visible parameters extracted from a schema's
// Domain Payload. Pure data type — no extraction logic here.
//
// The SchemaParameterExtractor interface (schema/parameters.go) produces this.
// Default JSON extractor implemented in Phase 4 (first consumer).
// Domain repos provide custom extractors for non-JSON payloads.
//
// Consumed by:
//   - Phase 4 verifier: key_rotation reads MaturationEpoch,
//     contest_override reads OverrideRequiresIndependentWitness,
//     schema_succession reads MigrationPolicy and PredecessorSchema
//   - Phase 5 condition_evaluator: reads ActivationDelay and CosignatureThreshold
//   - Phase 5 exchange/lifecycle/artifact_access.go: reads ArtifactEncryption,
//     GrantEntryRequired, ReEncryptionThreshold
//
// Builder NEVER reads the three operational fields (SDK-D6).
// One struct for now, split at 15 fields.
type SchemaParameters struct {
	// ── Protocol-mechanical (verifier + condition_evaluator) ──────────

	ActivationDelay                    time.Duration
	CosignatureThreshold               int
	MaturationEpoch                    time.Duration
	CredentialValidityPeriod           *time.Duration      // nil = no expiry
	OverrideRequiresIndependentWitness bool
	MigrationPolicy                    MigrationPolicyType
	PredecessorSchema                  *LogPosition        // nil = no predecessor

	// ── Operational — artifact access control ─────────────────────────
	// (exchange + domain, never builder or verifier)

	ArtifactEncryption    EncryptionScheme // aes_gcm | umbral_pre
	GrantEntryRequired    bool             // true -> publish grant commentary entries
	ReEncryptionThreshold *ThresholdConfig // nil for aes_gcm. Same M-of-N as Shamir.
}
