package types

import "time"

// MigrationPolicyType declares how schema succession is evaluated.
type MigrationPolicyType uint8

const (
	MigrationStrict    MigrationPolicyType = 1 // No backward compatibility
	MigrationForward   MigrationPolicyType = 2 // Forward migration only
	MigrationAmendment MigrationPolicyType = 3 // Amendment-based migration
)

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
type SchemaParameters struct {
	ActivationDelay                    time.Duration
	CosignatureThreshold               int
	MaturationEpoch                    time.Duration
	CredentialValidityPeriod           *time.Duration  // nil = no expiry
	OverrideRequiresIndependentWitness bool
	MigrationPolicy                    MigrationPolicyType
	PredecessorSchema                  *LogPosition    // nil = no predecessor
}
