package schema

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// SchemaParameterExtractor extracts domain-visible parameters from a schema's
// Domain Payload. The builder never calls this — it is consumed by:
//   - Phase 4 verifier: key_rotation reads MaturationEpoch,
//     contest_override reads OverrideRequiresIndependentWitness,
//     schema_succession reads MigrationPolicy and PredecessorSchema
//   - Phase 5 condition_evaluator: reads ActivationDelay and CosignatureThreshold
//
// Interface defined here (Phase 1D). Default JSON implementation arrives in Phase 4.
// Domain repos provide custom extractors for non-JSON payloads.
type SchemaParameterExtractor interface {
	Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error)
}
