/*
Package verifier — schema_succession.go walks the predecessor_schema chain
from a pinned Schema_Ref.

Reads each predecessor's Domain Payload via SchemaParameterExtractor to get
migration_policy and predecessor_schema. Builds the full version history.
Evaluates migration compatibility between schema versions.

Migration policies:
  strict    — No cross-version references allowed.
  forward   — Newer schema can reference entries from older schema.
  amendment — Explicit per-entry migration required.

Consumed by:
  - onboarding/schema_adoption.go for compatibility checks
  - Builder: ensures pinned Schema_Ref returns correct parameters even
    when newer versions exist
  - Domain verification: validates that a credential issued under an
    older schema version is still valid under the current version

KEY ARCHITECTURAL DECISIONS:
  - Chain depth capped at 100 (prevents infinite loops from corrupt data).
  - Each SchemaVersion includes the extracted parameters and position.
  - Migration compatibility is evaluated pairwise (newer → older).
  - The SchemaChain is ordered oldest-first (SchemaVersions[0] is the
    original schema, SchemaVersions[len-1] is the most recent).
*/
package verifier

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// SchemaVersion describes one version in a schema succession chain.
type SchemaVersion struct {
	// Position is the LogPosition of this schema entry.
	Position types.LogPosition

	// Parameters is the extracted schema parameters from Domain Payload.
	Parameters *types.SchemaParameters

	// Entry is the deserialized schema entry.
	Entry *envelope.Entry

	// ChainIndex is the 0-based index in the chain (0 = oldest/root).
	ChainIndex int
}

// SchemaChain is the full version history of a schema, oldest first.
type SchemaChain struct {
	// Versions is the ordered list of schema versions, oldest first.
	// Versions[0] is the root schema (no predecessor).
	// Versions[len-1] is the pinned schema (where the walk started).
	Versions []SchemaVersion

	// MigrationPolicy is the effective migration policy of the pinned
	// (most recent) schema version. One of "strict", "forward", "amendment".
	MigrationPolicy string
}

// MigrationResult describes whether a reference from one schema version
// to another is allowed under the migration policy.
type MigrationResult struct {
	Allowed bool
	Policy  string
	Reason  string
}

// Errors.
var (
	ErrSchemaNotFound      = errors.New("verifier/schema: schema entry not found")
	ErrSchemaDeserialize   = errors.New("verifier/schema: failed to deserialize schema entry")
	ErrSchemaExtract       = errors.New("verifier/schema: failed to extract schema parameters")
	ErrSchemaChainTooDeep  = errors.New("verifier/schema: predecessor chain exceeds maximum depth")
	ErrSchemaCycle         = errors.New("verifier/schema: cycle detected in predecessor chain")
)

// maxSchemaChainDepth prevents infinite loops.
const maxSchemaChainDepth = 100

// ─────────────────────────────────────────────────────────────────────
// WalkSchemaChain — build full version history
// ─────────────────────────────────────────────────────────────────────

// WalkSchemaChain walks the predecessor_schema chain from a pinned
// Schema_Ref and builds the full version history.
//
// The walk starts at the pinned position and follows predecessor_schema
// pointers backward until a schema with no predecessor is found (the
// root schema). The result is ordered oldest-first.
//
// Each schema's Domain Payload is read via the SchemaParameterExtractor
// to extract migration_policy and predecessor_schema.
func WalkSchemaChain(
	pinnedRef types.LogPosition,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*SchemaChain, error) {
	if extractor == nil {
		return nil, fmt.Errorf("verifier/schema: nil extractor")
	}

	// Walk backward from pinned position, collecting versions.
	var versions []SchemaVersion
	current := pinnedRef
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < maxSchemaChainDepth; depth++ {
		if visited[current] {
			return nil, fmt.Errorf("%w at %s", ErrSchemaCycle, current)
		}
		visited[current] = true

		// Fetch the schema entry.
		meta, err := fetcher.Fetch(current)
		if err != nil {
			return nil, fmt.Errorf("%w: fetch %s: %v", ErrSchemaNotFound, current, err)
		}
		if meta == nil {
			return nil, fmt.Errorf("%w: %s", ErrSchemaNotFound, current)
		}

		// Deserialize.
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrSchemaDeserialize, current, err)
		}

		// Extract parameters.
		params, err := extractor.Extract(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrSchemaExtract, current, err)
		}

		versions = append(versions, SchemaVersion{
			Position:   current,
			Parameters: params,
			Entry:      entry,
		})

		// Follow predecessor chain.
		if params.PredecessorSchema == nil {
			break // Root schema — no predecessor.
		}
		current = *params.PredecessorSchema
	}

	if len(versions) >= maxSchemaChainDepth {
		return nil, ErrSchemaChainTooDeep
	}

	// Reverse: make oldest first.
	for i, j := 0, len(versions)-1; i < j; i, j = i+1, j-1 {
		versions[i], versions[j] = versions[j], versions[i]
	}

	// Set chain indices.
	for i := range versions {
		versions[i].ChainIndex = i
	}

	// Determine effective migration policy from the pinned (newest) version.
	effectivePolicy := "strict" // Default.
	if len(versions) > 0 {
		newest := versions[len(versions)-1]
		if newest.Parameters != nil {
			effectivePolicy = migrationPolicyString(newest.Parameters.MigrationPolicy)
		}
	}

	return &SchemaChain{
		Versions:        versions,
		MigrationPolicy: effectivePolicy,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// EvaluateMigration — compatibility check between two versions
// ─────────────────────────────────────────────────────────────────────

// EvaluateMigration checks whether a reference from an entry governed
// by sourceSchema to an entry governed by targetSchema is allowed.
//
// Rules:
//   strict    — References only allowed within the same schema version.
//   forward   — Newer schema can reference entries from older versions
//              (source.ChainIndex >= target.ChainIndex).
//   amendment — Cross-version references require explicit per-entry
//              migration. Returns Allowed=true but includes the reason
//              "amendment_required".
func EvaluateMigration(chain *SchemaChain, sourcePos, targetPos types.LogPosition) *MigrationResult {
	if chain == nil || len(chain.Versions) == 0 {
		return &MigrationResult{
			Allowed: false,
			Policy:  "unknown",
			Reason:  "no schema chain available",
		}
	}

	// Find source and target in the chain.
	sourceIdx := -1
	targetIdx := -1
	for _, v := range chain.Versions {
		if v.Position.Equal(sourcePos) {
			sourceIdx = v.ChainIndex
		}
		if v.Position.Equal(targetPos) {
			targetIdx = v.ChainIndex
		}
	}

	if sourceIdx == -1 || targetIdx == -1 {
		return &MigrationResult{
			Allowed: false,
			Policy:  chain.MigrationPolicy,
			Reason:  "schema version not found in chain",
		}
	}

	if sourceIdx == targetIdx {
		// Same version — always allowed.
		return &MigrationResult{
			Allowed: true,
			Policy:  chain.MigrationPolicy,
			Reason:  "same version",
		}
	}

	switch chain.MigrationPolicy {
	case "strict":
		return &MigrationResult{
			Allowed: false,
			Policy:  "strict",
			Reason:  "cross-version references not allowed under strict policy",
		}

	case "forward":
		// Newer can reference older.
		if sourceIdx > targetIdx {
			return &MigrationResult{
				Allowed: true,
				Policy:  "forward",
				Reason:  "newer schema referencing older version",
			}
		}
		return &MigrationResult{
			Allowed: false,
			Policy:  "forward",
			Reason:  "older schema cannot reference newer version",
		}

	case "amendment":
		return &MigrationResult{
			Allowed: true,
			Policy:  "amendment",
			Reason:  "amendment_required",
		}

	default:
		return &MigrationResult{
			Allowed: false,
			Policy:  chain.MigrationPolicy,
			Reason:  "unknown migration policy",
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// migrationPolicyString converts a MigrationPolicyType to its string
// representation used in JSON and the SchemaChain result.
func migrationPolicyString(p types.MigrationPolicyType) string {
	switch p {
	case types.MigrationStrict:
		return "strict"
	case types.MigrationForward:
		return "forward"
	case types.MigrationAmendment:
		return "amendment"
	default:
		return "strict"
	}
}
