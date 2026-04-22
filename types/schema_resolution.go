// Package types — schema_resolution.go defines the contract types
// shared by the write path (builder) and the read path (verifier)
// for schema-parameter resolution.
//
// v7.5 relocated these from builder/ to types/ to close a cycle:
// builder now depends on schema (for MarshalParameters in
// BuildSchemaEntry), schema in turn produces SchemaResolution values
// consumed by builder. Keeping the contract types in types/ keeps
// schema unaware of builder.
//
// These are pure data contracts. No state, no behaviour.
package types

// SchemaResolver translates a Schema_Ref log position into schema
// parameters relevant to batch processing. Currently used to detect
// commutative-OCC schemas and their Δ-window size. The resolver
// deserializes the schema entry and extracts its parameters.
//
// A nil SchemaResolver is legal: ProcessBatch treats all entries as
// non-commutative (strict OCC) in that case. Commutative resolution
// requires a schema resolver to be wired in.
type SchemaResolver interface {
	Resolve(ref LogPosition, fetcher EntryFetcher) (*SchemaResolution, error)
}

// SchemaResolution is the subset of schema parameters the builder
// uses during batch processing. Additional fields (activation delay,
// cosignature threshold, etc.) are resolved by the verifier layer at
// read time, not here.
type SchemaResolution struct {
	// IsCommutative marks the schema as permitting Δ-window CRDT
	// resolution for Path C enforcement (SDK-D7). When true,
	// concurrent enforcement entries within the Δ-window are all
	// accepted; when false, OCC applies strict Prior_Authority
	// matching.
	IsCommutative bool

	// DeltaWindowSize is the per-schema Δ-window for commutative
	// OCC. Ignored when IsCommutative is false. Defaults to 10 when
	// the schema does not specify.
	DeltaWindowSize int
}
