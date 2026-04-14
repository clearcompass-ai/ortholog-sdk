// Package log defines the operator query interfaces.
// Pure type definitions. No implementations.
// Phase 2 (operator) implements in Postgres. Phase 5 provides in-memory reference impls.
package log

import "github.com/clearcompass-ai/ortholog-sdk/types"

// OperatorQueryAPI defines the 5 query interfaces that log operators must implement.
// The CosignatureOf index is certification-required per spec.
// The other 4 indexes are recommended and implemented from day one.
type OperatorQueryAPI interface {
	// QueryByCosignatureOf returns all entries whose Cosignature_Of field
	// matches the given position. Certification-required per spec.
	// Primary consumer: exchange lifecycle compiling Evidence_Pointers
	// to discover cosignature arrivals during the three-phase lifecycle.
	QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)

	// QueryByTargetRoot returns all entries targeting a specific root entity.
	// For case history, enforcement chain walking, delegation tree construction.
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)

	// QueryBySignerDID returns all entries signed by a specific DID.
	// For officer audit, compliance monitoring, delegation tree reading.
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)

	// QueryBySchemaRef returns all entries governed by a specific schema.
	// For schema migration evaluation, domain monitoring.
	QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error)

	// ScanFromPosition returns entries sequentially starting from a position.
	// For monitoring, load accounting, mirror consistency, settlement tallies,
	// delta-window buffer reconstruction after cold start.
	// Returns entries in strict log sequence order.
	// Pagination: caller advances startPos to last returned sequence + 1.
	ScanFromPosition(startPos uint64, count int) ([]types.EntryWithMetadata, error)
}
