// Package types — fetcher.go defines EntryFetcher, the read-side
// abstraction over positional entry lookup.
//
// Placed in the types/ package so both builder (write path) and
// verifier (read path) can depend on it without creating a cycle.
// Previously it lived in builder/ and was duplicated in verifier/;
// Decision 52 consolidates the definition here as part of the
// core/scope/ primitive layering.
package types

// EntryFetcher retrieves canonical bytes plus log metadata for an
// entry at a given log position.
//
// Implementations: operator's query layer in production (Postgres-
// backed HTTPEntryFetcher in log/), MockFetcher in tests.
//
// Returns (nil, nil) when the position has no entry — this is a
// normal outcome during chain walks (end of history, pruned branch,
// not-yet-materialized scope amendment) and MUST NOT be surfaced
// as an error. Returns a non-nil error only for transport or
// storage failures the caller should propagate.
type EntryFetcher interface {
	Fetch(pos LogPosition) (*EntryWithMetadata, error)
}
