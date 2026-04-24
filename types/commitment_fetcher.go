// Package types — commitment_fetcher.go declares the read-side
// abstraction over v7.75 commitment-entry lookup (ADR-005 §4, §6.2).
//
// The existing EntryFetcher in fetcher.go fetches by LogPosition; the
// commitment-entry lookup primitives in crypto/artifact and
// crypto/escrow need a complementary "query by SplitID" shape. Rather
// than force every caller of FetchPREGrantCommitment /
// FetchEscrowSplitCommitment to scan all positions, this interface
// defines the narrow contract operator query layers already satisfy
// via their indexing on commitment-schema entries.
//
// Placing the interface in types/ keeps crypto/artifact and
// crypto/escrow free of any import on log/ or any operator package —
// test fixtures and production implementations satisfy it via Go's
// structural typing.
package types

// CommitmentFetcher retrieves commitment-schema entries by the
// SplitID embedded in their payload. A single SplitID MUST match at
// most one non-equivocating commitment entry; a return slice with
// length > 1 indicates equivocation (the dealer published two
// distinct commitments for the same SplitID) which callers handle
// per ADR-005 §3.
//
// Schema IDs the SDK defines:
//
//   - "pre-grant-commitment-v1"
//   - "escrow-split-commitment-v1"
//
// Implementations MUST NOT filter or reorder matching entries — the
// caller's equivocation-detection logic relies on seeing every
// matching entry. Implementations MAY cap the result length (return
// the first N matches) as long as the cap is documented; callers
// that depend on exhaustive enumeration set the cap appropriately.
//
// Returns (nil, nil) when no entry matches — this is a normal
// outcome (the commitment has not yet been published or has been
// pruned). Returns a non-nil error only for transport or storage
// failures the caller should propagate.
type CommitmentFetcher interface {
	FindCommitmentEntries(schemaID string, splitID [32]byte) ([]*EntryWithMetadata, error)
}
