/*
FILE PATH:
    types/entry_with_metadata.go

DESCRIPTION:
    The EntryWithMetadata type carries a canonical-bytes-plus-log-metadata
    view of a stored log entry. This is what EntryFetcher implementations
    return and what the builder, verifier, and lifecycle packages consume.

KEY ARCHITECTURAL DECISIONS:
    - Under v6 the SignatureAlgoID and SignatureBytes sidecar fields are
      removed. Signatures live inside CanonicalBytes (in the v6 signatures
      section) and are extracted via envelope.Deserialize when needed.
      This eliminates the redundancy between sidecar fields and canonical
      content, and removes a class of bugs where the sidecar and the
      canonical sigs could drift out of sync.
    - Callers that need the primary signature's algoID or bytes:
        entry, _ := envelope.Deserialize(meta.CanonicalBytes)
        algoID := entry.Signatures[0].AlgoID
        sigBytes := entry.Signatures[0].Bytes
      This costs one Deserialize call per access. If the access pattern
      is tight, callers should Deserialize once and cache the Entry.
    - The HTTP operator API (log/http_entry_fetcher.go) may still return
      sig_algo_id and signature_hex as JSON sidecar fields for
      human-readable diagnostics. The fetcher ignores them under v6 —
      CanonicalBytes is authoritative.

OVERVIEW:
    EntryWithMetadata is constructed by:
      - log/http_entry_fetcher.go Fetch (from operator HTTP response)
      - tests/helpers_test.go MockFetcher.Store (from an *envelope.Entry)
      - tests/cross_log_test.go mockEntryFetcher (test fixture)
      - tests/phase6_part_c_test.go newOperatorEntryServer (test fixture)

    EntryWithMetadata is consumed by:
      - types.EntryFetcher.Fetch callers (algorithm.go, entry_classification.go)
      - verifier.EntryFetcher.Fetch callers (condition_evaluator.go, delegation_tree.go)
      - lifecycle/recovery.go, scope_governance.go
      - core/smt/derivation_commitment.go (consumes CanonicalBytes as opaque)

KEY DEPENDENCIES:
    - time (standard library): LogTime field
    - types/log_position.go: LogPosition struct
*/
package types

import "time"

// -------------------------------------------------------------------------------------------------
// 1) EntryWithMetadata
// -------------------------------------------------------------------------------------------------

// EntryWithMetadata pairs a canonical entry's wire bytes with the log
// metadata the operator attaches at admission time.
//
// CanonicalBytes is the authoritative entry content. It deserializes via
// envelope.Deserialize to an *envelope.Entry carrying the header, payload,
// and signatures. The log's Merkle leaf hash is over these bytes.
//
// LogTime is the operator-asserted wall-clock time at admission. Distinct
// from Header.EventTime (the domain-asserted timestamp); the operator
// controls LogTime and the submitter controls EventTime.
//
// Position is the log position the entry was admitted at. Used for
// cross-entry references (TargetRoot, DelegationPointers, etc.) and for
// ordering during batch replay.
type EntryWithMetadata struct {
	CanonicalBytes []byte
	LogTime        time.Time
	Position       LogPosition
}
