/*
Package builder — api.go is the public entry point for batch processing.

ProcessBatch is the one function domain applications call to advance the
SMT state. Given a set of entries and their log positions, it:

 1. Iterates each entry through processEntry (builder/algorithm.go), which
    dispatches to the appropriate path processor (A / B / C / commentary /
    new leaf) and advances the SMT leaves.

 2. Tallies results by classification bucket (PathA, PathB, PathC,
    Commentary, NewLeaf, PathD, Rejected). The operator uses these
    counts for observability and the OCC retry wrapper uses
    RejectedCounts to decide whether to back off and retry.

 3. Collects the mutation record from the SMT tree and computes the new
    root. The mutation set is what the operator persists to its storage
    layer in a single transaction with the root update.

Determinism. ProcessBatch is deterministic — two invocations over the same
tree state with the same entries in the same order produce identical
mutations and identical roots. This is the property that lets derivation
commitments be replayed and fraud-proved (verifier/fraud_proofs.go).

Error model. Individual entry failures are captured as path classifications
(PathD or Rejected), not returned as errors. A returned error from
ProcessBatch indicates a fatal condition for the whole batch — malformed
inputs, tree corruption, or root computation failure. In these cases the
partial tree state from any entries already processed is still committed
to the tree; callers treat a non-nil error as "this batch cannot be
trusted, do not publish the root."

Structural-error opacity. The per-entry errors from processEntry
(ErrTipRegression, ErrIntermediateForeign, ErrIntermediateNotFound, and
others) are currently collapsed into PathResultPathD for counting purposes.
Operators that need per-entry failure reasons should classify entries
through ClassifyBatch (builder/entry_classification.go) before submitting
to ProcessBatch.

Consumed by:
  - ortholog-operator/builder/loop.go (primary caller, via ProcessWithRetry)
  - lifecycle/scope_governance.go (in-process amendment execution)
  - lifecycle/recovery.go (in-process recovery execution)
  - verifier/fraud_proofs.go (commitment replay)
  - tests/* (determinism tests, integration tests)
*/
package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────

// EntryFetcher retrieves canonical-bytes + metadata for an entry at a
// given log position. Satisfied by the operator's query layer
// (Postgres-backed) in production and by MockFetcher in tests.
//
// Returns (nil, nil) when the position has no entry — this is a normal
// outcome during chain walks, not an error. Returns a non-nil error
// only for transport or storage failures the caller should propagate.
type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// SchemaResolver translates a Schema_Ref log position into schema
// parameters relevant to batch processing. Currently used to detect
// commutative-OCC schemas and their Δ-window size. The resolver
// deserializes the schema entry and extracts its parameters
// (schema.JSONParameterExtractor is the reference implementation).
//
// A nil SchemaResolver is legal: ProcessBatch treats all entries as
// non-commutative (strict OCC) in that case. Commutative resolution
// requires a schema resolver to be wired in.
type SchemaResolver interface {
	Resolve(ref types.LogPosition, fetcher EntryFetcher) (*SchemaResolution, error)
}

// SchemaResolution is the subset of schema parameters the builder uses
// during batch processing. Additional fields (activation delay,
// cosignature threshold, etc.) are resolved by the verifier layer at
// read time, not here.
type SchemaResolution struct {
	// IsCommutative marks the schema as permitting Δ-window CRDT
	// resolution for Path C enforcement (SDK-D7). When true, concurrent
	// enforcement entries within the Δ-window are all accepted; when
	// false, OCC applies strict Prior_Authority matching.
	IsCommutative bool

	// DeltaWindowSize is the per-schema Δ-window for commutative OCC.
	// Ignored when IsCommutative is false. Defaults to 10 when the
	// schema does not specify.
	DeltaWindowSize int
}

// ─────────────────────────────────────────────────────────────────────
// Path classification
// ─────────────────────────────────────────────────────────────────────

// PathResult is the classification assigned to an entry after processing.
// Every entry lands in exactly one bucket. The operator persists the
// classification alongside the entry for audit and query purposes.
type PathResult uint8

const (
	// PathResultCommentary — zero SMT impact. Entry has no TargetRoot
	// and no AuthorityPath (pure commentary, cosignatures, anchors,
	// mirrors, recovery requests).
	PathResultCommentary PathResult = iota

	// PathResultNewLeaf — entry creates a new SMT leaf. Entry has no
	// TargetRoot but has AuthorityPath (root entities, scope entities,
	// schemas, delegations).
	PathResultNewLeaf

	// PathResultPathA — same-signer amendment. Signer_DID matches the
	// target entity's signer. Advances OriginTip.
	PathResultPathA

	// PathResultPathB — delegated authority. Delegation chain connects
	// signer to target entity through up to 3 hops. Advances OriginTip.
	PathResultPathB

	// PathResultPathC — scope authority. Signer is a member of the
	// governing scope's AuthoritySet. Advances AuthorityTip for
	// enforcement entries; advances OriginTip for scope amendments.
	PathResultPathC

	// PathResultPathD — entry failed to qualify for Paths A, B, or C.
	// The SMT is not modified. The entry is retained in the log but
	// has no state-advancing effect. Common reasons: foreign log
	// reference, missing target, authority mismatch, stale OCC.
	PathResultPathD

	// PathResultRejected — entry violated a structural invariant that
	// makes it invalid under any path. Distinct from PathD: rejection
	// means the entry should not have been admitted to the log in the
	// first place. Operators use this to flag anomalies. Common reasons:
	// evidence pointer cap exceeded on non-snapshot, delegation cycle,
	// approval pointer not in authority set.
	PathResultRejected
)

// ─────────────────────────────────────────────────────────────────────
// BatchResult — the per-batch output
// ─────────────────────────────────────────────────────────────────────

// BatchResult is the complete outcome of a ProcessBatch call. The
// operator commits BatchResult atomically: mutations to the leaf table,
// NewRoot to the tree-head table, and UpdatedBuffer to the delta
// window table in one transaction.
type BatchResult struct {
	// NewRoot is the SMT root after all entries in the batch have been
	// processed. Deterministic for a given (prior root, entries) pair.
	NewRoot [32]byte

	// Mutations is the ordered list of leaf changes the SMT produced.
	// Each mutation records the leaf key, old tips, and new tips. The
	// verifier replays this list to construct fraud proofs.
	Mutations []types.LeafMutation

	// Path counts — one entry contributes to exactly one bucket.
	// The sum of all counts equals len(entries).
	PathACounts      int
	PathBCounts      int
	PathCCounts      int
	PathDCounts      int
	CommentaryCounts int
	NewLeafCounts    int
	RejectedCounts   int

	// UpdatedBuffer is the DeltaWindowBuffer after all Path C
	// authority-tip advances have been recorded. The operator persists
	// this between batches so commutative OCC can detect Δ-window
	// misses across batch boundaries.
	UpdatedBuffer *DeltaWindowBuffer
}

// ─────────────────────────────────────────────────────────────────────
// ProcessBatch
// ─────────────────────────────────────────────────────────────────────

// ProcessBatch advances SMT state for a list of entries.
//
// Arguments:
//
//   - tree:         the SMT to mutate. The tree's LeafStore supplies
//     current leaf state; ProcessBatch reads and writes
//     through this tree.
//   - entries:      entries to process in order. An empty slice is
//     valid and produces an empty BatchResult with the
//     tree's current root.
//   - positions:    log positions for each entry. positions[i] is
//     where entries[i] appears in the log. len(entries)
//     must equal len(positions) — mismatch is a
//     programming error and returns a fatal error.
//   - fetcher:      reads foreign entries referenced by TargetRoot,
//     DelegationPointers, ApprovalPointers, etc. A
//     non-nil fetcher is required even when entries
//     reference only local positions — the fetcher may
//     be queried during classification.
//   - schemaRes:    optional. When non-nil, enables commutative OCC
//     resolution for schemas that declare it. When nil,
//     all entries use strict OCC.
//   - localLogDID:  the DID of the log owning this batch. Entries
//     referencing foreign logs are classified as PathD
//     (locality enforcement per Decision 47).
//   - deltaBuffer:  the delta-window state carried over from the
//     previous batch. A nil buffer is replaced with a
//     fresh 10-slot buffer; pass a sized buffer to match
//     the operator's schema-declared window.
//
// Returns:
//
//   - *BatchResult: the full outcome. Never nil on successful return.
//   - error:        non-nil only on fatal batch-level failure (length
//     mismatch between entries and positions, or tree
//     root computation failure). Per-entry failures
//     surface as PathResultPathD or PathResultRejected,
//     not as errors.
//
// Determinism contract. For the same (tree state, entries, positions,
// schemaRes behavior, deltaBuffer) inputs, ProcessBatch produces
// identical NewRoot and Mutations output. This property is load-bearing
// for derivation commitments and fraud proofs; any change that breaks
// determinism (map iteration order leaking into hashes, wall-clock
// dependencies, non-deterministic fetcher behavior) is a bug.
//
// Partial-batch behavior. ProcessBatch is not transactional across
// entries. If entry i succeeds and entry j (j > i) hits a tree-mutation
// failure in its apply phase, entry i's mutations remain committed in
// the tree. The compute-then-apply pattern in algorithm.go prevents
// partial mutations within a single entry but does not roll back prior
// entries in the batch. Callers requiring all-or-nothing semantics
// should process entries one at a time or use an operator-level
// transaction wrapper.
func ProcessBatch(
	tree *smt.Tree,
	entries []*envelope.Entry,
	positions []types.LogPosition,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (*BatchResult, error) {
	// ─── Input validation ──────────────────────────────────────────
	//
	// A length mismatch between entries and positions is a caller
	// programming error. Returning an error (rather than panicking on
	// the subsequent index expression) gives the caller a useful
	// diagnostic.
	if len(entries) != len(positions) {
		return nil, fmt.Errorf(
			"builder: entries length %d != positions length %d",
			len(entries), len(positions),
		)
	}

	// A nil delta buffer is legal — callers who don't care about
	// commutative OCC pass nil. We substitute a default-sized buffer
	// so the path processors can always call buffer.Record without
	// a nil check. The 10-slot default matches the protocol's
	// reference Δ-window size.
	if deltaBuffer == nil {
		deltaBuffer = NewDeltaWindowBuffer(10)
	}

	// ─── Mutation tracking ─────────────────────────────────────────
	//
	// StartTracking asks the SMT to record every leaf mutation from
	// this point forward. StopTracking returns the recorded list and
	// disables tracking. The tracking window must wrap the entire
	// batch processing loop — partial tracking would miss mutations
	// and corrupt fraud-proof replay.
	tree.StartTracking()

	result := &BatchResult{}

	// ─── Per-entry processing loop ─────────────────────────────────
	//
	// Each entry goes through processEntry, which classifies and
	// (for A/B/C/NewLeaf) mutates the SMT via the compute-then-apply
	// pipeline in path_compression.go.
	//
	// Errors from processEntry are collapsed to PathResultPathD for
	// tallying. The distinction between "legitimately classified as
	// PathD" and "hit a validation error (tip regression, foreign
	// intermediate, missing intermediate)" is lost here. Operators
	// needing per-entry failure reasons should pre-classify via
	// ClassifyBatch, which returns structured Classification results
	// including the Reason string.
	for i, entry := range entries {
		pos := positions[i]
		pathResult, err := processEntry(
			tree, entry, pos,
			fetcher, schemaRes,
			localLogDID, deltaBuffer,
		)
		if err != nil {
			// Structural validation error — count as PathD. The tree
			// mutation pipeline guarantees no partial SMT state from
			// this entry (compute-then-apply semantics).
			pathResult = PathResultPathD
		}

		switch pathResult {
		case PathResultCommentary:
			result.CommentaryCounts++
		case PathResultNewLeaf:
			result.NewLeafCounts++
		case PathResultPathA:
			result.PathACounts++
		case PathResultPathB:
			result.PathBCounts++
		case PathResultPathC:
			result.PathCCounts++
		case PathResultPathD:
			result.PathDCounts++
		case PathResultRejected:
			result.RejectedCounts++
		}
	}

	// ─── Capture tracked mutations ─────────────────────────────────
	//
	// StopTracking returns the ordered list of (leaf_key, old_tips,
	// new_tips) triples collected during the batch. This list IS the
	// state transition — the operator persists it alongside NewRoot
	// in a single transaction, and the verifier uses it to replay
	// and fraud-prove the batch.
	result.Mutations = tree.StopTracking()

	// ─── Compute new root ──────────────────────────────────────────
	//
	// A root computation failure is fatal for the batch: we have
	// mutations committed in the tree, but we cannot report a trusted
	// root back to the caller. The caller should treat this as
	// "rollback the entire batch" — don't publish the partial tree.
	root, err := tree.Root()
	if err != nil {
		return nil, fmt.Errorf("builder: compute batch root: %w", err)
	}
	result.NewRoot = root

	// The updated buffer flows back to the caller. The operator
	// persists it so the next batch's commutative-OCC checks see
	// mutations from this batch within the Δ-window.
	result.UpdatedBuffer = deltaBuffer

	return result, nil
}
