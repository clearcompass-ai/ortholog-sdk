/*
Package builder — concurrency.go implements the delta-window authority history
buffer and optimistic concurrency control (OCC) verification for the SMT builder.

The DeltaWindowBuffer tracks recent Authority_Tip values per SMT leaf. It serves
two purposes:

 1. Strict OCC (default): Prior_Authority must exactly match the current
    Authority_Tip. Mismatch = rejection with exponential backoff.

 2. Commutative OCC (schema-declared): Prior_Authority must reference a state
    within the last N Authority_Tip values for the target leaf. Concurrent valid
    operations within the delta window are sorted lexicographically by entry hash
    before SMT update. This enables order-independent operations (parallel
    attestations, accumulating signatures) without serialization failures.

The buffer is builder working memory — not part of the SMT leaf, the log, or any
proof format. It is deterministic given the same log history: two operators
maintaining the buffer from the same log produce identical contents. The operator
persists it to Postgres between batches (builder/delta_buffer.go SaveTx) and
reconstructs it from ScanFromPosition if lost (SDK-D9: cold start = strict OCC).

Protocol references:
  - Decision 37: Commutative operations opt-in per schema, strict OCC default.
  - SDK-D7: Commutative_Operations is a boolean check (non-empty = delta-window).
  - SDK-D9: Cold-start delta-window buffer = strict OCC.
*/
package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// DeltaWindowBuffer — per-leaf authority tip history for OCC verification
// ─────────────────────────────────────────────────────────────────────────────

// DeltaWindowBuffer maintains the last N Authority_Tip values for each SMT leaf
// that received Path C updates. The window size is schema-configurable (default
// 10). The buffer is populated during ProcessBatch and persisted by the operator
// between batches.
//
// Thread safety: the buffer is accessed only by the single builder goroutine.
// No concurrent access. No mutex required.
type DeltaWindowBuffer struct {
	windowSize int
	history    map[[32]byte][]types.LogPosition
}

// NewDeltaWindowBuffer creates a buffer with the given window depth.
// Window size is clamped to a minimum of 1 (strict OCC equivalent).
// Default production value: 10.
func NewDeltaWindowBuffer(windowSize int) *DeltaWindowBuffer {
	if windowSize < 1 {
		windowSize = 10
	}
	return &DeltaWindowBuffer{
		windowSize: windowSize,
		history:    make(map[[32]byte][]types.LogPosition),
	}
}

// Record appends a new Authority_Tip to the leaf's history window.
// Called by updateAuthorityTip (path_compression.go) after each Path C update.
// Trims history to windowSize, retaining the most recent entries.
func (b *DeltaWindowBuffer) Record(leafKey [32]byte, tip types.LogPosition) {
	h := b.history[leafKey]
	h = append(h, tip)
	if len(h) > b.windowSize {
		h = h[len(h)-b.windowSize:]
	}
	b.history[leafKey] = h
}

// Contains checks whether a LogPosition exists within the leaf's history window.
// Used by verifyPriorAuthority for commutative OCC: the writer's Prior_Authority
// must reference a state within the window.
func (b *DeltaWindowBuffer) Contains(leafKey [32]byte, pos types.LogPosition) bool {
	for _, tip := range b.history[leafKey] {
		if tip.Equal(pos) {
			return true
		}
	}
	return false
}

// History returns the ordered tip history for a leaf. Returns nil if the leaf
// has no recorded history (cold start or non-Path-C leaf).
// Used by the operator's DeltaBufferStore.SaveTx for persistence.
func (b *DeltaWindowBuffer) History(leafKey [32]byte) []types.LogPosition {
	return b.history[leafKey]
}

// SetHistory loads a leaf's tip history from persisted state. Called by the
// operator's DeltaBufferStore.Load during startup to restore buffer state.
// Trims to windowSize if the persisted history exceeds the current window.
func (b *DeltaWindowBuffer) SetHistory(leafKey [32]byte, tips []types.LogPosition) {
	if len(tips) > b.windowSize {
		tips = tips[len(tips)-b.windowSize:]
	}
	b.history[leafKey] = tips
}

// AllKeys returns every leaf key that has recorded history in the buffer.
// Used by the operator's DeltaBufferStore.SaveTx to enumerate all leaves
// that need persistence. The returned slice is a snapshot — safe to iterate
// while the buffer is subsequently modified.
//
// Typical cardinality: under 100 active leaves per batch. The buffer only
// tracks leaves that received Path C updates, not all SMT leaves.
func (b *DeltaWindowBuffer) AllKeys() [][32]byte {
	keys := make([][32]byte, 0, len(b.history))
	for k := range b.history {
		keys = append(keys, k)
	}
	return keys
}

// WindowSize returns the configured window depth.
func (b *DeltaWindowBuffer) WindowSize() int {
	return b.windowSize
}

// Len returns the number of leaves with recorded history.
func (b *DeltaWindowBuffer) Len() int {
	return len(b.history)
}

// ─────────────────────────────────────────────────────────────────────────────
// OCC verification — Prior_Authority validation for Path C entries
// ─────────────────────────────────────────────────────────────────────────────

// verifyPriorAuthority validates the Prior_Authority field for a Path C entry
// against the target leaf's current Authority_Tip and the delta-window buffer.
//
// Three cases:
//
//  1. Authority_Tip == self (no prior enforcement): Prior_Authority must be nil.
//     This is the base case for a leaf that has never had a Path C update.
//
//  2. Schema declares commutative operations (SDK-D7): Prior_Authority must
//     reference either the current Authority_Tip or any position within the
//     delta window. Concurrent writers within the window are accepted.
//
//  3. Default (strict OCC): Prior_Authority must exactly match the current
//     Authority_Tip. Mismatch = rejection. Writers retry with exponential backoff.
//
// The function never reads Domain Payload (SDK-D6). It reads Schema_Ref from
// the Control Header to determine OCC mode via the SchemaResolver.
func verifyPriorAuthority(
	h *envelope.ControlHeader,
	targetRoot types.LogPosition,
	leaf *types.SMTLeaf,
	buffer *DeltaWindowBuffer,
	schemaRes SchemaResolver,
	fetcher EntryFetcher,
) error {
	currentTip := leaf.AuthorityTip

	// Case 1: leaf has never been enforced (Authority_Tip == self at creation).
	// Prior_Authority must be nil — there is no prior authority to reference.
	if currentTip.Equal(targetRoot) {
		if h.PriorAuthority != nil {
			return fmt.Errorf("Prior_Authority must be null when Authority_Tip == self")
		}
		return nil
	}

	// Authority_Tip != self → enforcement history exists. Prior_Authority required.
	if h.PriorAuthority == nil {
		return fmt.Errorf("Prior_Authority required when Authority_Tip != self")
	}

	// Determine OCC mode from schema (SDK-D7: boolean check on Commutative_Operations).
	isCommutative := false
	if h.SchemaRef != nil && schemaRes != nil {
		resolution, err := schemaRes.Resolve(*h.SchemaRef, fetcher)
		if err == nil && resolution != nil {
			isCommutative = resolution.IsCommutative
		}
		// Resolution failure → default to strict OCC (conservative).
	}

	// Case 2: commutative OCC — Prior_Authority within delta window.
	if isCommutative && buffer != nil {
		if h.PriorAuthority.Equal(currentTip) {
			return nil // Matches current tip — always valid.
		}
		if buffer.Contains(leaf.Key, *h.PriorAuthority) {
			return nil // Within delta window — concurrent operation accepted.
		}
		return fmt.Errorf(
			"commutative OCC: Prior_Authority %s not within delta window for leaf %x",
			h.PriorAuthority, leaf.Key[:8],
		)
	}

	// Case 3: strict OCC — exact match required.
	if !h.PriorAuthority.Equal(currentTip) {
		return fmt.Errorf(
			"strict OCC: Prior_Authority %s != current Authority_Tip %s",
			h.PriorAuthority, currentTip,
		)
	}
	return nil
}
