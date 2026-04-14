package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// DeltaWindowBuffer maintains per-leaf authority tip history for commutative OCC.
// Provided by the operator as input to ProcessBatch (Decision 26).
// Cold start: empty buffer = strict OCC (SDK-D9).
// Deterministic: two operators from the same log produce identical contents.
type DeltaWindowBuffer struct {
	windowSize int
	history    map[[32]byte][]types.LogPosition
}

// NewDeltaWindowBuffer creates a buffer with the given window size.
func NewDeltaWindowBuffer(windowSize int) *DeltaWindowBuffer {
	if windowSize < 1 {
		windowSize = 10
	}
	return &DeltaWindowBuffer{
		windowSize: windowSize,
		history:    make(map[[32]byte][]types.LogPosition),
	}
}

// Record adds a new Authority_Tip to the history for a leaf.
func (b *DeltaWindowBuffer) Record(leafKey [32]byte, tip types.LogPosition) {
	h := b.history[leafKey]
	h = append(h, tip)
	if len(h) > b.windowSize {
		h = h[len(h)-b.windowSize:]
	}
	b.history[leafKey] = h
}

// Contains checks if a position is within the delta window for a leaf.
func (b *DeltaWindowBuffer) Contains(leafKey [32]byte, pos types.LogPosition) bool {
	for _, tip := range b.history[leafKey] {
		if tip.Equal(pos) {
			return true
		}
	}
	return false
}

// History returns the tip history for a leaf.
func (b *DeltaWindowBuffer) History(leafKey [32]byte) []types.LogPosition {
	return b.history[leafKey]
}

// SetHistory sets the tip history for a leaf (deserialization/loading).
func (b *DeltaWindowBuffer) SetHistory(leafKey [32]byte, tips []types.LogPosition) {
	b.history[leafKey] = tips
}

// verifyPriorAuthority checks the OCC constraint for Path C entries.
//
// Self-referential check: if Authority_Tip still equals the root entity's
// own position (targetRoot), no prior enforcement exists and Prior_Authority
// must be null.
//
// For strict OCC: Prior_Authority must exactly equal current Authority_Tip.
// For commutative (SDK-D7): Prior_Authority within delta window.
// Cold start (SDK-D9): missing buffer = strict OCC.
func verifyPriorAuthority(
	h *envelope.ControlHeader,
	targetRoot types.LogPosition,
	leaf *types.SMTLeaf,
	buffer *DeltaWindowBuffer,
	schemaRes SchemaResolver,
	fetcher EntryFetcher,
) error {
	currentTip := leaf.AuthorityTip

	// Check if Authority_Tip == E_target itself (no prior enforcement).
	// At leaf initialization, Authority_Tip = root entity position.
	// If Authority_Tip still equals targetRoot, no Path C entry has modified it.
	if currentTip.Equal(targetRoot) {
		if h.PriorAuthority != nil {
			return fmt.Errorf("Prior_Authority must be null when Authority_Tip == self (no prior enforcement)")
		}
		return nil
	}

	// Prior authority exists — PriorAuthority is required.
	if h.PriorAuthority == nil {
		return fmt.Errorf("Prior_Authority required when Authority_Tip != self")
	}

	// Determine OCC mode from schema.
	isCommutative := false
	if h.SchemaRef != nil && schemaRes != nil {
		resolution, err := schemaRes.Resolve(*h.SchemaRef, fetcher)
		if err == nil && resolution != nil {
			isCommutative = resolution.IsCommutative
		}
		// Schema fetch failure -> default to strict OCC.
	}
	// Null Schema_Ref -> strict OCC (spec requirement).

	if isCommutative && buffer != nil {
		// Delta-window: Prior_Authority within last N tips OR equals current tip.
		if h.PriorAuthority.Equal(currentTip) || buffer.Contains(leaf.Key, *h.PriorAuthority) {
			return nil
		}
		return fmt.Errorf("commutative OCC: Prior_Authority %s not within delta window", h.PriorAuthority)
	}

	// Strict OCC: Prior_Authority must == current Authority_Tip exactly.
	if !h.PriorAuthority.Equal(currentTip) {
		return fmt.Errorf("strict OCC: Prior_Authority %s != current Authority_Tip %s",
			h.PriorAuthority, currentTip)
	}
	return nil
}
