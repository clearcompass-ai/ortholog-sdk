package builder

import (
	"fmt"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type DeltaWindowBuffer struct {
	windowSize int
	history    map[[32]byte][]types.LogPosition
}

func NewDeltaWindowBuffer(windowSize int) *DeltaWindowBuffer {
	if windowSize < 1 { windowSize = 10 }
	return &DeltaWindowBuffer{windowSize: windowSize, history: make(map[[32]byte][]types.LogPosition)}
}

func (b *DeltaWindowBuffer) Record(leafKey [32]byte, tip types.LogPosition) {
	h := b.history[leafKey]; h = append(h, tip)
	if len(h) > b.windowSize { h = h[len(h)-b.windowSize:] }
	b.history[leafKey] = h
}

func (b *DeltaWindowBuffer) Contains(leafKey [32]byte, pos types.LogPosition) bool {
	for _, tip := range b.history[leafKey] { if tip.Equal(pos) { return true } }
	return false
}

func (b *DeltaWindowBuffer) History(leafKey [32]byte) []types.LogPosition { return b.history[leafKey] }
func (b *DeltaWindowBuffer) SetHistory(leafKey [32]byte, tips []types.LogPosition) { b.history[leafKey] = tips }

func verifyPriorAuthority(h *envelope.ControlHeader, targetRoot types.LogPosition, leaf *types.SMTLeaf, buffer *DeltaWindowBuffer, schemaRes SchemaResolver, fetcher EntryFetcher) error {
	currentTip := leaf.AuthorityTip
	if currentTip.Equal(targetRoot) {
		if h.PriorAuthority != nil { return fmt.Errorf("Prior_Authority must be null when Authority_Tip == self") }
		return nil
	}
	if h.PriorAuthority == nil { return fmt.Errorf("Prior_Authority required when Authority_Tip != self") }
	isCommutative := false
	if h.SchemaRef != nil && schemaRes != nil {
		resolution, err := schemaRes.Resolve(*h.SchemaRef, fetcher)
		if err == nil && resolution != nil { isCommutative = resolution.IsCommutative }
	}
	if isCommutative && buffer != nil {
		if h.PriorAuthority.Equal(currentTip) || buffer.Contains(leaf.Key, *h.PriorAuthority) { return nil }
		return fmt.Errorf("commutative OCC: Prior_Authority %s not within delta window", h.PriorAuthority)
	}
	if !h.PriorAuthority.Equal(currentTip) {
		return fmt.Errorf("strict OCC: Prior_Authority %s != current Authority_Tip %s", h.PriorAuthority, currentTip)
	}
	return nil
}
