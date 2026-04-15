/*
verifier/shard_chain_verifier.go — Shard chain integrity verification.

Operators shard logs when they reach a configured size. Each shard's
genesis entry (position 0) contains a pointer to its predecessor:

  shard₀ (genesis)  → no predecessor
  shard₁ (genesis)  → predecessor: shard₀, final_size, final_head_hash
  shard₂ (genesis)  → predecessor: shard₁, final_size, final_head_hash

VerifyShardChain walks the chain and checks that every link is consistent:
  - Each shard's genesis references the correct predecessor
  - Predecessor final size matches
  - Chain positions are sequential

The genesis payload type is defined in schema/shard_genesis.go as
ShardGenesisPayload — the canonical type shared between the verifier
(consumer) and the operator's shard_manager.go (producer).
*/
package verifier

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var ErrShardChainBroken = errors.New("verifier/shard: chain broken")
var ErrShardGenesisParse = errors.New("verifier/shard: genesis parse failed")
var ErrShardChainEmpty = errors.New("verifier/shard: empty shard chain")

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// ShardInfo describes one shard in a chain.
type ShardInfo struct {
	// ShardID is the unique identifier for this shard (e.g., "shard-0000").
	ShardID string

	// GenesisBytes is the canonical bytes of the genesis entry (position 0).
	GenesisBytes []byte

	// FinalHead is the last cosigned tree head of this shard.
	FinalHead types.CosignedTreeHead

	// FinalSize is the total number of entries in this shard.
	FinalSize uint64
}

// ShardChainResult is the outcome of chain verification.
type ShardChainResult struct {
	ChainLength int
	FirstShard  string
	LastShard   string
	Valid       bool
	BrokenAt    int // -1 if valid, otherwise the index of the first broken link.
	Error       error
}

// ─────────────────────────────────────────────────────────────────────
// VerifyShardChain
// ─────────────────────────────────────────────────────────────────────

// VerifyShardChain verifies the integrity of a shard chain.
//
// For each shard after the first:
//  1. Parse genesis entry → extract ShardGenesisPayload
//  2. genesis.PredecessorShard must match shards[i-1].ShardID
//  3. genesis.PredecessorFinalSize must match shards[i-1].FinalSize
//  4. genesis.PredecessorFinalHead must match hash of shards[i-1].FinalHead
//  5. genesis.ChainPosition must equal i
//
// The first shard (index 0) must have ChainPosition=0 and no predecessor.
func VerifyShardChain(shards []ShardInfo) (*ShardChainResult, error) {
	if len(shards) == 0 {
		return nil, ErrShardChainEmpty
	}

	result := &ShardChainResult{
		ChainLength: len(shards),
		FirstShard:  shards[0].ShardID,
		LastShard:   shards[len(shards)-1].ShardID,
		Valid:       true,
		BrokenAt:    -1,
	}

	// Verify first shard genesis.
	genesis0, err := parseGenesis(shards[0].GenesisBytes)
	if err != nil {
		return breakChain(result, 0, fmt.Errorf("%w at shard 0: %v", ErrShardGenesisParse, err))
	}
	if genesis0.ChainPosition != 0 {
		return breakChain(result, 0, fmt.Errorf("%w at shard 0: chain_position=%d, want 0",
			ErrShardChainBroken, genesis0.ChainPosition))
	}
	if genesis0.PredecessorShard != "" {
		return breakChain(result, 0, fmt.Errorf("%w at shard 0: has predecessor %q",
			ErrShardChainBroken, genesis0.PredecessorShard))
	}

	// Verify subsequent shards.
	for i := 1; i < len(shards); i++ {
		genesis, err := parseGenesis(shards[i].GenesisBytes)
		if err != nil {
			return breakChain(result, i, fmt.Errorf("%w at shard %d: %v", ErrShardGenesisParse, i, err))
		}

		prev := shards[i-1]

		// Check predecessor shard ID.
		if genesis.PredecessorShard != prev.ShardID {
			return breakChain(result, i, fmt.Errorf(
				"%w at shard %d: predecessor=%q, want %q",
				ErrShardChainBroken, i, genesis.PredecessorShard, prev.ShardID))
		}

		// Check predecessor final size.
		if genesis.PredecessorFinalSize != prev.FinalSize {
			return breakChain(result, i, fmt.Errorf(
				"%w at shard %d: predecessor_final_size=%d, want %d",
				ErrShardChainBroken, i, genesis.PredecessorFinalSize, prev.FinalSize))
		}

		// Check predecessor final head hash.
		expectedHeadHash := TreeHeadHash(prev.FinalHead.TreeHead)
		expectedHex := hex.EncodeToString(expectedHeadHash[:])
		if genesis.PredecessorFinalHead != expectedHex {
			return breakChain(result, i, fmt.Errorf(
				"%w at shard %d: predecessor_final_head mismatch",
				ErrShardChainBroken, i))
		}

		// Check chain position.
		if genesis.ChainPosition != i {
			return breakChain(result, i, fmt.Errorf(
				"%w at shard %d: chain_position=%d, want %d",
				ErrShardChainBroken, i, genesis.ChainPosition, i))
		}
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// VerifyShardGenesis — verify a single shard's genesis against predecessor
// ─────────────────────────────────────────────────────────────────────

// VerifyShardGenesis checks that a shard's genesis entry correctly
// references its predecessor. Useful when verifying a single shard
// transition without the full chain.
func VerifyShardGenesis(
	genesisBytes []byte,
	expectedPredecessor string,
	expectedFinalSize uint64,
	expectedFinalHead types.TreeHead,
) error {
	genesis, err := parseGenesis(genesisBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShardGenesisParse, err)
	}

	if genesis.PredecessorShard != expectedPredecessor {
		return fmt.Errorf("%w: predecessor=%q, want %q",
			ErrShardChainBroken, genesis.PredecessorShard, expectedPredecessor)
	}

	if genesis.PredecessorFinalSize != expectedFinalSize {
		return fmt.Errorf("%w: predecessor_final_size=%d, want %d",
			ErrShardChainBroken, genesis.PredecessorFinalSize, expectedFinalSize)
	}

	expectedHash := TreeHeadHash(expectedFinalHead)
	expectedHex := hex.EncodeToString(expectedHash[:])
	if genesis.PredecessorFinalHead != expectedHex {
		return fmt.Errorf("%w: predecessor_final_head mismatch", ErrShardChainBroken)
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────

// parseGenesis delegates to the canonical parser in schema/shard_genesis.go.
// Wraps the error with verifier-specific context.
func parseGenesis(data []byte) (*schema.ShardGenesisPayload, error) {
	payload, err := schema.ParseShardGenesisPayload(data)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func breakChain(result *ShardChainResult, at int, err error) (*ShardChainResult, error) {
	result.Valid = false
	result.BrokenAt = at
	result.Error = err
	return result, err
}
