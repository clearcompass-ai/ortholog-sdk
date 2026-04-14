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

The shardGenesisFields struct is a local copy of the operator's
ShardGenesisPayload — only the chain-linking fields. Field names and
JSON tags match exactly so json.Unmarshal works on operator-produced data.
*/
package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

// shardGenesisFields is the SDK-local copy of the operator's
// ShardGenesisPayload. Only chain-linking fields are included.
// JSON tags match the operator's lifecycle/shard_manager.go exactly.
type shardGenesisFields struct {
	PredecessorShard     string `json:"predecessor_shard"`
	PredecessorFinalHead string `json:"predecessor_final_head"`
	PredecessorFinalSize uint64 `json:"predecessor_final_size"`
	ChainPosition        int    `json:"chain_position"`
}

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
//  1. Parse genesis entry → extract shardGenesisFields
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
	genesis0, err := parseGenesisFields(shards[0].GenesisBytes)
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
		genesis, err := parseGenesisFields(shards[i].GenesisBytes)
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
	genesis, err := parseGenesisFields(genesisBytes)
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

func parseGenesisFields(data []byte) (*shardGenesisFields, error) {
	if len(data) == 0 {
		return nil, errors.New("empty genesis data")
	}
	var fields shardGenesisFields
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return &fields, nil
}

func breakChain(result *ShardChainResult, at int, err error) (*ShardChainResult, error) {
	result.Valid = false
	result.BrokenAt = at
	result.Error = err
	return result, err
}

// Suppress unused import.
var _ = sha256.Sum256
