package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func makeGenesisBytes(predecessorShard string, predecessorFinalHead string, predecessorFinalSize uint64, chainPosition int) []byte {
	data := map[string]interface{}{
		"predecessor_shard":      predecessorShard,
		"predecessor_final_head": predecessorFinalHead,
		"predecessor_final_size": predecessorFinalSize,
		"chain_position":         chainPosition,
	}
	b, _ := json.Marshal(data)
	return b
}

func buildShardChain(n int) []verifier.ShardInfo {
	shards := make([]verifier.ShardInfo, n)

	// First shard: no predecessor.
	shards[0] = verifier.ShardInfo{
		ShardID:      "shard-0000",
		GenesisBytes: makeGenesisBytes("", "", 0, 0),
		FinalHead: types.CosignedTreeHead{
			TreeHead: types.TreeHead{
				RootHash: sha256.Sum256([]byte("root-0")),
				TreeSize: 1000,
			},
		},
		FinalSize: 1000,
	}

	for i := 1; i < n; i++ {
		prev := shards[i-1]
		headHash := verifier.TreeHeadHash(prev.FinalHead.TreeHead)
		headHex := hex.EncodeToString(headHash[:])

		shardID := "shard-000" + string(rune('0'+i))
		shards[i] = verifier.ShardInfo{
			ShardID:      shardID,
			GenesisBytes: makeGenesisBytes(prev.ShardID, headHex, prev.FinalSize, i),
			FinalHead: types.CosignedTreeHead{
				TreeHead: types.TreeHead{
					RootHash: sha256.Sum256([]byte("root-" + string(rune('0'+i)))),
					TreeSize: uint64((i + 1) * 1000),
				},
			},
			FinalSize: uint64((i + 1) * 1000),
		}
	}

	return shards
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyShardChain
// ─────────────────────────────────────────────────────────────────────

func TestShardChain_SingleShard_Valid(t *testing.T) {
	shards := buildShardChain(1)
	result, err := verifier.VerifyShardChain(shards)
	if err != nil {
		t.Fatalf("single shard: %v", err)
	}
	if !result.Valid {
		t.Fatal("should be valid")
	}
	if result.ChainLength != 1 {
		t.Fatalf("length: %d", result.ChainLength)
	}
	if result.FirstShard != "shard-0000" {
		t.Fatalf("first: %s", result.FirstShard)
	}
	if result.LastShard != "shard-0000" {
		t.Fatalf("last: %s", result.LastShard)
	}
	if result.BrokenAt != -1 {
		t.Fatalf("brokenAt: %d", result.BrokenAt)
	}
}

func TestShardChain_ThreeShards_Valid(t *testing.T) {
	shards := buildShardChain(3)
	result, err := verifier.VerifyShardChain(shards)
	if err != nil {
		t.Fatalf("three shards: %v", err)
	}
	if !result.Valid {
		t.Fatal("should be valid")
	}
	if result.ChainLength != 3 {
		t.Fatalf("length: %d", result.ChainLength)
	}
	if result.FirstShard != "shard-0000" {
		t.Fatalf("first: %s", result.FirstShard)
	}
}

func TestShardChain_FiveShards_Valid(t *testing.T) {
	shards := buildShardChain(5)
	result, err := verifier.VerifyShardChain(shards)
	if err != nil {
		t.Fatalf("five shards: %v", err)
	}
	if !result.Valid {
		t.Fatal("should be valid")
	}
	if result.ChainLength != 5 {
		t.Fatalf("length: %d", result.ChainLength)
	}
}

func TestShardChain_Empty_Error(t *testing.T) {
	_, err := verifier.VerifyShardChain(nil)
	if !errors.Is(err, verifier.ErrShardChainEmpty) {
		t.Fatalf("expected ErrShardChainEmpty, got: %v", err)
	}
}

func TestShardChain_BrokenPredecessorID(t *testing.T) {
	shards := buildShardChain(3)
	// Corrupt shard 2's genesis to reference wrong predecessor.
	shards[2].GenesisBytes = makeGenesisBytes("wrong-shard", "", 2000, 2)

	result, err := verifier.VerifyShardChain(shards)
	if err == nil {
		t.Fatal("broken predecessor should error")
	}
	if result.Valid {
		t.Fatal("should not be valid")
	}
	if result.BrokenAt != 2 {
		t.Fatalf("brokenAt: %d, want 2", result.BrokenAt)
	}
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

func TestShardChain_BrokenFinalSize(t *testing.T) {
	shards := buildShardChain(3)
	prev := shards[0]
	headHash := verifier.TreeHeadHash(prev.FinalHead.TreeHead)
	headHex := hex.EncodeToString(headHash[:])
	// Wrong final size.
	shards[1].GenesisBytes = makeGenesisBytes(prev.ShardID, headHex, 9999, 1)

	result, err := verifier.VerifyShardChain(shards)
	if err == nil {
		t.Fatal("wrong final size should error")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("brokenAt: %d", result.BrokenAt)
	}
}

func TestShardChain_BrokenChainPosition(t *testing.T) {
	shards := buildShardChain(3)
	prev := shards[1]
	headHash := verifier.TreeHeadHash(prev.FinalHead.TreeHead)
	headHex := hex.EncodeToString(headHash[:])
	// Wrong chain position (5 instead of 2).
	shards[2].GenesisBytes = makeGenesisBytes(prev.ShardID, headHex, prev.FinalSize, 5)

	_, err := verifier.VerifyShardChain(shards)
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

func TestShardChain_BadGenesisJSON(t *testing.T) {
	shards := []verifier.ShardInfo{
		{ShardID: "shard-0000", GenesisBytes: []byte("not json")},
	}
	_, err := verifier.VerifyShardChain(shards)
	if !errors.Is(err, verifier.ErrShardGenesisParse) {
		t.Fatalf("expected ErrShardGenesisParse, got: %v", err)
	}
}

func TestShardChain_EmptyGenesisBytes(t *testing.T) {
	shards := []verifier.ShardInfo{
		{ShardID: "shard-0000", GenesisBytes: nil},
	}
	_, err := verifier.VerifyShardChain(shards)
	if !errors.Is(err, verifier.ErrShardGenesisParse) {
		t.Fatalf("expected ErrShardGenesisParse, got: %v", err)
	}
}

func TestShardChain_FirstShardHasPredecessor_Error(t *testing.T) {
	shards := []verifier.ShardInfo{
		{ShardID: "shard-0000", GenesisBytes: makeGenesisBytes("some-shard", "", 0, 0)},
	}
	_, err := verifier.VerifyShardChain(shards)
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

func TestShardChain_FirstShardWrongPosition_Error(t *testing.T) {
	shards := []verifier.ShardInfo{
		{ShardID: "shard-0000", GenesisBytes: makeGenesisBytes("", "", 0, 3)},
	}
	_, err := verifier.VerifyShardChain(shards)
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyShardGenesis
// ─────────────────────────────────────────────────────────────────────

func TestShardGenesis_Valid(t *testing.T) {
	predHead := types.TreeHead{RootHash: sha256.Sum256([]byte("pred")), TreeSize: 500}
	headHash := verifier.TreeHeadHash(predHead)
	headHex := hex.EncodeToString(headHash[:])
	genesis := makeGenesisBytes("shard-prev", headHex, 500, 1)

	err := verifier.VerifyShardGenesis(genesis, "shard-prev", 500, predHead)
	if err != nil {
		t.Fatalf("valid genesis: %v", err)
	}
}

func TestShardGenesis_WrongPredecessor(t *testing.T) {
	predHead := types.TreeHead{RootHash: sha256.Sum256([]byte("pred")), TreeSize: 500}
	headHash := verifier.TreeHeadHash(predHead)
	headHex := hex.EncodeToString(headHash[:])
	genesis := makeGenesisBytes("shard-wrong", headHex, 500, 1)

	err := verifier.VerifyShardGenesis(genesis, "shard-prev", 500, predHead)
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

func TestShardGenesis_WrongSize(t *testing.T) {
	predHead := types.TreeHead{RootHash: sha256.Sum256([]byte("pred")), TreeSize: 500}
	headHash := verifier.TreeHeadHash(predHead)
	headHex := hex.EncodeToString(headHash[:])
	genesis := makeGenesisBytes("shard-prev", headHex, 999, 1)

	err := verifier.VerifyShardGenesis(genesis, "shard-prev", 500, predHead)
	if !errors.Is(err, verifier.ErrShardChainBroken) {
		t.Fatalf("expected ErrShardChainBroken, got: %v", err)
	}
}

func TestShardGenesis_BadJSON(t *testing.T) {
	err := verifier.VerifyShardGenesis([]byte("{bad"), "x", 0, types.TreeHead{})
	if !errors.Is(err, verifier.ErrShardGenesisParse) {
		t.Fatalf("expected ErrShardGenesisParse, got: %v", err)
	}
}
