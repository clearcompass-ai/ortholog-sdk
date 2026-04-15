/*
Package schema — shard_genesis.go defines the shard genesis payload type
and its constructor/parser. A shard's genesis entry (position 0) carries
this payload in its Domain Payload, linking the shard to its predecessor.

Previously, verifier/shard_chain_verifier.go maintained a local copy of
this struct (shardGenesisFields). This file is the canonical definition —
the verifier imports it, the operator's shard_manager.go produces it,
and domain applications adopt it via their schema adoption flow.

Consistent with verifier/shard_chain_verifier.go living in the SDK:
the verifier consumes the type, so the type belongs in the same repo.

Exported types:
  ShardGenesisPayload — the Domain Payload for shard genesis entries
  BuildShardGenesisPayload — deterministic JSON constructor
  ParseShardGenesisPayload — deserializer (used by verifier)
  ShardGenesisSchemaParams — SchemaParameters for shard genesis entries
*/
package schema

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// ShardGenesisPayload
// ─────────────────────────────────────────────────────────────────────

// ShardGenesisPayload is the Domain Payload for a shard's genesis entry
// at position 0. It links the shard to its predecessor in the shard chain.
//
// JSON field names match the operator's lifecycle/shard_manager.go exactly.
// Two implementations producing the same JSON → byte-identical payloads.
//
// For the first shard in a chain (chain_position=0):
//   predecessor_shard = ""
//   predecessor_final_head = ""
//   predecessor_final_size = 0
//
// For subsequent shards:
//   predecessor_shard = ShardID of the prior shard
//   predecessor_final_head = hex(SHA-256(WitnessCosignMessage(finalHead)))
//   predecessor_final_size = total entries in the prior shard
//   chain_position = sequential index (1, 2, 3, ...)
type ShardGenesisPayload struct {
	// PredecessorShard is the ShardID of the prior shard.
	// Empty string for the first shard (no predecessor).
	PredecessorShard string `json:"predecessor_shard"`

	// PredecessorFinalHead is the hex-encoded hash of the prior shard's
	// final cosigned tree head. Computed by TreeHeadHash(finalHead).
	// Empty string for the first shard.
	PredecessorFinalHead string `json:"predecessor_final_head"`

	// PredecessorFinalSize is the total number of entries in the prior shard.
	// Zero for the first shard.
	PredecessorFinalSize uint64 `json:"predecessor_final_size"`

	// ChainPosition is the 0-based index of this shard in the chain.
	// First shard = 0, second = 1, etc.
	ChainPosition int `json:"chain_position"`
}

// ─────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────

// BuildShardGenesisPayload creates a deterministic JSON payload for a
// shard genesis entry. The output is suitable for envelope.NewEntry's
// payload parameter.
//
// For the first shard:
//   BuildShardGenesisPayload("", "", 0, 0)
//
// For subsequent shards:
//   headHash := verifier.TreeHeadHash(prevShard.FinalHead.TreeHead)
//   headHex := hex.EncodeToString(headHash[:])
//   BuildShardGenesisPayload(prevShard.ShardID, headHex, prevShard.FinalSize, chainPos)
func BuildShardGenesisPayload(predecessorShard, predecessorFinalHead string, predecessorFinalSize uint64, chainPosition int) ([]byte, error) {
	if chainPosition < 0 {
		return nil, fmt.Errorf("schema/shard_genesis: negative chain position %d", chainPosition)
	}
	if chainPosition == 0 && predecessorShard != "" {
		return nil, fmt.Errorf("schema/shard_genesis: chain position 0 must have empty predecessor")
	}
	if chainPosition > 0 && predecessorShard == "" {
		return nil, fmt.Errorf("schema/shard_genesis: chain position %d requires predecessor shard ID", chainPosition)
	}

	payload := ShardGenesisPayload{
		PredecessorShard:     predecessorShard,
		PredecessorFinalHead: predecessorFinalHead,
		PredecessorFinalSize: predecessorFinalSize,
		ChainPosition:        chainPosition,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("schema/shard_genesis: marshal: %w", err)
	}
	return data, nil
}

// ─────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────

// ParseShardGenesisPayload deserializes a shard genesis Domain Payload.
// Used by verifier/shard_chain_verifier.go to validate shard chain links.
//
// Returns an error if the data is empty or not valid JSON.
func ParseShardGenesisPayload(data []byte) (*ShardGenesisPayload, error) {
	if len(data) == 0 {
		return nil, errors.New("schema/shard_genesis: empty genesis data")
	}
	var payload ShardGenesisPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("schema/shard_genesis: %w", err)
	}
	return &payload, nil
}

// ─────────────────────────────────────────────────────────────────────
// Schema Parameters
// ─────────────────────────────────────────────────────────────────────

// ShardGenesisSchemaParams returns the SchemaParameters for shard genesis
// entries. Shard genesis is operator-signed, not scope-governed:
//   - No activation delay (immediate effect)
//   - No cosignature threshold (operator acts alone)
//   - No maturation epoch
//   - No credential validity period (permanent)
//   - AES-GCM encryption (default, though genesis entries rarely have artifacts)
//   - Strict migration policy (no cross-version references)
func ShardGenesisSchemaParams() *types.SchemaParameters {
	return &types.SchemaParameters{
		ActivationDelay:      0,
		CosignatureThreshold: 0,
		MaturationEpoch:      0,
		MigrationPolicy:      types.MigrationStrict,
		ArtifactEncryption:   types.EncryptionAESGCM,
	}
}
