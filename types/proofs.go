package types

// MerkleProof proves inclusion of a leaf in the Merkle tree.
// O(log N) hashes where N is total log size.
type MerkleProof struct {
	LeafPosition uint64     // Sequence number of the entry
	LeafHash     [32]byte   // Canonical hash of the entry
	Siblings     [][32]byte // Sibling hashes along path to root
	TreeSize     uint64     // Tree size this proof is valid against
}

// SMTProof proves membership or non-membership of a key in the SMT.
// Contains only non-default siblings along the 256-bit path.
// Typically 30-40 hashes; at 10K leaves avg 13 non-default hashes (~517 bytes).
type SMTProof struct {
	Key      [32]byte            // SMT leaf key being proved
	Leaf     *SMTLeaf            // Non-nil for membership, nil for non-membership
	Siblings map[uint8][32]byte  // depth -> sibling hash (only non-default)
}

// BatchProof combines Merkle and SMT multiproofs with shared-path deduplication.
// 5-entry chain: ~3.8 KB (vs 11 KB individual). 20-entry: ~9 KB (vs 44 KB).
type BatchProof struct {
	TreeHead        CosignedTreeHead
	SMTRoot         [32]byte
	MerkleNodes     []ProofNode  // Deduplicated Merkle path nodes
	SMTNodes        []ProofNode  // Deduplicated SMT path nodes (non-default only)
	Entries         []BatchEntry // Entry index -> (position, hash)
}

// ProofNode is a single node in a batch multiproof.
// Canonical ordering (SDK-D13): depth ascending, position ascending.
type ProofNode struct {
	Depth    uint16   // Depth in tree (0 = root)
	Position uint64   // Position at this depth
	Hash     [32]byte // Node hash
}

// BatchEntry maps an entry to its log position and hash within a batch proof.
type BatchEntry struct {
	LogPos LogPosition
	Hash   [32]byte
}

// CrossLogProof packages cross-log verification into a single verifiable object.
// 5-step verification: local head -> local inclusion -> anchor binding ->
// source head -> source inclusion.
// Approximately 2.1 KB per cross-log verification.
type CrossLogProof struct {
	// Source log proof
	SourceEntry     LogPosition
	SourceEntryHash [32]byte
	SourceTreeHead  CosignedTreeHead
	SourceInclusion MerkleProof

	// Anchor binding on local log
	AnchorEntry       LogPosition
	AnchorEntryHash   [32]byte
	AnchorTreeHeadRef [32]byte // Must match SHA-256(SourceTreeHead)

	// Local log proof
	LocalTreeHead  CosignedTreeHead
	LocalInclusion MerkleProof
}

// EquivocationProof is cryptographic evidence that a log operator has forked.
// Two valid cosigned tree heads for the same tree size with different root hashes.
// Base primitive for slashing, fraud-proof bridges, and objective triggers.
type EquivocationProof struct {
	Head1 CosignedTreeHead
	Head2 CosignedTreeHead
	// Invariant: Head1.TreeSize == Head2.TreeSize && Head1.RootHash != Head2.RootHash
	// Both must have valid K-of-N cosignatures from the same witness set.
}
