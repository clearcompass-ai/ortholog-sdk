package types

type MerkleProof struct {
	LeafPosition uint64
	LeafHash     [32]byte
	Siblings     [][32]byte
	TreeSize     uint64
}

type SMTProof struct {
	Key      [32]byte
	Leaf     *SMTLeaf
	Siblings map[uint8][32]byte
}

type BatchProof struct {
	TreeHead    CosignedTreeHead
	SMTRoot     [32]byte
	MerkleNodes []ProofNode
	SMTNodes    []ProofNode
	Entries     []BatchEntry
}

type ProofNode struct {
	Depth    uint16
	Position uint64
	Hash     [32]byte
}

type BatchEntry struct {
	LogPos LogPosition
	Hash   [32]byte
}

type CrossLogProof struct {
	SourceEntry     LogPosition
	SourceEntryHash [32]byte
	SourceTreeHead  CosignedTreeHead
	SourceInclusion MerkleProof
	AnchorEntry       LogPosition
	AnchorEntryHash   [32]byte
	AnchorTreeHeadRef [32]byte
	LocalTreeHead  CosignedTreeHead
	LocalInclusion MerkleProof
}

type EquivocationProof struct {
	Head1 CosignedTreeHead
	Head2 CosignedTreeHead
}
