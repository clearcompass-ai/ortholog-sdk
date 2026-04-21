// types/proofs.go — proof types carried between prover and verifier.
//
// PROOFS ARE PURE DATA
// ════════════════════
// Every type in this file is a serializable record of cryptographic
// evidence. They perform no computation, have no methods beyond value
// construction, and carry no references to runtime resources (no
// channels, mutexes, network handles, or function values). This
// discipline lets proofs be:
//
//   - Stored on-log alongside the data they attest to.
//   - Archived for later audit replay, years after their construction.
//   - Transmitted across trust boundaries, including through
//     adversarial intermediaries — every field is inspectable and
//     every invariant is independently checkable.
//   - Verified by a pure function with no I/O surface. The verifier
//     that consumes a proof never reaches out for additional bytes.
//
// When a verifier needs a byte to do its job, that byte lives on the
// proof. This is the single rule from which every design decision in
// this file follows. In particular it is the rule that drove
// CrossLogProof.AnchorEntryCanonical: the content-binding check
// requires the anchor entry's bytes, so the proof carries them.
//
// NAMING DISCIPLINE
// ─────────────────
// Field names suffixed with "Hash" are RFC 6962 leaf hashes
// (SHA-256(0x00 || canonical_bytes)) unless documented otherwise.
// These are NOT the same as SHA-256(canonical_bytes), which is
// EntryIdentity — used for dedup, never for Merkle proofs. Confusing
// the two silently breaks every proof.
//
// Field names suffixed with "Canonical" are the raw canonical bytes
// of an entry (what envelope.Serialize produces), exactly as they
// appear in the log. Canonical bytes are never altered in transit;
// they are hashed, not re-serialized, by the verifier.

package types

// ═══════════════════════════════════════════════════════════════════
// MerkleProof — RFC 6962 inclusion proof for a single leaf
// ═══════════════════════════════════════════════════════════════════

// MerkleProof is an inclusion proof for a single leaf in an append-only
// Merkle log, per RFC 6962 §2.1.1. A valid MerkleProof attests:
//
//	"The leaf with LeafHash at position LeafPosition is present in a
//	 tree of size TreeSize whose root hash the verifier will recompute
//	 by walking Siblings bottom-up from LeafHash."
//
// A MerkleProof alone proves only that SOME leaf with the given hash
// is in the tree. It does NOT prove what the leaf represents. The
// caller is responsible for binding LeafHash to a known entry hash
// — every Ortholog proof type that carries a MerkleProof does so
// alongside an explicit hash field and a binding check in the verifier
// (see CrossLogProof.SourceEntryHash / AnchorEntryHash).
//
// INVARIANTS (must hold for verification to succeed):
//
//   - LeafPosition < TreeSize.
//   - LeafHash = envelope.EntryLeafHashBytes(entryCanonicalBytes), i.e.
//     SHA-256(0x00 || canonical). Not SHA-256(canonical).
//   - len(Siblings) equals the RFC 6962 co-path length for LeafPosition
//     within a tree of TreeSize leaves (= ceil(log2(TreeSize)) adjusted
//     for the imperfect-tree case).
//   - TreeSize equals the TreeSize of the CosignedTreeHead the proof
//     was constructed against. Mismatched TreeSize means the proof is
//     for a different tree state and will not chain to the same root.
//
// IMMUTABILITY
//
//	Once constructed, a MerkleProof is never mutated in transit.
//	Builders that compute a proof and later bind a leaf hash should do
//	so on the instance they own before handing it off; consumers treat
//	every field as read-only.
type MerkleProof struct {
	// LeafPosition is the zero-based index of the leaf within the tree.
	// Must be strictly less than TreeSize.
	LeafPosition uint64

	// LeafHash is the RFC 6962 leaf hash of the entry at LeafPosition.
	// Computed as SHA-256(0x00 || canonical_bytes) — use
	// envelope.EntryLeafHashBytes to compute; do not inline.
	//
	// Provers that obtain this proof from an external source (e.g., a
	// log operator) may leave this field zero and expect the caller to
	// populate it from independently-obtained canonical bytes. Every
	// verifier in the SDK binds this field to a separately-supplied
	// entry hash before trusting it.
	LeafHash [32]byte

	// Siblings is the co-path from the leaf to the root: the hashes of
	// the Merkle tree nodes that the verifier combines with LeafHash to
	// reconstruct the root. Order is bottom-up: Siblings[0] is the
	// leaf's immediate sibling; Siblings[len-1] is the sibling of the
	// node directly below the root.
	Siblings [][32]byte

	// TreeSize is the total number of leaves in the tree this proof was
	// constructed against. Combined with LeafPosition, it fixes the
	// exact tree shape the verifier reconstructs.
	TreeSize uint64
}

// ═══════════════════════════════════════════════════════════════════
// SMTProof — Sparse Merkle Tree (non-)inclusion proof
// ═══════════════════════════════════════════════════════════════════

// SMTProof is a (non-)inclusion proof for a single key in a Sparse
// Merkle Tree. It attests one of:
//
//	PRESENCE:  "Key maps to Leaf in the SMT whose root the verifier
//	            reconstructs by walking from Leaf up through Siblings."
//	ABSENCE:   "Key maps to the empty leaf in the SMT whose root the
//	            verifier reconstructs from Siblings alone."
//
// Encoded as a single type because the two cases share a verification
// skeleton; the only difference is whether Leaf is nil.
//
// SIBLINGS IS SPARSE ON PURPOSE
// ─────────────────────────────
// A full SMT path at depth 256 has 256 siblings, most of which are the
// empty-subtree hash at that depth. Storing them densely as [][32]byte
// wastes ~8KB per proof. The map[uint8][32]byte form stores only
// non-default siblings, keyed by depth. The verifier fills in empty
// siblings at missing depths from a precomputed empty-subtree ladder.
//
// INVARIANTS:
//   - For presence proofs: Leaf != nil and Leaf.Key == Key.
//   - For absence proofs: Leaf == nil.
//   - Siblings keys are strictly less than 256 (SMT max depth).
//   - Reconstructing the root from Leaf (or the empty leaf) combined
//     with Siblings must equal the SMT root the verifier is checking.
type SMTProof struct {
	// Key is the 256-bit SMT key being proven.
	Key [32]byte

	// Leaf is the leaf stored at Key, or nil for an absence proof.
	// When non-nil, Leaf.Key MUST equal Key — a presence proof for one
	// key cannot be repurposed as a presence proof for another.
	Leaf *SMTLeaf

	// Siblings is the sparse co-path: only depths whose sibling differs
	// from the empty-subtree hash are present. Missing depths are
	// reconstructed by the verifier from the empty-subtree ladder.
	Siblings map[uint8][32]byte
}

// ═══════════════════════════════════════════════════════════════════
// BatchProof — amortized inclusion/non-inclusion for many keys at once
// ═══════════════════════════════════════════════════════════════════

// BatchProof attests to the inclusion of multiple entries in a single
// tree head simultaneously, sharing common internal nodes across the
// individual proofs. A batch of N entries whose paths share a common
// ancestor at depth D can be proven with far fewer sibling hashes than
// N independent MerkleProofs.
//
// Use cases:
//   - Operator publishing an EntryBundle: all entries in the bundle
//     share a common Merkle subtree root.
//   - Verifier auditing a cross-log sync: proving that a batch of
//     foreign entries all appear in the local log at a specific head.
//
// VERIFICATION SKETCH
//
//	For each entry in Entries:
//	  1. Confirm entry.Hash is the leaf hash at entry.LogPos.Sequence.
//	  2. Reconstruct the leaf-to-root path using MerkleNodes, treating
//	     the shared nodes as siblings-of-common-ancestors rather than
//	     leaf-side siblings.
//	Then:
//	  3. Confirm the reconstructed Merkle root equals TreeHead.RootHash.
//	  4. Confirm the SMTRoot is consistent with SMTNodes and any
//	     referenced SMT leaves.
//	  5. Confirm TreeHead has valid witness cosignatures.
type BatchProof struct {
	// TreeHead is the witness-cosigned tree head the batch is valid at.
	// All entry Merkle proofs resolve to TreeHead.RootHash; the SMT root
	// is bound to TreeHead via the SMTRoot field.
	TreeHead CosignedTreeHead

	// SMTRoot is the Sparse Merkle Tree root at the same tree state.
	// Carried explicitly because not every TreeHead format embeds it.
	SMTRoot [32]byte

	// MerkleNodes are the internal Merkle tree nodes needed to
	// reconstruct the path from each entry leaf to TreeHead.RootHash.
	// Deduplicated across entries — a node shared by two entry paths
	// appears once.
	MerkleNodes []ProofNode

	// SMTNodes are the SMT internal nodes needed to reconstruct the
	// SMT root. Similar deduplication as MerkleNodes.
	SMTNodes []ProofNode

	// Entries are the log entries being proven. Each carries its
	// position and its RFC 6962 leaf hash; the verifier binds these
	// to external claims before trusting them.
	Entries []BatchEntry
}

// ProofNode is an internal node in a batch proof — either a Merkle tree
// node or an SMT node, depending on which slice of BatchProof it lives
// in. The Depth + Position pair uniquely identifies the node's location
// in the tree, which the verifier uses to stitch together paths.
type ProofNode struct {
	// Depth is the node's depth from the root (root is 0). For SMT
	// nodes, depth ranges 0..255; for Merkle tree nodes, depth ranges
	// 0..ceil(log2(TreeSize)).
	Depth uint16

	// Position is the node's index at Depth, left-to-right.
	Position uint64

	// Hash is the node's hash: RFC 6962 interior node hash for Merkle
	// nodes (SHA-256(0x01 || left || right)), or the SMT interior hash
	// for SMT nodes.
	Hash [32]byte
}

// BatchEntry binds a log position to its RFC 6962 leaf hash within a
// BatchProof. It's the atomic unit the verifier uses to confirm that
// a specific entry is covered by the batch.
type BatchEntry struct {
	// LogPos is the position (shard + sequence) of the entry.
	LogPos LogPosition

	// Hash is the RFC 6962 leaf hash of the entry's canonical bytes.
	// Same discipline as MerkleProof.LeafHash — use
	// envelope.EntryLeafHashBytes to compute.
	Hash [32]byte
}

// ═══════════════════════════════════════════════════════════════════
// CrossLogProof — cross-log reference proof
// ═══════════════════════════════════════════════════════════════════

// CrossLogProof proves that an entry in a foreign (source) log is
// reachable from a tree head of the local log via an anchor entry.
// Specifically, the proof attests all of the following simultaneously:
//
//  1. The source log, at SourceTreeHead, contains SourceEntry (at
//     position SourceEntry.Sequence) with leaf hash SourceEntryHash.
//  2. SourceTreeHead has valid K-of-N witness cosignatures, so it is
//     a genuine publicly-attested state of the source log.
//  3. The local log, at LocalTreeHead, contains AnchorEntry (at
//     position AnchorEntry.Sequence) with leaf hash AnchorEntryHash.
//  4. The bytes carried as AnchorEntryCanonical hash exactly to
//     AnchorEntryHash — no byte substitution.
//  5. The anchor entry's DomainPayload, parsed by a domain-supplied
//     extractor, contains an explicit reference to TreeHeadHash of
//     SourceTreeHead. This is the content-binding check that prevents
//     a forger from swapping in a real-but-unrelated anchor entry.
//
// It is the combination of (4) and (5) that closes the Forged Anchor
// Attack: the attacker cannot produce AnchorEntryCanonical bytes that
// both (a) hash to the anchor leaf the local-log inclusion proof covers
// and (b) semantically commit to the source tree head they want to
// forge, without actually getting the local log to write such an entry.
// Since the local log only writes anchor entries for tree heads it
// observed, the attacker cannot fabricate the combination.
//
// VERIFIER IS A PURE FUNCTION
// ───────────────────────────
// The verifier that consumes a CrossLogProof performs no I/O. Every
// byte it needs — canonical anchor bytes, tree heads, inclusion paths
// — is in the proof. This means proofs can be archived, replayed years
// later, or verified in restricted environments (browsers, smart
// contracts via ZK-ported verifier code, air-gapped auditors).
//
// TRUST ASSUMPTIONS
// ─────────────────
//
//	SourceTreeHead:  UNTRUSTED input until its witness quorum is
//	                 verified by the verifier (step 2 of the checks
//	                 above). After verification, authoritative.
//
//	LocalTreeHead:   TRUSTED by the caller. The verifier uses
//	                 LocalTreeHead.RootHash directly without checking
//	                 witness cosignatures, because a CrossLogProof is
//	                 typically consumed by a party that already treats
//	                 the local log as authoritative (the operator
//	                 itself, a monitoring service, a domain application
//	                 that has pinned local witnesses out of band).
//	                 Callers who need witness verification of
//	                 LocalTreeHead should invoke witness.VerifyTreeHead
//	                 on it separately before calling the cross-log
//	                 verifier.
//
//	extractor:       TRUSTED dependency supplied by the domain
//	                 application. A malicious extractor can return any
//	                 32-byte value, voiding the content-binding check.
//	                 This is an API-boundary concern, not a proof-
//	                 format concern.
//
// SIZE
// ────
// A CrossLogProof's size is dominated by AnchorEntryCanonical (up to
// envelope.MaxBundleEntrySize = 65535 bytes) and by the two inclusion
// proofs (each ~32 bytes per tree level). Typical proofs are a few
// hundred bytes to a few kilobytes; worst case is ~64KB. Callers
// embedding CrossLogProof in larger artifacts should plan capacity
// accordingly.
type CrossLogProof struct {
	// ── Source side (foreign log, witness-verified in-band) ──────────

	// SourceEntry is the (shard, sequence) position of the claimed
	// entry in the source log.
	SourceEntry LogPosition

	// SourceEntryHash is the RFC 6962 leaf hash of the source entry's
	// canonical bytes. Must equal SourceInclusion.LeafHash (bound by
	// verifier step 2).
	SourceEntryHash [32]byte

	// SourceTreeHead is the source log tree head at which SourceEntry
	// is provably included. Untrusted until its witness cosignatures
	// are verified against a caller-supplied set of source witness keys
	// (verifier step 4).
	SourceTreeHead CosignedTreeHead

	// SourceInclusion is the Merkle inclusion proof linking
	// SourceEntryHash to SourceTreeHead.RootHash.
	// Invariant: SourceInclusion.LeafHash == SourceEntryHash.
	// Invariant: SourceInclusion.TreeSize == SourceTreeHead.TreeSize.
	SourceInclusion MerkleProof

	// ── Anchor side (local log, trusted by caller) ───────────────────

	// AnchorEntry is the (shard, sequence) position of the anchor entry
	// in the local log. An anchor entry is a local-log entry whose
	// DomainPayload contains (or references) the source tree head
	// being cross-certified.
	AnchorEntry LogPosition

	// AnchorEntryHash is the RFC 6962 leaf hash of the anchor entry's
	// canonical bytes. Must equal LocalInclusion.LeafHash (bound by
	// verifier step 5) and must equal the hash of AnchorEntryCanonical
	// (bound by verifier step 7).
	AnchorEntryHash [32]byte

	// AnchorEntryCanonical is the exact canonical-byte serialization
	// of the anchor entry, as it appears in the local log. The
	// verifier:
	//
	//   1. Hashes these bytes and confirms they equal AnchorEntryHash
	//      (defense against byte substitution).
	//   2. Deserializes them to an envelope.Entry.
	//   3. Passes Entry.DomainPayload to a domain-supplied extractor.
	//   4. Confirms the extracted tree head reference equals
	//      TreeHeadHash(SourceTreeHead.TreeHead).
	//
	// This field is the concrete mechanism by which the pure-function
	// verifier obtains the bytes it needs to perform content binding
	// without any network or filesystem I/O. See the file header for
	// the general principle.
	//
	// Size ceiling: envelope.MaxBundleEntrySize (65535 bytes). Larger
	// values indicate a bug in the builder or corruption in transit.
	AnchorEntryCanonical []byte

	// ── Local side (local log, trusted by caller) ────────────────────

	// LocalTreeHead is the local log tree head at which AnchorEntry is
	// provably included. Trusted by the caller; the cross-log verifier
	// does NOT re-verify its witness cosignatures. See the
	// "Trust assumptions" section of the type-level doc above.
	LocalTreeHead CosignedTreeHead

	// LocalInclusion is the Merkle inclusion proof linking
	// AnchorEntryHash to LocalTreeHead.RootHash.
	// Invariant: LocalInclusion.LeafHash == AnchorEntryHash.
	// Invariant: LocalInclusion.TreeSize == LocalTreeHead.TreeSize.
	LocalInclusion MerkleProof
}

// ═══════════════════════════════════════════════════════════════════
// EquivocationProof — proof that a log signed two conflicting heads
// ═══════════════════════════════════════════════════════════════════

// EquivocationProof carries evidence that a log operator (or witness
// quorum) signed two distinct tree heads for the same (or overlapping)
// tree states. It is the single most serious governance-level violation
// in the protocol: a log that equivocates has been proven dishonest
// and its entire history becomes untrustworthy going forward.
//
// WHAT COUNTS AS EQUIVOCATION
// ───────────────────────────
// Given two CosignedTreeHeads H1 and H2 signed by the same log
// identifier, any of the following constitutes equivocation:
//
//   - H1.TreeSize == H2.TreeSize and H1.RootHash != H2.RootHash.
//     The operator produced two conflicting trees at the same size.
//
//   - H1.TreeSize < H2.TreeSize and a consistency proof from H1 to H2
//     fails. The operator produced a later tree that is not a
//     consistent extension of the earlier one (i.e., they rewrote
//     history).
//
// EquivocationProof carries only the two heads. Detection and handling
// (consistency-proof fetching, governance action) live in the witness
// package.
//
// INVARIANTS:
//   - Head1 and Head2 MUST be signed by the same log identifier.
//     An EquivocationProof comparing heads from different logs is
//     meaningless and will be rejected by the verifier.
//   - Head1 and Head2 MUST be distinct (differ in at least one field).
type EquivocationProof struct {
	// Head1 and Head2 are the two conflicting tree heads. Order is not
	// semantically significant — equivocation is symmetric — but
	// convention is that Head1 is the earlier-observed head.
	Head1 CosignedTreeHead
	Head2 CosignedTreeHead
}
