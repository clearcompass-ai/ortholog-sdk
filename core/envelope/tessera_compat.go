// Package envelope — tessera_compat.go aligns the SDK's output with the
// Tessera tile-based transparency log's Entry contract.
//
// Tessera (github.com/transparency-dev/tessera) defines an Entry as four
// quantities:
//
//	Data            — the raw leaf bytes that form the entry in the log
//	Identity        — a dedup key (SHA-256 of Data, per Tessera's identityHash)
//	LeafHash        — the Merkle leaf hash (RFC 6962: SHA-256(0x00 || Data))
//	MarshalBundle*  — bundle-format bytes per c2sp.org/tlog-tiles:
//	                  uint16_BE(len(Data)) || Data
//
// The four primitives below produce these four values from an *Entry.
// Together they are exactly what Tessera's NewEntry(data) produces when
// data = envelope.Serialize(entry), so an operator can bridge to Tessera
// with a single call:
//
//	tEntry := tessera.NewEntry(envelope.Serialize(entry))
//	// or, equivalently, consume the SDK primitives directly without
//	// importing Tessera in consumer code.
//
// WHY NO TESSERA IMPORT
// ─────────────────────
// Importing github.com/transparency-dev/tessera into the SDK would force
// every SDK consumer (judicial-network, verifiers, witnesses, schema
// resolvers) to transitively depend on Tessera's storage internals, GCS
// adapters, and persistence layers. Only the ortholog-operator actually
// writes tile files. RFC 6962 is a frozen spec (RFC 6962-bis is a distinct
// protocol); we can inline the 4-line leaf-hash rule and cite it.
//
// WHY Identity == SHA-256(data) (NOT RFC 6962)
// ────────────────────────────────────────────
// Tessera uses two distinct hashes on purpose:
//   - Identity is for "have I seen this entry before" dedup. It must be
//     a cheap, non-domain-separated hash because the log may have to compute
//     it on many candidate entries before dedup rejects one.
//   - LeafHash is for Merkle-tree construction. RFC 6962 prepends 0x00 so
//     leaf hashes are domain-separated from interior-node hashes (which
//     prepend 0x01), preventing second-preimage attacks on the tree.
//
// Confusing these is a live footgun: a previous iteration of this SDK used
// SHA-256(data) as both the dedup key AND the leaf hash. That happened to
// work because the operator never constructed Merkle proofs across node
// types, but the moment a real tile-proof verifier runs against such
// hashes, every proof fails. These two functions make the distinction
// explicit and unskippable.
//
// MIGRATION NOTE
// ──────────────
// envelope.EntryIdentity(entry) is semantically equivalent to
// EntryIdentity(entry). If you're currently feeding its output into a
// Merkle tree construction, that's a bug — switch to EntryLeafHash. The
// existing ProcessBatch / fraud-proof replay paths use CanonicalHash for
// entry identity only; those are correct.
package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ─────────────────────────────────────────────────────────────────────
// Frozen constants
// ─────────────────────────────────────────────────────────────────────

// RFC6962LeafPrefix is the RFC 6962 §2.1 leaf domain separator byte.
// Prepended to leaf data before SHA-256 to produce the Merkle leaf hash.
// This byte MUST NOT change — changing it invalidates every tree head
// ever produced against this protocol.
const RFC6962LeafPrefix byte = 0x00

// RFC6962NodePrefix is the RFC 6962 §2.1 interior-node domain separator
// byte. Exposed for completeness; the SDK does not construct interior
// nodes (that's Tessera's job), but downstream verifiers may need it.
const RFC6962NodePrefix byte = 0x01

// MaxBundleEntrySize is the largest data length the c2sp.org/tlog-tiles
// bundle format can represent. The length prefix is uint16, so entries
// exceeding 65535 bytes cannot be bundled. The SDK's envelope already
// enforces a smaller cap (MaxEntrySize in validation.go), so hitting this
// limit indicates a bug, not user input.
const MaxBundleEntrySize = 65535

// ─────────────────────────────────────────────────────────────────────
// 1. EntryIdentity — Tessera Entry.Identity() equivalent
// ─────────────────────────────────────────────────────────────────────

// EntryIdentity returns the SHA-256 of the entry's canonical bytes.
// This is the dedup key: two entries with identical EntryIdentity are
// the same entry and should not both be written to the log.
//
// Equivalent to Tessera's Entry.Identity() when the entry is constructed
// via tessera.NewEntry(envelope.Serialize(entry)) — both compute
// SHA-256(Serialize(entry)).
//
// This is ALSO equivalent to the SDK's existing envelope.EntryIdentity.
// Prefer EntryIdentity in new code; CanonicalHash remains for backward
// compatibility with existing call sites.
func EntryIdentity(entry *Entry) [32]byte {
	return sha256.Sum256(Serialize(entry))
}

// ─────────────────────────────────────────────────────────────────────
// 2. EntryLeafHash — Tessera Entry.LeafHash() equivalent (RFC 6962)
// ─────────────────────────────────────────────────────────────────────

// EntryLeafHash returns the RFC 6962 §2.1 leaf hash of the entry's
// canonical bytes: SHA-256(0x00 || Serialize(entry)).
//
// This is the hash that goes into Tessera tile leaves and into any
// Merkle inclusion / consistency proof rooted at a tree head the
// operator publishes.
//
// DO NOT confuse with EntryIdentity. They compute different hashes:
//
//	EntryIdentity(entry) = SHA-256(data)
//	EntryLeafHash(entry) = SHA-256(0x00 || data)
//
// Equivalent to Tessera's Entry.LeafHash() when the entry is constructed
// via tessera.NewEntry(envelope.Serialize(entry)) — both apply
// rfc6962.DefaultHasher.HashLeaf to the same bytes.
func EntryLeafHash(entry *Entry) [32]byte {
	data := Serialize(entry)
	h := sha256.New()
	// Writes to sha256 never return an error; intentionally ignored.
	_, _ = h.Write([]byte{RFC6962LeafPrefix})
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ─────────────────────────────────────────────────────────────────────
// 3. MarshalBundleEntry — Tessera Entry.MarshalBundleData() equivalent
// ─────────────────────────────────────────────────────────────────────

// MarshalBundleEntry serializes the entry into the per-entry wire shape
// used inside a Tessera EntryBundle, per c2sp.org/tlog-tiles:
//
//	uint16_BE(len(data)) || data
//
// The operator calls this to obtain bytes ready to append to an
// EntryBundle. The Tessera tile writer does not need to re-frame these
// bytes; they are already in bundle shape.
//
// Tessera's Entry.MarshalBundleData takes an index argument because some
// formats embed the index. The tlog-tiles default marshaller ignores
// index (see Tessera's NewEntry → marshalForBundle closure). This SDK
// follows the tlog-tiles default, so index is unused and omitted from
// the signature. If a future bundle format needs index, add a new
// function; do not overload this one.
//
// Panics (via a size check, not a silent truncation) if the serialized
// entry exceeds MaxBundleEntrySize. The SDK's envelope validation rejects
// oversized entries before they reach this function, so a panic here
// indicates a validation bypass bug.
func MarshalBundleEntry(entry *Entry) []byte {
	data := Serialize(entry)
	if len(data) > MaxBundleEntrySize {
		// Fail loud: NewEntry/Validate should have rejected with
		// ErrBundleEntryTooLarge. If this panics, a caller is either
		// skipping validation or hand-constructing an Entry bypassing
		// NewEntry. Silent truncation would corrupt every tile the
		// entry appears in; the panic is the invariant's last line
		// of defense.
		panic(fmt.Sprintf(
			"envelope: MarshalBundleEntry on invalid entry "+
				"(call Validate or NewEntry first): %d > %d",
			len(data), MaxBundleEntrySize))
	}
	out := make([]byte, 0, 2+len(data))
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	out = append(out, data...)
	return out
}

// ─────────────────────────────────────────────────────────────────────
// 4. BundleEntries — bulk helper for operators building whole bundles
// ─────────────────────────────────────────────────────────────────────

// BundleEntries marshals a slice of entries into concatenated
// tlog-tiles bundle shape. The output is the exact byte sequence a
// Tessera EntryBundle contains for these entries, in order.
//
// Provided as a convenience so operators never hand-roll the
// concatenation loop (and can't accidentally forget a length prefix
// mid-bundle). Equivalent to calling MarshalBundleEntry on each entry
// and appending the result.
func BundleEntries(entries []*Entry) []byte {
	// Pre-size the output buffer. Each entry contributes 2 bytes of
	// length prefix plus its data bytes. We compute the serialized
	// lengths up front to avoid repeated reallocation on append.
	total := 0
	serialized := make([][]byte, len(entries))
	for i, e := range entries {
		serialized[i] = Serialize(e)
		if len(serialized[i]) > MaxBundleEntrySize {
			panic("envelope: entry exceeds c2sp.org/tlog-tiles bundle size limit (65535 bytes)")
		}
		total += 2 + len(serialized[i])
	}
	out := make([]byte, 0, total)
	for _, data := range serialized {
		out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
		out = append(out, data...)
	}
	return out
}

// Append to core/envelope/tessera_compat.go

// EntryLeafHashBytes is EntryLeafHash for callers that hold the
// canonical bytes of an entry directly (e.g., from
// types.EntryWithMetadata.CanonicalBytes), avoiding the *Entry
// intermediate.
//
// Produces exactly the same hash EntryLeafHash produces for the same
// bytes: SHA-256(0x00 || canonical).
//
// Callers:
//   - core/smt/merkle_wrap.go:    StubMerkleTree.AppendLeaf
//   - verifier/cross_log.go:      BuildCrossLogProof source + anchor hashes
//   - operator builder/loop.go:   leaf-hash computation before AppendLeaf
//     (once operator is migrated to v6)
func EntryLeafHashBytes(canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{RFC6962LeafPrefix})
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleInteriorHash computes the RFC 6962 §2.1 interior node hash:
// SHA-256(0x01 || left || right).
//
// Exposed because downstream Merkle implementations (the SDK's stub
// tree, cross-log verifiers computing subtree roots, fraud-proof
// replay) must match this exactly to be interoperable with Tessera
// and with each other. Inlining this byte layout in multiple places
// is how the SDK previously drifted out of RFC 6962 compliance.
//
// Callers:
//   - core/smt/merkle_wrap.go: StubMerkleTree.hashLevel
//   - any future verifier that computes subtree roots independently
func MerkleInteriorHash(left, right [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = RFC6962NodePrefix
	copy(buf[1:33], left[:])
	copy(buf[33:65], right[:])
	return sha256.Sum256(buf[:])
}
