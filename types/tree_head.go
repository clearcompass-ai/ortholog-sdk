/*
FILE PATH:

	types/tree_head.go

DESCRIPTION:

	Canonical types for cosigned tree heads and witness cosignatures.
	The tree head is the committed state of a transparency log at a
	given point in time; witnesses cosign the head to attest they have
	observed this specific (RootHash, TreeSize) pair and consider it
	the log's current consistent state.

	This file is the protocol boundary between the SDK and every
	consumer that produces, transports, persists, or verifies witness
	cosignatures. Field order, field presence, and field semantics
	here are load-bearing. Changes to these types are protocol changes
	and must be treated accordingly.

WAVE 2 CHANGE: Per-signature scheme dispatch

	This file changed in Wave 2. Prior to Wave 2, the scheme tag lived
	on CosignedTreeHead as a head-level field, forcing every witness
	in a cosigned head to use the same signing scheme. Post-Wave-2 the
	scheme tag lives on each WitnessSignature independently, enabling
	heterogeneous witness sets where different witnesses operate under
	different cryptographic schemes.

	The motivation is operational: witness rotation, onboarding,
	regulatory constraint on specific witnesses (e.g., an HSM that
	only speaks ECDSA while the rest of the network has migrated to
	BLS), and forward compatibility with future scheme additions all
	benefit from per-signature scheme declaration. The alternative —
	all-or-nothing scheme migration for entire witness sets — would
	force lockstep coordination across every deployed witness for
	every future scheme upgrade, which is operationally intractable.

	The cost is a one-byte overhead per signature on the wire. This
	is negligible compared to the ~64-byte (ECDSA) or ~48-byte (BLS)
	signature payload itself.

KEY ARCHITECTURAL DECISIONS:

  - Tree head shape preserved. RootHash [32]byte + TreeSize uint64 is
    the canonical 40-byte commitment covered by WitnessCosignMessage.
    Wave 2 does NOT change the signed message; the signing target
    bytes are identical before and after the refactor. Existing BLS
    signatures, ECDSA signatures, and hash-to-curve lock vectors all
    remain valid.

  - SchemeTag on WitnessSignature is required and non-zero. The zero
    value (0x00) is reserved for "scheme not declared" and MUST be
    rejected by every verifier. Wave 1 tests already lock
    SchemeECDSA=0x01 and SchemeBLS=0x02 as the only currently-valid
    values. Unknown non-zero values are also rejected (future scheme
    additions must propagate through the dispatcher deliberately).

  - Field ordering in WitnessSignature: PubKeyID → SchemeTag →
    SigBytes. This order matches the conceptual flow: "who signed,
    what scheme, the bytes." Wire encoders that serialize these
    structs should follow the same order for consistency, though
    individual JSON/CBOR/Tessera encoders may permute within their
    own conventions.

  - CosignedTreeHead no longer carries SchemeTag. Any consumer still
    reading head.SchemeTag after Wave 2 is a compile error. The AST
    audit at cmd/verify-bls-refactor guards against regressions.

  - No JSON tags on these types. Go's JSON library defaults to
    exporting fields by their Go name, which is what the operator
    wire format uses. Adding explicit tags would be gratuitous; not
    having them matches the existing Tessera-compatible convention
    in witness/tree_head_client.go.

OVERVIEW:

	Constructing a cosigned tree head (typical producer pattern):
	    head := TreeHead{RootHash: root, TreeSize: size}
	    sigs := []WitnessSignature{
	        {PubKeyID: id1, SchemeTag: SchemeECDSA, SigBytes: ecdsaSig},
	        {PubKeyID: id2, SchemeTag: SchemeBLS,   SigBytes: blsSig},
	    }
	    cosigned := CosignedTreeHead{TreeHead: head, Signatures: sigs}

	Verification (typical consumer pattern):
	    msg := WitnessCosignMessage(cosigned.TreeHead)  // 40 bytes
	    // dispatcher reads each sig's SchemeTag independently

RELATED:
  - crypto/signatures/witness_verify.go: the per-signature dispatcher
    that reads WitnessSignature.SchemeTag and routes to ECDSA or BLS
    verification accordingly
  - witness/rotation.go: enforces per-signature SchemeTag matches the
    rotation's declared SchemeTagOld / SchemeTagNew
  - witness/tree_head_client.go: parses operator wire format and
    populates WitnessSignature.SchemeTag from the SigAlgo field
*/
package types

// TreeHead is the canonical state commitment of a transparency log
// at a point in time. Width is 40 bytes (32-byte RootHash + 8-byte
// big-endian TreeSize), matching the output of WitnessCosignMessage.
//
// This is the message signed by witnesses during cosignature. Any
// change to field width, ordering, or endianness here would
// invalidate every witness signature ever produced.
type TreeHead struct {
	// RootHash is the 32-byte Merkle root of the log at TreeSize.
	// The hash algorithm is the log's configured digest (SHA-256 in
	// the default Ortholog profile; locked via the MerkleInteriorHash
	// primitive in core/smt/merkle_wrap.go).
	RootHash [32]byte

	// TreeSize is the number of leaves in the log. Wire encoding is
	// big-endian across all transports (see WitnessCosignMessage).
	TreeSize uint64
}

// CosignedTreeHead is a tree head accompanied by witness
// cosignatures. Each signature carries its own scheme tag (Wave 2)
// so that heterogeneous witness sets can cosign the same head with
// different cryptographic schemes.
//
// Pre-Wave-2 this type carried a head-level SchemeTag that forced
// every signature in a single head to use the same scheme. That
// field was removed in Wave 2; see file-header for rationale.
type CosignedTreeHead struct {
	// TreeHead is the committed state. Embedded so callers can
	// access head.RootHash and head.TreeSize directly.
	TreeHead

	// Signatures is the set of witness cosignatures over this head.
	// Order is not semantically significant but should be preserved
	// on the wire for reproducibility. Each signature declares its
	// own SchemeTag; the verifier dispatches per-signature.
	Signatures []WitnessSignature
}

// WitnessSignature is a single witness's cosignature over a tree
// head, along with the scheme identifier that determines how the
// signature bytes are verified.
//
// SchemeTag is required and non-zero. Verifiers reject signatures
// with SchemeTag == 0 (reserved for "not declared") and signatures
// with unknown non-zero scheme tags (defensive rejection of
// future-scheme signatures until they're explicitly supported).
//
// The current valid scheme values are:
//
//	SchemeECDSA = 0x01  (secp256k1, 64-byte raw R||S, low-S normalized)
//	SchemeBLS   = 0x02  (BLS12-381 aggregate, 48-byte compressed G1)
//
// Both are defined as constants in crypto/signatures/witness_verify.go.
// New scheme values require protocol coordination and a dispatcher
// update; they should not be added silently.
type WitnessSignature struct {
	// PubKeyID is the 32-byte identifier of the witness public key
	// that produced SigBytes. Typically derived from the public key
	// bytes via sha256, but the derivation is caller-defined and
	// must match the corresponding WitnessPublicKey.ID in the
	// verifier's witness set.
	PubKeyID [32]byte

	// SchemeTag declares the signing scheme for SigBytes. Must be
	// non-zero and must be one of the dispatcher-known values.
	// Declared on every signature in Wave 2 and later; pre-Wave-2
	// signatures carried the scheme at the head level and did not
	// populate this field.
	SchemeTag byte

	// SigBytes is the raw signature material under SchemeTag. Length
	// and encoding are scheme-specific:
	//   - SchemeECDSA: 64 bytes, R||S big-endian, low-S normalized
	//   - SchemeBLS:   48 bytes, compressed G1 point
	// Length mismatches are rejected at verification time with a
	// scheme-specific error message.
	SigBytes []byte
}

// WitnessCosignMessage canonicalizes a TreeHead into the 40-byte
// message that witnesses sign. This is the exact byte sequence
// consumed by every scheme-specific signing primitive:
//
//	SchemeECDSA: sha256.Sum256(msg[:]) → SignEntry
//	SchemeBLS:   HashToG1(msg[:], BLSDomainTag) → scalar multiply
//
// Wave 2 does NOT change this function. The signed message bytes
// remain identical before and after the per-signature-scheme
// refactor, meaning signatures produced under the old shape are
// still cryptographically valid — only the wire encoding of the
// containing CosignedTreeHead changes.
//
// Byte layout:
//
//	[0:32]  RootHash (32 bytes, big-endian matches stored order)
//	[32:40] TreeSize (8 bytes, big-endian)
//
// This ordering is locked by:
//   - TestHashToG1_LockedOutput_CosigDST (hash-to-curve vector)
//   - Every round-trip test in crypto/signatures/*_test.go
//
// Any change to this function is a breaking protocol change
// requiring new scheme versions, not an in-place modification.
func WitnessCosignMessage(head TreeHead) [40]byte {
	var msg [40]byte
	copy(msg[0:32], head.RootHash[:])
	msg[32] = byte(head.TreeSize >> 56)
	msg[33] = byte(head.TreeSize >> 48)
	msg[34] = byte(head.TreeSize >> 40)
	msg[35] = byte(head.TreeSize >> 32)
	msg[36] = byte(head.TreeSize >> 24)
	msg[37] = byte(head.TreeSize >> 16)
	msg[38] = byte(head.TreeSize >> 8)
	msg[39] = byte(head.TreeSize)
	return msg
}
