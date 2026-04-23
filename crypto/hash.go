// Package crypto provides general-purpose cryptographic primitives that
// are not Entry-specific. For Entry canonical hashing, see the envelope
// package instead.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// HashBytes returns SHA-256 of arbitrary bytes.
//
// For Entry canonical hashes, do NOT use this function. Use the
// Tessera-aligned primitives in the envelope package:
//
//   - envelope.EntryIdentity(entry)      — dedup key (SHA-256 of canonical bytes)
//   - envelope.EntryLeafHash(entry)      — RFC 6962 Merkle leaf hash for Tessera
//   - envelope.MarshalBundleEntry(entry) — c2sp.org/tlog-tiles bundle framing
//
// Mixing HashBytes with Entry canonical bytes would bypass destination-
// binding validation and produce plain SHA-256 where RFC 6962 is required
// for Merkle proofs. Use envelope.* for anything Entry-shaped.
func HashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// maxLengthPrefixedField is the upper bound on any length-prefixed field
// (including the DST). The 2-byte length caps at 65535; any legitimate
// cryptographic identifier fits comfortably under this, and a >65KB field
// is a caller bug. LengthPrefixed panics rather than silently truncating.
const maxLengthPrefixedField = 1<<16 - 1

// LengthPrefixed is the TupleHash-style canonicalization primitive
// every SDK-internal cryptographic identifier MUST route through. It
// writes, in order:
//
//  1. 2-byte big-endian length of dst
//  2. dst bytes
//  3. for each field: 2-byte big-endian length of the field, then
//     the field bytes
//
// then returns SHA-256 of the result. This is the universal length-
// prefix rule locked by ADR-005 §2.
//
// # TupleHash discipline
//
// Length-prefix everything. No exceptions at the call-site level —
// every SDK identifier that hashes variable-length inputs routes
// through this helper. Raw-concatenation constructions for SplitIDs,
// commitment hashes, transcript inputs, and domain-app identifiers
// are forbidden. The length prefix on the DST is not optional:
// treating the DST as an unprefixed constant and length-prefixing
// only the fields readmits the boundary-shift collision class that
// this rule exists to prevent.
//
// # RFC 9380 carveout
//
// The only strings that skip this helper are the IETF-standardized
// hash-to-curve suite IDs embedded inside expand_message_xmd — the
// DST format defined in RFC 9380 §3.1, applied during BLS12-381
// point derivation. Those suite IDs (e.g.,
// "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") are governed by
// the IETF specification and interop with external BLS
// implementations depends on using them exactly as the RFC
// specifies. They do not route through LengthPrefixed.
//
// # Ortholog-bespoke tags are NOT carveouts
//
// The cosignature domain tag and the Proof-of-Possession domain
// tag used in crypto/signatures/bls_verifier.go are application-
// layer DSTs unique to this protocol. They namespace Ortholog-
// internal BLS signatures against cross-protocol confusion, and
// they get composed with variable-length Ortholog fields (entry
// hashes, tree head hashes, signer identifiers) at signing and
// verification time. If those compositions are raw-concatenated,
// the BLS verification path inherits the exact boundary-shift
// collision class the universal rule exists to prevent. The
// cosignature domain tag and PoP domain tag MUST migrate to
// LengthPrefixed; that migration is scoped to the composition-
// layer audit pass that covers bls_verifier.go. These tags are
// migration targets, not exceptions — naming them explicitly here
// prevents future drift.
//
// # Caller-normalizes contract
//
// NFC normalization of DIDs and other Unicode strings happens at
// the edge where the caller enters the SDK, never inside this
// function. LengthPrefixed operates on raw bytes; if two callers
// pass different byte sequences for what they consider "the same"
// DID, they get different hashes. This is by design — the SDK
// does not guess at caller intent.
//
// # Bounds
//
// Each field (and the DST) is limited to 65535 bytes by the 2-byte
// length prefix. Exceeding that bound panics because any legitimate
// cryptographic identifier fits comfortably under it and an over-
// length field is a caller bug.
func LengthPrefixed(dst string, fields ...[]byte) [32]byte {
	if len(dst) > maxLengthPrefixedField {
		panic(fmt.Sprintf("crypto/hash: DST length %d exceeds %d", len(dst), maxLengthPrefixedField))
	}
	h := sha256.New()
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dst)))
	h.Write(lenBuf[:])
	h.Write([]byte(dst))
	for i, f := range fields {
		if len(f) > maxLengthPrefixedField {
			panic(fmt.Sprintf("crypto/hash: field %d length %d exceeds %d", i, len(f), maxLengthPrefixedField))
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(f)))
		h.Write(lenBuf[:])
		h.Write(f)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
