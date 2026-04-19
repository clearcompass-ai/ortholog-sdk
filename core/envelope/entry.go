/*
FILE PATH:
    core/envelope/entry.go

DESCRIPTION:
    The Entry type — the in-memory representation of a protocol log entry.
    Under v6 Entry carries three components: the ControlHeader (protocol
    mechanics), the DomainPayload (opaque domain bytes), and the Signatures
    list (cryptographic proof over the signing payload).

KEY ARCHITECTURAL DECISIONS:
    - Signatures are a slice, not a single sig. v6 admits entry-level
      multi-sig natively: a user-authorized entry cosigned by a court
      carries two signatures, not one sig plus a separate cosignature
      entry. The Merkle leaf hash commits to the full slice (via
      Serialize's output), so the log attests to exactly which signatures
      were present at submission time.
    - Invariant: Signatures[0].SignerDID == Header.SignerDID. The primary
      signature is from the authorizing party; additional signatures are
      cosigners. Enforced by Entry.Validate and by the decoder in
      serialize.go.
    - Insertion order is preserved. No canonicalizing sort on the slice —
      the submitter declares the cosigner sequence, and reordering would
      defeat the "primary signer first" invariant.
    - DomainPayload is []byte (opaque). The SDK does not parse it. Domain
      semantics travel via SchemaRef per the domain/protocol separation
      principle (see control_header.go).

OVERVIEW:
    Entries are produced by:
      - envelope.NewEntry(header, payload, signatures) — the fully-signed
        constructor for callers that already hold all signatures.
      - envelope.NewUnsignedEntry(header, payload) — the build-then-sign
        constructor for the 18 builder/entry_builders.go callers that
        construct entries before obtaining signatures. Callers append to
        entry.Signatures, then call Validate() before Serialize.
      - envelope.Deserialize(canonicalBytes) — the wire parser.

    Entries are consumed by:
      - envelope.Serialize(entry) for wire output
      - crypto/signatures/entry_verify.go VerifyEntrySignatures for
        signature verification
      - builder/algorithm.go processEntry for path classification
        (reads Header fields only)
      - tessera_compat.go EntryIdentity/EntryLeafHash/MarshalBundleEntry

KEY DEPENDENCIES:
    - control_header.go: ControlHeader struct definition
    - signatures_section.go: Signature struct definition
*/
package envelope

// -------------------------------------------------------------------------------------------------
// 1) Entry struct
// -------------------------------------------------------------------------------------------------

// Entry is the in-memory representation of a protocol log entry at v6.
//
// Serialize(entry) produces the canonical wire bytes that Tessera stores
// and that the Merkle leaf hash commits to. The three fields together
// constitute the full entry state; there is no external sidecar for any
// cryptographic or protocol-semantic data.
type Entry struct {
	// Header carries protocol mechanics: signer DID, destination exchange,
	// target references, authority path discriminator, delegation chain,
	// scope authority set, and so on. Every field is read by the builder
	// or verifier as part of path classification and state evaluation.
	// Domain vocabulary never appears here (see control_header.go).
	Header ControlHeader

	// DomainPayload is the domain-governed bytes attached to this entry.
	// The SDK treats this as opaque — its structure is defined by the
	// schema entry referenced by Header.SchemaRef. Common domain uses:
	// credential attestations, recording-instrument metadata, scope
	// governance proposals.
	DomainPayload []byte

	// Signatures carries one or more cryptographic proofs over the
	// entry's SigningPayload (preamble + header + payload bytes).
	//
	// Invariants (enforced by Validate and by Deserialize):
	//   - len(Signatures) >= 1
	//   - len(Signatures) <= MaxSignaturesPerEntry (64)
	//   - Signatures[0].SignerDID == Header.SignerDID
	//   - Every Signature's AlgoID is registered (ValidateAlgorithmID)
	//   - Every Signature's DID is non-empty ASCII, <= MaxSignerDIDLen
	//   - Every Signature's Bytes length <= MaxSignatureBytes
	//
	// The primary signature at index 0 is from the authorizing party
	// (same DID as Header.SignerDID). Subsequent signatures are
	// cosigners in submitter-declared order.
	Signatures []Signature
}
