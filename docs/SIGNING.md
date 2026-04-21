Conceptual overview: what's signed, and whyThe core idea: A signature proves "the holder of this key authorizes this entry." But if signatures were stored outside the canonical bytes, an attacker could strip or replace them post-hoc. So v6 embeds signatures inside the canonical wire, making them cryptographically bound to the entry.This creates a circular-looking problem:

To produce canonical bytes, you need signatures.
To produce signatures, you need something to sign.
What do you sign if not the canonical bytes?
The elegant solution — there are two distinct byte sequences:SigningPayload = preamble + header + payload
Canonical      = SigningPayload + signatures_sectionThe signer signs SigningPayload (which doesn't contain signatures). The canonical wire bytes are SigningPayload || signatures_section. No circular dependency — signatures commit to content-that-excludes-signatures.This is the same trick RFC 6962 uses for certificate transparency: the TreeHeadSignature signs the head, not the head-plus-signature.The three SDK primitives you needReading the SDK source, here's the surface:go// (1) Build an entry WITHOUT signatures. No signatures list required.
//     Validates header, not signatures.
func NewUnsignedEntry(header ControlHeader, payload []byte) (*Entry, error)

// (2) Given an entry (signed or unsigned), return the bytes to sign.
//     Layout: [uint16 version] [uint32 hbl] [header] [uint32 payloadLen] [payload]
func SigningPayload(e *Entry) []byte

// (3) Build the FINAL entry with signatures embedded.
//     Validates: len(sigs) >= 1, sigs[0].SignerDID == header.SignerDID,
//     each sig's algorithm, size caps.
func NewEntry(header ControlHeader, payload []byte, signatures []Signature) (*Entry, error)And the Signature struct:gotype Signature struct {
    SignerDID string  // must match header.SignerDID for sigs[0]
    AlgoID    uint16  // e.g., SigAlgoECDSA, SigAlgoEd25519
    Bytes     []byte  // the raw signature bytes
}The five-step signing flowHere's what any self-signing code path (anchor publisher, commitment publisher, shard genesis) must do:Step 1 — Build the ControlHeaderPopulate fields: SignerDID, Destination, EventTime, plus whatever structural fields the entry type needs (null Target_Root for commentary, etc.).goheader := envelope.ControlHeader{
    SignerDID:   "did:web:operator.example.gov",
    Destination: "did:web:log.example.gov",
    EventTime:   time.Now().UTC().Unix(),
    // Target_Root nil, Authority_Path nil → commentary entry
}Step 2 — Build the payloadDomain-specific bytes. For anchor commentary:gopayload := json.Marshal(map[string]any{
    "anchor_type":    "tree_head_ref",
    "source_log_did": source.LogDID,
    "tree_head_ref":  hex.EncodeToString(treeHeadRef[:]),
    "anchored_at":    time.Now().UTC().Format(time.RFC3339),
})Step 3 — Construct the unsigned entrygounsigned, err := envelope.NewUnsignedEntry(header, payload)
if err != nil {
    return fmt.Errorf("build unsigned: %w", err)
}This validates the header. Returns an *Entry with Signatures: nil.Step 4 — Sign the SigningPayloadgotoSign := envelope.SigningPayload(unsigned)
// toSign is the bytes the signer commits to

// For ECDSA-P256-SHA256:
digest := sha256.Sum256(toSign)
r, s, err := ecdsa.Sign(rand.Reader, operatorPrivateKey, digest[:])
if err != nil {
    return fmt.Errorf("sign: %w", err)
}

// Format signature as 64-byte r||s concatenation (SDK convention)
sigBytes := make([]byte, 64)
rBytes, sBytes := r.Bytes(), s.Bytes()
copy(sigBytes[32-len(rBytes):32], rBytes)
copy(sigBytes[64-len(sBytes):64], sBytes)Notice what's signed: toSign is the header + payload, NOT signatures. The signature commits to the entry content but the entry content does not commit to the signature. No recursion.Step 5 — Construct the final signed entrygoentry, err := envelope.NewEntry(header, payload, []envelope.Signature{{
    SignerDID: header.SignerDID,       // MUST match (SDK enforces this)
    AlgoID:    envelope.SigAlgoECDSA,  // 0x0001 from signature_algo.go
    Bytes:     sigBytes,
}})
if err != nil {
    return fmt.Errorf("build signed: %w", err)
}Now envelope.Serialize(entry) produces the complete wire bytes — SigningPayload || signatures_section — ready for admission.Why each design choice mattersWhy two constructors exist (NewEntry + NewUnsignedEntry)NewEntry is for callers who already have signatures (e.g., the operator receives a pre-signed entry at the submission endpoint, deserializes it, validates it).NewUnsignedEntry is for callers who construct the entry then sign it (operator self-signing, SDK builders in entry_builders.go). They need to produce SigningPayload before they can sign.Without NewUnsignedEntry, self-signing would need to construct an Entry struct by hand, bypassing validation — exactly the footgun v6 wants to eliminate.Why Signatures[0].SignerDID must equal Header.SignerDIDThe protocol routes authority on Header.SignerDID. If the primary signature's DID differed from the header's, the log would attest that some key signed the entry, but not that the authorized key signed it. Binding them together prevents an attacker with any valid key from authorizing an entry under someone else's DID.Why cosignatures are a slice, not a separate fieldCourt-cosigned judgments, witness-cosigned checkpoints, committee-cosigned accreditations — all need multiple signatures in a fixed order. Representing them as []Signature with sigs[0] as primary and sigs[1:] as cosigners matches the protocol semantics directly, and serializes cleanly without separate "primary" and "cosigner" wire sections.Why algorithm ID is per-signature, not per-entryA judge might sign with ECDSA (hardware wallet), a clerk with Ed25519 (software key), a witness with a JWZ ZK-proof (Polygon ID). One entry, three algorithms, three signatures. The per-signature AlgoID makes this natural.Why the signing payload excludes signaturesTo avoid circular hash dependency. If signatures were inside the signing payload, signing would require a hash of something that includes the signature — impossible without a fixed-point iteration. RFC 6962 makes the same choice for tree head signatures.Why Serialize panics on invalid entriesSerialize is called by Merkle tree code expecting a total function (always returns bytes, never an error). Validation happens upstream at NewEntry or Validate(). If someone hand-constructs an invalid Entry and calls Serialize, panicking is correct — producing defensive-but-invalid bytes would silently corrupt every Merkle tile the entry appears in.