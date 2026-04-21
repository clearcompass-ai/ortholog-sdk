Here is the complete, architect-level conceptual overview of the Ortholog SDK’s verification, signing, and integrity model. This document bridges the gap between the low-level cryptographic mechanics (how bytes are assembled) and the macroscopic trust model (how logs hold operators accountable).

***

# Ortholog SDK: Cryptographic Integrity & Verification Architecture

## 1. Core Philosophy: The Skeptical Verifier
The Ortholog SDK operates on a "trust nothing, verify everything" model. It treats the underlying storage operators (e.g., Tessera logs, Postgres databases) as inherently untrusted. 

Integrity is not achieved by database constraints or API access controls. It is achieved entirely by **cryptographic proofs** that allow any skeptical client to independently verify the authenticity, ordering, and state of the log. If an operator lies, truncates the log, or attempts to forge an entry, the verification primitives will mathematically fail.

---

## 2. Layer I: The Anatomy of a Signature (What is Signed, and Why?)
A log entry is only as trustworthy as the signature that authorizes it. But cryptographically binding a signature to an entry presents a circular dependency:
* To produce canonical bytes, you need the signatures.
* To produce signatures, you need the canonical bytes to sign.

**The Solution:** The SDK cleanly separates the entry into two distinct byte sequences:
1. `SigningPayload` = Preamble + Header + Payload
2. `CanonicalBytes` = `SigningPayload` + Signatures Section

The signer hashes and signs *only* the `SigningPayload` (which excludes signatures). The final canonical wire bytes embed that signature. Therefore, the signatures commit to content-that-excludes-signatures, avoiding recursion. 

### The 5-Step Signing Lifecycle
Any code path creating an entry (e.g., a court filing, a cross-log anchor, or a schema definition) follows this strict progression:
1. **Build the Header:** Declare the `SignerDID`, Destination, Event Time, and SMT targets.
2. **Build the Payload:** Serialize the domain-specific event data (e.g., a JSON blob or an encrypted artifact CID).
3. **Construct the Unsigned Entry:** `envelope.NewUnsignedEntry(header, payload)` initializes the struct and validates the header, but leaves the signature slice empty.
4. **Sign the Payload:** The SDK extracts `envelope.SigningPayload(unsigned)`, hashes it, and the keyholder executes the cryptographic signature (e.g., ECDSA, Ed25519) over the digest.
5. **Finalize:** The signature is injected into the entry, and `entry.Validate()` enforces the invariants.

### Architectural Invariants in the Envelope
* **`Signatures[0].SignerDID == Header.SignerDID`:** The protocol routes authority based on the Header. If the primary signature's DID differed from the header's, the log would attest that *some* key signed the entry, but not the authorized key. Binding them at the validation layer prevents impersonation.
* **Signatures are a Slice:** Multi-party authorization (e.g., a judge and a witness) is native. Representing signatures as `[]Signature` avoids separating "primary" and "cosigner" wire sections.
* **Per-Signature Algorithm IDs:** A judge might use a hardware wallet (ECDSA), while a clerk uses a software key (Ed25519). Embedding the `AlgoID` directly in the signature struct allows diverse, cryptographic interoperability on a single entry.

---

## 3. Layer II: Log Integrity and RFC 6962 Domain Separation
To prevent attacks against the Merkle log itself, the SDK strictly segregates hashing responsibilities to adhere to Certificate Transparency standards (RFC 6962). 

* **Deduplication vs. Inclusion:** There is a rigid type boundary between `EntryIdentity` (computed as `SHA-256(data)`) which operators use for simple deduplication, and the actual Merkle leaf hash.
* **Second-Preimage Defense:** All inclusion proofs and state tree leaves utilize `envelope.EntryLeafHashBytes`, which computes `SHA-256(0x00 || data)`. Interior tree nodes use `SHA-256(0x01 || left || right)` via `MerkleInteriorHash`. This prevents a fatal vulnerability where an attacker could submit an entry that perfectly mimics an interior node's hash, forging inclusion proofs.

---

## 4. Layer III: Cross-Log Verification (The Pure Function Principle)
When domains interact (e.g., a county recorder verifying a state-level schema, or a court anchoring its docket to a federal log), they use `VerifyCrossLogProof`. 

**The Pure Function Mandate:** Verifiers in transparency logs must be **pure functions**. Verification cannot require an injected `Fetcher` or live network I/O. If verification requires fetching data mid-flight, you introduce network timeouts, DNS failures, and authentication issues into what should be deterministic cryptographic math. The proof blob must be entirely self-contained.

Therefore, `VerifyCrossLogProof` executes a rigid, two-sided protocol entirely in memory:

### The Source Side (Mathematical Verification)
The verifier proves the event occurred in the foreign log without needing its heavy payload bytes:
1. **Hash Binding:** Asserts `SourceInclusion.LeafHash == SourceEntryHash` to prevent an attacker from pairing a fabricated entry hash with a valid, unrelated Merkle proof.
2. **Inclusion:** Mathematically verifies the `SourceInclusion` proof hashes up to the `SourceTreeHead.RootHash`.
3. **Quorum Verification:** Verifies the `SourceTreeHead` is cosigned by a valid K-of-N quorum of BLS witness keys, guaranteeing the foreign log is not an isolated, malicious fork.

### The Anchor Side (Physical Payload Extraction)
Unlike the source side, the verifier **must** inspect the local anchor entry to ensure the local log explicitly committed to the foreign event.
1. **Byte Substitution Defense:** Hashes the `AnchorEntryCanonical` bytes carried inside the proof and asserts they equal the proven `AnchorEntryHash`.
2. **Payload Extraction:** Deserializes the anchor bytes and passes the opaque `DomainPayload` to an injected `AnchorPayloadExtractor` closure. This allows the domain application (which knows its own JSON/Protobuf schema) to extract the embedded foreign tree head reference without tightly coupling the SDK to specific data formats.
3. **Final Commitment:** Asserts the extracted payload reference strictly matches the hash of the `SourceTreeHead` provided in the proof.

---

## 5. Layer IV: State Determinism and Fraud Proofs
While the Tessera append-only log guarantees *ordering* and *inclusion*, the Sparse Merkle Tree (SMT) calculates and guarantees *state correctness* (e.g., verifying if a judge's delegation is active or a court record is sealed).

* **Deterministic Transitions:** The builder processes batches of entries in exact log order. It categorizes them (Path A, B, or C) and calculates leaf updates, producing a strictly deterministic `NewRoot` and a sequence of `Mutations`.
* **Fraud Proof Replay:** Because the SMT logic relies purely on the canonical bytes and previous state root, any auditor or witness node can invoke `VerifyDerivationCommitment`. By feeding the prior SMT root and the batch of entries into the verifier, they compute the expected next root. If their calculated root diverges from the operator's published root, the operator is cryptographically proven to have committed fraud.