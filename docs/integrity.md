To fully understand the Ortholog SDK's security model, you have to look at it as a nested hierarchy of trust. Cryptography in this system isn't just applied at the network edge; it is layered so that different actors (users, operators, witnesses, and foreign networks) mathematically prove their claims to each other without having to trust one another.

Here is the objective breakdown of all 5 layers of signatures and integrity verifications in the Ortholog architecture, from the innermost payload to the outermost global consensus.



---

### Layer 1: The Origin Layer (Envelope Signatures)
**Purpose:** Proves *who* authorized an action and ensures the payload wasn't tampered with in transit.
* **The Mechanism:** When a domain application (like a court CMS) generates an entry, the SDK wraps it in an `Envelope`. The SDK computes the canonical byte representation of this entry and hashes it.
* **The Signature:** The origin actor (e.g., a judge's DID or an automated scheduling system) signs this digest using an **ECDSA secp256k1** private key (`crypto/signatures/entry_verify.go`).
* **The Verification:** When the entry arrives at the exchange/operator, the admission gate checks that `Signatures[0].SignerDID` matches the `Header.SignerDID`, and that the cryptographic signature resolves to that DID's public key.
* **Failure Mode Avoided:** Man-in-the-middle attacks, payload tampering, and identity spoofing (prevented, as long as DIDs are correctly mapped).

### Layer 2: The Structural Layer (Merkle Inclusion & SMT)
**Purpose:** Proves *when* the action happened, its sequence, and the current absolute state of the database.
* **The Mechanism:** The log operator (backed by Tessera) takes the cryptographically signed envelope from Layer 1 and appends it to a cryptographic ledger.
* **The Integrity:**
    1.  **Append-Only Sequence (RFC 6962):** The entry is hashed (`sha256(0x00 || entry_bytes)`) and added as a leaf to a dense Merkle tree.
    2.  **Current State (SMT):** The entry modifies a Sparse Merkle Tree (SMT), updating the `AuthorityTip` and `OriginTip`. 
* **The Verification:** Anyone can query the log and run `smt.VerifyMerkleInclusion` to prove that a specific entry mathematically exists at sequence *N* in the log.
* **Failure Mode Avoided:** The operator secretly deleting a case, backdating a filing, or altering historical records.



### Layer 3: The Consensus Layer (Witness Cosignatures)
**Purpose:** Prevents a rogue operator from maintaining "split brain" ledgers (showing one history to Court A and a different history to Court B).
* **The Mechanism:** Periodically, the operator publishes a `TreeHead` (a 40-byte commitment containing the 32-byte `RootHash` and 8-byte `TreeSize`). 
* **The Signatures:** Independent "Witness" nodes observe this tree head. If they agree it is valid and append-only, they sign it. 
    * **Heterogeneous Dispatch (Wave 2):** Witnesses can sign using legacy **ECDSA** (verified sequentially) or modern **BLS12-381** (optimistically aggregated into a single $O(1)$ pairing check).
* **The Verification:** The `VerifyWitnessCosignatures` dispatcher checks these signatures against a configured Witness Registry. It strictly requires a **K-of-N quorum** (e.g., 5 out of 7 witnesses must mathematically agree on the `TreeHead` for it to be considered valid).
* **Failure Mode Avoided:** The "Equivocation" attack, where a corrupt central operator tries to lie about the true state of the log.

### Layer 4: The Federated Layer (Cross-Log Proofs)
**Purpose:** Allows completely distinct transparency logs (e.g., Davidson County and Shelby County) to mathematically trust each other without API bridges.
* **The Mechanism:** A `CrossLogProof` bundles the Layer 2 structural proof of Log A into the payload of Layer 1 in Log B. 
* **The Integrity:** Court B wants to verify a protective order issued in Court A. Court B receives a proof containing Court A's entry, Court A's Merkle inclusion proof, and Court A's Witness-cosigned Tree Head. 
* **The Verification:** The `VerifyCrossLogProof` function verifies the witness signatures on the foreign tree head, then verifies the inclusion proof against that root, and finally checks the entry signature.
* **Failure Mode Avoided:** Reliance on centralized state-wide SQL databases or fragile REST API integrations for cross-jurisdictional truth.

### Layer 5: The Semantic & Transport Layers (Domain Rules & ECIES)
**Purpose:** Enforces business logic and protects data secrecy over the transparent ledger.
* **Semantic Integrity:** Even if an entry passes Layers 1 through 4 (it is cryptographically valid and on the log), the domain application runs a `ConditionEvaluator`. This checks the *meaning* of the data (e.g., checking the `ScopeLimit` of a delegation to ensure an automated scheduler didn't try to sign a court order).
* **Data Secrecy (ECIES):** Because logs are public, secret material (like M-of-N recovery shares for encrypted evidence) cannot be stored in plaintext. `crypto/escrow/ecies.go` wraps the 32-byte secret in an Ephemeral ECDH key, derives an AES-GCM key, and encrypts it. The GCM authentication tag acts as a final micro-layer of integrity, ensuring the ciphertext wasn't bit-flipped before decryption.

### Summary
If you submit a sealing order to the judicial network:
1. Your private key signs the order **(Layer 1)**.
2. The operator hashes it into the tree **(Layer 2)**.
3. 5 independent servers cosign the new tree root **(Layer 3)**.
4. The State AOC log anchors that root into its own tree **(Layer 4)**.
5. A foreign court verifies the semantic permissions and math before accepting it **(Layer 5)**.