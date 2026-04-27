Based on the architectural evidence, specifications, and code files reviewed throughout this implementation, your system is divided into four highly decoupled layers. 

This decoupling is intentional: it prevents the system from turning into a monolithic application and ensures that the transparency log remains an objective, mathematically provable source of truth.

Here is the evidence-based breakdown of each component's role and the core guiding principles that bind them together.

### 1. The Roles of the Four Components

#### A. The Ortholog SDK (The Cryptographic Brain)
The SDK is the mathematical foundation of the entire ecosystem. It does not run as a standalone server; it is a library imported by clients, verifiers, and the Operator.
* **Role:** It is the sole authority on cryptographic primitives. It handles Elliptic Curve Cryptography (secp256k1), BLS signature aggregation, Pedersen Verifiable Secret Sharing (VSS), and Umbral Proxy Re-Encryption (PRE).
* **Responsibility:** It guarantees "Transparency by Construction." It enforces the Protocol v6 Canonical Wire Format and strictly refuses to serialize an entry unless it possesses a valid cryptographic signature. 

#### B. The Operator (The Gatekeeper & Sequencer)
The Operator is the physical server infrastructure that ingests data and maintains the log. It is split internally between a Postgres metadata layer and the Tessera personality.
* **Role:** It provides the HTTP API for submitting entries (`POST /v1/entries`), allocates gapless sequence numbers, and integrates entries into the Sparse Merkle Tree (SMT).
* **Responsibility:** It enforces admission rules. It checks the Proof-of-Work stamps (Argon2id), deducts fiat credits, catches exact duplicates, and maintains secondary indexes (like `SplitID`s) so clients can query the log quickly. 

#### C. The Artifact Store (The Off-Chain Vault)
Because the transparency log strictly caps entries at ~64KB to maintain compatibility with `c2sp.org/tlog-tiles`, massive files (like gigabytes of Sealed Evidence or Private Credentials) cannot live on the log itself.
* **Role:** It is a generic, horizontally scalable object storage system (like MinIO, S3, or IPFS) that natively implements the SDK's `storage.ContentStore` interface.
* **Responsibility:** It securely holds massive, encrypted ciphertext blobs off-chain, and returns a tiny 32-byte `storage.CID` (Content Identifier). This CID is placed onto the transparency log, mathematically binding the infinite off-chain storage to the immutable on-chain record without blowing up the database size.

#### D. The Domain Network (e.g., The Judicial Network)
This is the application layer built by you (or independent NGOs, universities, and courts). 
* **Role:** It gives meaning to the bytes. While the SDK handles the math and the Operator stores the data, the Domain Network defines what a "Judicial Override" or a "Proxy Re-Encryption Grant" actually means in the real world.
* **Responsibility:** It provides the UI, manages human governance, resolves legal disputes, and deploys any "Normalizing Shims" (API Gateways) required to clean up bad client inputs before they hit the operator.

---

### 2. The Guiding Principles of the Architecture

The codebase strictly enforces three core architectural principles. Violating any of these breaks the system's security model.

#### Principle 1: The Domain/Protocol Separation Principle
**"The Operator does not care what your payload means."**
* The Operator treats the `DomainPayload` of an entry as opaque bytes. When processing a batch of entries, the Operator never cracks open the payload to police domain-level logic (e.g., it does not enforce that a PRE Grant must accompany a PRE Commitment). 
* *Why:* If the Operator policed domain logic, it would become a centralized, heavily-coupled bottleneck. By keeping the Operator dumb and pushing domain validation to the SDK and the Verifiers, the network remains decentralized and agnostic to future use-cases.

#### Principle 2: The Caller-Normalizes (Validation-Only) Contract
**"The Operator will reject bad data, but it will never fix it."**
* The Operator strictly asserts that inputs (like `SignerDID` and `Destination`) are NFC-normalized Unicode. However, if they are not, it throws a `422 Unprocessable Entity` rather than cleaning them up.
* *Why:* If the Operator secretly mutated (normalized) a byte string after a client had already cryptographically signed it, the signature would break, and downstream verifiers would calculate a different canonical hash. The canonical bytes stored on the log MUST exactly match what the signer signed.

#### Principle 3: Transparency by Construction
**"Unsigned data cannot be serialized."**
* In Protocol v6, signatures are not sidecars; they are an inline component of the canonical wire format. The SDK's `envelope.Serialize()` function is a "total function" that actively panics if a developer attempts to serialize a payload without first attaching a valid cryptographic signature.
* *Why:* This prevents "silent regressions" where developers might accidentally write log entries that bypass authorization gates. It forces tests and production code to physically prove cryptographic intent before bytes can ever leave the application layer.