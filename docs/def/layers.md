# Ortholog SDK Architecture: The 4-Tier Internal Dependency Graph

## Overview: The Zero-Trust Hierarchy

The Ortholog SDK is fundamentally designed around a strict, **four-tier, one-way dependency graph**. This architectural constraint guarantees that cryptographic mathematics never accidentally rely on high-level business logic, and that state transitions are never polluted by composition-layer requirements. 

A layer within this SDK is strictly prohibited from importing packages from a layer above it. Information and dependencies flow in exactly one direction: upwards.

This document details the four layers, their distinct roles, their sub-packages, and the strict rules that govern them.

---

## Layer 1: The Pure Cryptography Layer (`crypto/`)

**The Role:** This layer knows absolutely nothing about the log, the Sparse Merkle Tree (SMT), or domain rules. It answers a single, foundational question: *"Is this math valid?"*

**The Rule:** It imports nothing but standard Go mathematics and cryptography libraries. It acts as the "Physics" engine of the SDK.

### Core Components

* **Canonicalization (`crypto/hash.go`)**
    This package implements the universal `LengthPrefixed` TupleHash primitive. It enforces the rule that all fields (and their Domain Separation Tags) must be length-prefixed with 2-byte Big-Endian integers before hashing. This mathematically eliminates boundary-shifting collisions and ensures 50-year forward compatibility across all derived identifiers.

* **Signature Verification (`crypto/signatures/`)**
    This sub-package handles digital signatures across multiple elliptic curves:
    * `secp256k1` and `Ed25519` for standard entry payload signatures.
    * Ethereum-compatible `EIP-191` and `EIP-712` verification for Web3 wallets.
    * `BLS12-381` and IETF RFC 9380 Hash-to-Curve implementations for threshold aggregate signatures used by decentralized Witness nodes.

* **Proxy Re-Encryption (`crypto/artifact/`)**
    Houses the Umbral Proxy Re-Encryption (PRE) scheme. It is strictly responsible for generating threshold `KFrags`, executing dual-gate `VerifyCFrag` logic, and performing Discrete Logarithm Equality (DLEQ) proofs. It dictates how artifacts are mathematically sealed and selectively unsealed.

* **Verifiable Secret Sharing (`crypto/escrow/`)**
    Implements Pedersen Verifiable Secret Sharing (VSS). It mathematically splits master keys into `N` shares and derives `SplitID`s, utilizing ECIES wrapping so shares can traverse hostile networks without exposing plaintext.

---

## Layer 2: The Data Structure Layer (`core/`)

**The Role:** This layer defines the physical shape of the data at rest. It answers the question: *"Is this structure valid?"*

**The Rule:** It imports `crypto/` to hash its structures and verify signatures, but it has zero concept of how these structures evolve over time or how they are submitted to a log.

### Core Components

* **The Protocol Constitution (`core/envelope/`)**
    This package defines the `ControlHeader`—the rigid, protocol-level metadata that dictates how an entry behaves. It extracts domain concepts into opaque payloads, leaving only protocol mechanics (e.g., `TargetRoot`, `AuthorityPath`, `SignerDID`). It also defines canonical serialization rules to ensure that two identical entries produce the exact same cryptographic hash across any architecture.

* **The State Geometry (`core/smt/`)**
    Defines the geometry of the Sparse Merkle Tree (SMT). It handles the mechanics of `LeafReader`, overlays, and the generation/verification of Merkle inclusion proofs. It provides the memory-efficient overlay node cache required to compute deep tree updates without flushing to disk.

* **Polynomial Commitments (`core/vss/`)**
    Defines the structure for threshold commitments, handling point-math on the curve and ensuring that threshold logic from Layer 1 can be accurately structured and persisted into memory blocks.

---

## Layer 3: The State Transition Layer (`builder/`, `witness/`)

**The Role:** This layer governs time, sequence, and mutability. It answers the question: *"Is this sequence of events legally allowed to update the ledger?"*

**The Rule:** It imports `core/` to read the data structures and subsequently updates the SMT. It relies purely on the structural rules defined in the `ControlHeader`. It does not execute business logic; it acts as a mechanical clockwork.

### Core Components

* **The Admission Engine (`builder/algorithm.go`)**
    The heart of the SMT mutation engine. It mechanically routes every submitted entry through one of the mathematically defined authority paths:
    * **Path A (Same Signer):** Direct amendments where the `SignerDID` matches the entity's root creator.
    * **Path B (Delegation Chain):** Traces a hierarchical array of `DelegationPointers` to verify that the signer possesses live, unrevoked authority delegated from the root institution.
    * **Path C (Scope Authority):** Validates the signer against a decentralized governing board (Scope Entity), enforcing Optimistic Concurrency Control (OCC) via `PriorAuthority`.

* **Tree Mutability & Concurrency (`builder/concurrency.go`)**
    Ensures that SMT updates do not collide. It manages atomic batch processing and resolves commutativity logic for domain applications that require high-throughput parallel execution.

* **Witness Consensus (`witness/`)**
    Calculates tree head staleness, detects equivocation, and orchestrates $K$-of-$N$ threshold aggregate signature verification to ensure the SMT root is properly certified by independent nodes.

---

## Layer 4: The Composition & Authorization Layer (`verifier/`, `lifecycle/`)

**The Role:** This layer allows external systems to interact with the log safely. It answers the ultimate question: *"Is this complex business action cryptographically authorized?"*

**The Rule:** It imports everything below it. It acts as the primary API surface for the Domain Applications (e.g., Tessera, Judicial Networks), orchestrating multi-step cryptographic actions.

### Core Components

* **Historical Proof & Verification (`verifier/`)**
    Performs rigorous, read-only audits on the ledger. 
    * `authority_evaluator.go`: Walks historical SMT chains to evaluate scope membership over decades. Protects against constraint laundering and DoS attacks via authority snapshots.
    * `cross_log.go`: Evaluates complex 9-step cross-log proofs, allowing an entry on a foreign log (e.g., a Tennessee Court Log) to be mathematically verified on a local log.
    * `condition_evaluator.go`: Protects the network against Sybil attacks and validates conditional logic based on Schema parameters.

* **Complex Flow Orchestration (`lifecycle/`)**
    Coordinates multi-step cryptography that requires interaction across multiple lower layers.
    * `artifact_access.go`: Orchestrates the granting of access to a sealed record. It coordinates the `builder` to publish the grant, and `crypto` to generate the threshold `KFrags` and execute the commitments.
    * `recovery.go`: Manages the complex process of social recovery, coordinating the fetching of escrow shares, the validation of witness independence, and the reconstruction of master identities.

---

## Conclusion: Enforcing Domain/Protocol Separation

This strict, one-way dependency graph is what makes the Ortholog SDK robust enough for a 50-year horizon. 

By enforcing that **Layer 1** (Math) and **Layer 2** (Structure) never interact with **Layer 3** (Sequence) or **Layer 4** (Business Actions), the system guarantees that vulnerabilities in application logic can never compromise the underlying cryptographic proofs. Domain Networks (the society) build on top of Layer 4, fully insulated from the underlying physics of the SMT, securely bridging their distinct realities via the `SchemaRef`.