# crypto/

## Purpose
The `crypto/` package is the **Pure Cryptography Layer (Layer 1)** of the Ortholog SDK.

This layer knows absolutely nothing about the Sparse Merkle Tree (SMT), log entry classifications, control headers, or domain rules. It answers a single, foundational question: *"Is this math valid?"* It acts as a strict, one-way dependency foundation. It imports nothing but standard Go mathematics and cryptographic libraries, ensuring that vulnerabilities in high-level business logic can never compromise the underlying cryptographic proofs.

## Architectural Mandates

### 1. The Universal Canonicalization Rule (TupleHash)
To guarantee 50-year collision resistance against boundary-shifting attacks, every SDK-internal cryptographic identifier that hashes variable-length inputs MUST route through the `LengthPrefixed(dst string, fields ...[]byte) [32]byte` primitive located in `crypto/hash.go`.
* **The Discipline:** The helper writes a 2-byte big-endian length for the Domain Separation Tag (DST), followed by the DST bytes, followed by a 2-byte big-endian length and the bytes for each subsequent field, returning a SHA-256 digest.
* **Zero Exceptions:** Raw-concatenation constructions for SplitIDs, commitment hashes, or domain identifiers are strictly forbidden.

### 2. The Caller-Normalizes Contract
The primitives in this package operate strictly on raw bytes. Unicode (NFC) normalization of identifiers, such as DIDs, must happen at the ingress edge of the SDK. If two callers pass different byte sequences for visually identical strings, the `crypto` package will deterministically produce different hashes.

### Subpackages
* `crypto/hash.go`: Core canonicalization and TupleHash primitives.
* `crypto/admission/`: Proof-of-Work admission stamp generation and verification.
* `crypto/artifact/`: AES-GCM storage encryption and Umbral Proxy Re-Encryption (PRE).
* `crypto/escrow/`: Pedersen Verifiable Secret Sharing (VSS) and threshold key custody.
* `crypto/signatures/`: Multi-curve digital signature verification and Ethereum-compatible recoveries.
