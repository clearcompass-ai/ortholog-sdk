# crypto/escrow

## Purpose
Threshold secret sharing for Ortholog master keys. It implements **V2 Pedersen Verifiable Secret Sharing (VSS)** over secp256k1, alongside per-node ECIES share transport and strict pre-reconstruction validators.

*(Note: V1 GF(256) Shamir Secret Sharing exists for legacy read-only compatibility but lacks cryptographic share verification).*

## V2 Pedersen VSS Functional Mechanics
V2 splits a 32-byte secp256k1 scalar into $N$ shares and publishes a Pedersen commitment set. Every share is mathematically verified against the dealer's published commitment set; tampering yields a typed cryptographic error rather than a silently-wrong secret.

### The Escrow Commitment Surface
* **Deterministic SplitID:** Unlike V1's random derivation, the V2 SplitID is anchored via the TupleHash canonicalization rule: `LengthPrefixed("ORTHOLOG-V7.75-ESCROW-SPLIT", []byte(dealerDID), nonce[:])`.
* **Commitment Struct:** `EscrowSplitCommitment` encapsulates `SplitID || M || N || DealerDID || CommitmentSet`.
* **Honest-Dealer Assumption:** `SplitV2` runs strictly in SDK-controlled processes. A malicious dealer who publishes inconsistent commitments causes reconstruction to fail explicitly; the equivocation is signed evidence handled at the witness layer.

## Wire Format (ADR-005 §5)
`ShareWireLen` is strictly pinned at **131 bytes** for both V1 and V2 shares.
V1 shares populate `BlindingFactor` and `CommitmentHash` slots with zeros; V2 shares populate them with polynomial evaluations. Any deviation in wire length rejects instantly at deserialization.

## ECIES Transport
Provides ECIES over secp256k1 for encrypting individual shares to specific escrow node public keys. Uses Ephemeral ECDH → SHA-256 KDF → AES-256-GCM. An off-curve point yields an undefined ECDH result and is rejected *before* `ScalarMult` executes.
