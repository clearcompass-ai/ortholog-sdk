# crypto/artifact

## Purpose
Manages two composable cryptographic concerns for artifact payloads:
1. **Storage encryption (at rest):** AES-256-GCM wrapping of raw artifact bytes with a freshly generated per-artifact key.
2. **Access control (selective disclosure):** Umbral Threshold Proxy Re-Encryption (PRE) over secp256k1, strictly bound to Pedersen VSS commitments (ADR-005).

## Access Control — Umbral PRE
Implements threshold re-encryption to securely grant artifact access.

### The Dual-Verification Gate (Anti-Substitution)
To close KFrag-substitution attacks, proxies and recipients MUST verify a dual-gate condition *before* Lagrange combination:
1. **DLEQ Proof:** Proves the proxy used a consistent $rk_i$ for both $VK_i = rk_i \cdot G$ and $E' = rk_i \cdot E$.
2. **Pedersen Commitment:** Proves that $(VK_i, BK_i)$ lies on the committed polynomial published on the log: $VK_i + BK_i = \sum C_j^{i^j}$.
Failing either gate instantly rejects the fragment.

### The PRE Commitment Surface (Phase C)
This package owns the full lifecycle of the `PREGrantCommitment` entry.
* **Deterministic SplitID:** Derived via `LengthPrefixed("ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1", grantorDID, recipientDID, artifactCID.Bytes())`. Uses `CID.Bytes()` to guarantee cross-algorithm collision resistance.
* **Struct & Wire:** `PREGrantCommitment` wire format encapsulates `SplitID || M || N || CommitmentSet`. Maximum size is 8,449 bytes at $M=255$.
* **Verification:** `VerifyPREGrantCommitment` ensures threshold bounds, point-on-curve validity, and deterministic SplitID recomputation.

## Wire Format (ADR-005 §8.3)
* **`CFrag` and `KFrag`:** Both strictly padded to **196 bytes**.
* **Reserved Padding:** Contains exactly 97 reserved zero-bytes (for KFrags) or 32 reserved zero-bytes (for CFrags). Any non-zero byte in the reserved zone triggers an immediate `ErrKFragReservedBytesNonZero` rejection, preventing covert channels and preparing the bay for future Post-Quantum extensions.
