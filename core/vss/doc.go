// Package vss implements Pedersen Verifiable Secret Sharing over
// secp256k1.
//
// # What this package provides
//
// One scheme: Pedersen VSS, M-of-N, with cryptographic share
// verification. Given a 32-byte secret, Split produces N shares
// (each carrying both a Shamir share value and a blinding scalar)
// plus a commitment vector that anyone can use to verify any share
// in isolation. Reconstruct recovers the secret from any M shares
// after checking each against the commitments. Verify checks one
// share against the commitments without reconstructing.
//
// Compared to the GF(256) Shamir scheme in crypto/escrow:
//
//   - Shamir(GF(256)): no commitments. A faulty dealer can hand a
//     shareholder bytes that are not a real share of the claimed
//     secret. The shareholder cannot detect the fault until a
//     reconstruction quorum gathers and the scheme silently
//     produces the wrong secret (or fails). Detection is post-hoc
//     and ambiguous.
//
//   - Pedersen VSS (this package): every share carries a
//     CommitmentHash that binds it to a published commitment vector.
//     Verify(share, commitments) returns nil if and only if the
//     dealer constructed the share honestly. Detection is local,
//     immediate, and unambiguous. A faulty dealer is caught by any
//     single shareholder.
//
// This package does not change the GF(256) Shamir surface — that
// remains in crypto/escrow for V1 share consumers. Pedersen VSS is
// the foundation V2 will build on (see Phase B of v7.5+).
//
// # Cryptographic primitives
//
// All curve operations on github.com/decred/dcrd/dcrec/secp256k1/v4,
// the same library Bitcoin, Decred, and (via btcec/v2) Cosmos /
// Ethereum tooling depend on. SHA-256 from the Go stdlib for the
// commitment hash and the H-generator derivation. crypto/rand for
// polynomial-coefficient sampling. No new cryptographic primitives
// are introduced; this package orchestrates audited operations.
//
// # The H generator
//
// Pedersen commitments require two generators G and H such that no
// party knows the discrete log relationship log_G(H). G is
// secp256k1's standard generator. H is derived deterministically
// here via try-and-increment from a versioned domain-separator
// seed (see h_generator.go HGeneratorDoc). Standard "nothing up my
// sleeve" construction; the same technique Bitcoin uses for its
// confidential-transactions H, with the seed published in source
// for auditor inspection. RFC 9380 hash-to-curve was considered
// and rejected — it solves bias problems for repeated
// per-message hashing that do not apply to deriving one constant
// generator, and it would have required either an external
// dependency (h2c-go-ref) or ~200 lines of custom SSWU map.
//
// # Security properties
//
// Computational hiding (under the discrete-log assumption on
// secp256k1):
//   - Given the commitments, the shareholder cannot recover the
//     secret without M shares.
//   - The blinding polynomial g(x) hides the secret polynomial f(x)
//     coefficients in the commitments.
//
// Computational binding (under the discrete-log assumption on
// secp256k1):
//   - The dealer cannot construct two different (Value,
//     BlindingFactor) pairs that satisfy the commitment equation
//     for the same Index without solving discrete log.
//   - In particular: the dealer cannot equivocate on share i.
//
// Information-theoretic share verification:
//   - Verify(share, commitments) returns nil if and only if the
//     share's (Value, BlindingFactor) satisfies the commitment
//     equation at the share's Index. No probabilistic error.
//
// # Out of scope
//
// This package does NOT:
//   - Define the wire format for Pedersen shares (that's
//     crypto/escrow's V2 Share, separate phase).
//   - Implement distributed key generation (DKG), proactive
//     refresh, or share rotation.
//   - Implement Pedersen with t < n/3 byzantine-tolerance properties
//     (this is the standard non-byzantine VSS, suitable for the
//     "honest dealer, possibly-faulty quorum" threat model).
//
// # Threat model
//
// Honest dealer, M-of-N reconstruction:
//   Standard Shamir guarantees apply. Pedersen VSS adds nothing
//   here beyond the per-share verification convenience.
//
// Faulty dealer, honest shareholders:
//   Any shareholder can call Verify on their own share and detect
//   a malformed share without coordinating with anyone. The faulty
//   dealer cannot construct a share that passes Verify but
//   reconstructs to a different secret (binding).
//
// Faulty shareholder, honest dealer + others:
//   The faulty shareholder's contribution is detected at
//   reconstruction time via Verify. The remaining honest
//   shareholders can complete reconstruction without the bad
//   share, provided the threshold is still met.
//
// Adversary observing the commitments:
//   Learns nothing computationally about the secret beyond what
//   M-1 shares would reveal (which under Shamir is nothing). The
//   commitments hide the secret polynomial under the blinding
//   polynomial.
package vss
