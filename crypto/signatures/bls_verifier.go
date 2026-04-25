/*
FILE PATH:

	crypto/signatures/bls_verifier.go

DESCRIPTION:

	Production BLS12-381 aggregate signature verification. Implements the
	BLSVerifier interface defined in witness_verify.go using
	Consensys's gnark-crypto library. Also provides VerifyBLSPoP, the
	registrar-side primitive that establishes the security precondition
	for aggregate verification.

	Under Wave 1's protocol shape (SchemeTag on CosignedTreeHead),
	VerifyWitnessCosignatures dispatches to this verifier's
	VerifyAggregate method when head.SchemeTag == SchemeBLS. Wave 2
	relocates SchemeTag to per-signature and changes the dispatch; this
	file's verification algorithm is unaffected by that restructuring.

KEY ARCHITECTURAL DECISIONS:
  - Same-message optimistic aggregation with per-signature attribution
    fallback. The optimistic path computes a single pairing check
    regardless of witness count N: the left side sums signatures, the
    right side sums public keys, and bilinearity makes the equation
    balance when all signatures are valid. The fallback path — engaged
    when the optimistic check fails — performs N individual pairing
    checks to identify exactly which signatures failed. Happy path is
    O(1) pairings; sad path is O(N) pairings with full attribution.
  - Security depends on proof-of-possession at registration. The
    aggregate algorithm is sound only when every public key in the
    input set has been verified for PoP. Without PoP, an attacker can
    construct a rogue public key (pk_rogue = g2^x - Σ pk_others) whose
    aggregate collapses to a key whose discrete log the attacker knows,
    enabling unilateral forgery. The SDK provides VerifyBLSPoP in this
    file; the registrar (typically the domain network's witness
    onboarding controller) must call it before admitting any public
    key to a witness set. The godoc on GnarkBLSVerifier documents this
    explicitly.
  - Subgroup validation at every decompression. Every G1 signature and
    G2 public key is checked for prime-order subgroup membership at
    parse time. Skipping this check enables small-subgroup attacks that
    can make the aggregate pairing equation satisfy spuriously.
  - Failure isolation. A single malformed signature or public key does
    not corrupt the aggregation; the malformed entry is marked invalid
    and excluded, while other entries are verified normally. This is
    essential for monitoring services that must distinguish "one
    witness sent garbage" from "the whole cosignature is bad."
  - No mutable state. GnarkBLSVerifier holds nothing across calls;
    multiple goroutines may share a single instance. The struct exists
    only to satisfy the BLSVerifier interface; it could be a bare
    function if not for the interface dispatch.

OVERVIEW:

	Construction:
	    v := NewGnarkBLSVerifier()

	Cosignature verification (dispatched by VerifyWitnessCosignatures):
	    results, err := v.VerifyAggregate(msg, signatures, pubkeys)
	    // results[i] is true iff signatures[i] verified under pubkeys[i]
	    // err is non-nil only for transport-level failures

	Registrar PoP verification:
	    err := VerifyBLSPoP(pub, popBytes)
	    // must be called before admitting pub to any witness set

KEY DEPENDENCIES:
  - github.com/consensys/gnark-crypto/ecc/bls12-381
  - types.WitnessSignature, types.WitnessPublicKey
  - BLSVerifier interface from witness_verify.go
*/
package signatures

import (
	"errors"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

var (
	// ErrBLSInvalidPoP is returned by VerifyBLSPoP when the proof-of-
	// possession signature fails pairing verification. This is the
	// security-critical rejection path: a PoP failure at registration
	// is the defense against rogue-key attacks. Registrars must treat
	// this error as a rejection of the witness, not a warning.
	ErrBLSInvalidPoP = errors.New("signatures/bls: proof-of-possession verification failed")

	// ErrBLSInvalidPoPLength is returned when a PoP is not exactly
	// BLSG1CompressedLen (48) bytes. Malformed length indicates
	// either corruption or a wire-format mismatch.
	ErrBLSInvalidPoPLength = errors.New("signatures/bls: invalid proof-of-possession length")

	// ErrBLSPoPNotOnCurve is returned when a PoP decompresses to a
	// point not on the BLS12-381 G1 curve.
	ErrBLSPoPNotOnCurve = errors.New("signatures/bls: proof-of-possession not on curve")

	// ErrBLSPoPNotInSubgroup is returned when a PoP is on the G1 curve
	// but not in the prime-order subgroup. Small-subgroup points can
	// make the pairing equation satisfy spuriously and must be rejected.
	ErrBLSPoPNotInSubgroup = errors.New("signatures/bls: proof-of-possession not in prime-order subgroup")

	// ErrBLSAggregateLengthMismatch is returned by VerifyAggregate when
	// the signatures and pubkeys slices have different lengths. The
	// function's contract requires parallel slices of equal length;
	// differing lengths are a caller bug.
	ErrBLSAggregateLengthMismatch = errors.New("signatures/bls: signatures and pubkeys length mismatch")
)

// -------------------------------------------------------------------------------------------------
// 2) GnarkBLSVerifier — production BLSVerifier implementation
// -------------------------------------------------------------------------------------------------

// GnarkBLSVerifier is the production BLSVerifier implementation. Uses
// Consensys's gnark-crypto library for all curve operations: point
// decompression, scalar multiplication, pairing computation, subgroup
// checks.
//
// # SECURITY INVARIANT (CRITICAL)
//
// VerifyAggregate's same-message aggregation optimization is
// cryptographically sound only when every public key in the input set
// has been verified for proof-of-possession at witness registration.
// Without PoP verification, an attacker controlling one witness slot
// can construct a public key such that the aggregate of all public
// keys in the set collapses to an attacker-known discrete log, enabling
// unilateral forgery of quorum cosignatures (Boldyreva 2003 rogue-key
// attack).
//
// # DEPLOYMENT REQUIREMENT
//
// Domain networks and witness registrars MUST call VerifyBLSPoP on every
// BLS public key before admitting it to a witness set. The SDK does not
// and cannot enforce this at verification time — the verifier has no
// visibility into the registration history of the keys passed to it.
// Responsibility falls on the caller. The witness onboarding
// documentation for each domain network must state this explicitly.
//
// # THREAD-SAFETY
//
// GnarkBLSVerifier holds no mutable state. A single instance may be
// shared across goroutines and reused for any number of concurrent
// verification calls.
type GnarkBLSVerifier struct{}

// NewGnarkBLSVerifier returns the default production BLS verifier.
// No configuration options; behavior is deterministic and governed
// entirely by protocol constants (BLSDomainTag, curve parameters)
// locked in bls_lock_test.go.
func NewGnarkBLSVerifier() BLSVerifier {
	return &GnarkBLSVerifier{}
}

// -------------------------------------------------------------------------------------------------
// 3) VerifyAggregate — same-message optimistic aggregation
// -------------------------------------------------------------------------------------------------

// VerifyAggregate verifies N witness signatures against N public keys,
// all over the same 40-byte WitnessCosignMessage. Implements the
// BLSVerifier interface.
//
// # ALGORITHM
//
// Same-message optimistic aggregation with per-signature attribution
// fallback:
//
//  1. PARSE PHASE
//     For each index i: decompress signatures[i].SigBytes as G1 and
//     pubkeys[i].PublicKey as G2. Malformed entries (wrong length,
//     off-curve, outside subgroup) are marked invalid and excluded
//     from aggregation. Valid entries enter the aggregation pool.
//
//  2. HASH-TO-CURVE (once)
//     H = HashToG1(msg, BLSDomainTag).
//
//  3. OPTIMISTIC AGGREGATION
//     sig_agg = Σ parsed_sigs_i       (G1 point addition)
//     pub_agg = Σ parsed_pubkeys_i    (G2 point addition)
//     Check: e(sig_agg, G2_gen) == e(H, pub_agg)
//     By bilinearity, this single pairing check holds iff every
//     individual pair satisfies its own verification equation — PROVIDED
//     that the public keys were registered via PoP (see security
//     invariant on GnarkBLSVerifier). Without PoP, a rogue key can
//     make this equation satisfy for a forged aggregate signature.
//
//  4. RESULT DETERMINATION
//     If optimistic check passes: mark all parsed entries as valid.
//     If optimistic check fails: engage fallback.
//
//  5. FALLBACK (per-signature attribution)
//     For each parsed pair, individual pairing check:
//     e(sig_i, G2_gen) == e(H, pubkey_i)
//     Mark results[i] according to each pair's outcome.
//
// # PERFORMANCE
//
//	Happy path (N valid signatures): 1 pairing check ≈ 1.9 ms
//	Sad path (any invalid signature): 1 + N pairing checks ≈ 1.9 + 2.0·N ms
//
// Benchmarks validated by bls_benchmark_test.go. The happy path is
// flat in N, which is the architectural argument for BLS at
// national-federation scale.
//
// # CONTRACT
//
//   - Returns []bool of length equal to len(signatures) and len(pubkeys)
//   - results[i] == true iff signatures[i] verified against pubkeys[i]
//   - results[i] == false if:
//   - signatures[i].SigBytes is not a valid compressed G1 point in
//     the prime-order subgroup, OR
//   - pubkeys[i].PublicKey is not a valid compressed G2 point in
//     the prime-order subgroup, OR
//   - the pairing check (aggregate or individual) fails for this pair
//   - Returns a non-nil error only for transport-level failures:
//   - signatures and pubkeys slice lengths differ
//   - hash-to-curve fails (effectively never — gnark's HashToG1 does
//     not fail on non-nil inputs)
//     Individual signature invalidity produces false at that index,
//     NOT a returned error. Monitoring callers rely on this distinction.
//
// # ASSUMPTION
//
// All witnesses sign the identical msg bytes. This is guaranteed by
// the witness cosignature protocol — every witness in a set signs
// WitnessCosignMessage(head). If a future caller violates this
// assumption (signing different messages per witness), the optimistic
// aggregation equation will not hold even for honest signatures, and
// the fallback will re-verify individually. Correctness is preserved;
// performance degrades to per-signature costs.
//
// # THREAD-SAFETY
//
// Stateless. Safe for concurrent calls with distinct inputs.
func (v *GnarkBLSVerifier) VerifyAggregate(
	msg []byte,
	signatures []types.WitnessSignature,
	pubkeys []types.WitnessPublicKey,
) ([]bool, error) {
	// Length check: parallel slices with identical length is a contract
	// requirement. Callers violating this have a programming error; we
	// fail fast rather than silently truncating.
	if len(signatures) != len(pubkeys) {
		return nil, fmt.Errorf("%w: %d signatures, %d pubkeys",
			ErrBLSAggregateLengthMismatch, len(signatures), len(pubkeys))
	}

	n := len(signatures)
	results := make([]bool, n)

	// Empty input: return immediately. This is a well-defined edge case
	// that the caller typically rejects at a higher layer (K-of-N with
	// N=0 is meaningless), but the verifier itself handles it cleanly.
	if n == 0 {
		return results, nil
	}

	// ─────────────────────────────────────────────────────────────
	// STEP 1: Parse phase
	// ─────────────────────────────────────────────────────────────
	//
	// Decompress every signature and public key. Record per-index parse
	// success. Only successfully-parsed pairs enter the aggregation
	// pool; malformed entries stay false in results and are excluded
	// from the subsequent pairing check.

	parsedSigs := make([]bls12381.G1Affine, n)
	parsedPubs := make([]bls12381.G2Affine, n)
	parseOK := make([]bool, n)

	for i := 0; i < n; i++ {
		// Signature parsing (G1 compressed, 48 bytes).
		if len(signatures[i].SigBytes) != BLSG1CompressedLen {
			continue // parseOK[i] stays false
		}
		if _, err := parsedSigs[i].SetBytes(signatures[i].SigBytes); err != nil {
			continue
		}
		if !parsedSigs[i].IsInSubGroup() {
			continue
		}

		// Public key parsing (G2 compressed, 96 bytes).
		if len(pubkeys[i].PublicKey) != BLSG2CompressedLen {
			continue
		}
		if _, err := parsedPubs[i].SetBytes(pubkeys[i].PublicKey); err != nil {
			continue
		}
		if !parsedPubs[i].IsInSubGroup() {
			continue
		}

		parseOK[i] = true
	}

	// ─────────────────────────────────────────────────────────────
	// STEP 2: Hash-to-curve (single invocation)
	// ─────────────────────────────────────────────────────────────
	//
	// All witnesses signed the same msg. Hash it once into G1; the
	// result is reused for both the optimistic aggregation check and
	// the per-signature fallback.

	hashPoint, err := bls12381.HashToG1(msg, []byte(BLSDomainTag))
	if err != nil {
		// HashToG1 does not fail on well-formed inputs. Surface any
		// library-level failure rather than panicking.
		return results, fmt.Errorf("%w: %v", ErrBLSHashToCurveFailed, err)
	}
	var hashJac bls12381.G1Jac
	hashJac.FromAffine(&hashPoint)

	// Collect parsed indices. If nothing parsed, we're done — all
	// entries remain false.
	validIndices := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if parseOK[i] {
			validIndices = append(validIndices, i)
		}
	}
	if len(validIndices) == 0 {
		return results, nil
	}

	// ─────────────────────────────────────────────────────────────
	// STEP 3: Optimistic aggregation
	// ─────────────────────────────────────────────────────────────
	//
	// sig_agg = Σ parsed_sigs_i   (Jacobian addition is faster than
	//                              repeated Affine additions for N > 2)
	// pub_agg = Σ parsed_pubs_i
	//
	// Single pairing check: e(sig_agg, G2_gen) == e(H, pub_agg).
	// Rearranged: e(sig_agg, -G2_gen) · e(H, pub_agg) == 1.
	// Gnark's PairingCheck computes this product and returns true iff
	// it equals the pairing identity.

	var sigAggJac bls12381.G1Jac
	var pubAggJac bls12381.G2Jac

	for _, i := range validIndices {
		var sigJac bls12381.G1Jac
		sigJac.FromAffine(&parsedSigs[i])
		sigAggJac.AddAssign(&sigJac)

		var pubJac bls12381.G2Jac
		pubJac.FromAffine(&parsedPubs[i])
		pubAggJac.AddAssign(&pubJac)
	}

	var sigAggAff bls12381.G1Affine
	sigAggAff.FromJacobian(&sigAggJac)

	var pubAggAff bls12381.G2Affine
	pubAggAff.FromJacobian(&pubAggJac)

	// Pairing check: e(sig_agg, G2_gen) ?= e(H, pub_agg).
	// Gnark's PairingCheck evaluates the product of pairings and tests
	// equality to the identity. We structure as:
	//   e(sig_agg, -G2_gen) · e(H, pub_agg) = 1
	// which verifies: e(H, pub_agg) = e(sig_agg, G2_gen).
	_, _, _, g2Gen := bls12381.Generators()
	var negG2Gen bls12381.G2Affine
	negG2Gen.Neg(&g2Gen)

	// Gate: muEnableBLSAggregateVerify
	// (bls_verifier_mutation_switches.go). When off, the
	// PairingCheck is bypassed and aggregatedOK is forced to true —
	// silent forgery acceptance for BLS cosignatures.
	var aggregatedOK bool
	if muEnableBLSAggregateVerify {
		aggregatedOK, err = bls12381.PairingCheck(
			[]bls12381.G1Affine{sigAggAff, hashPoint},
			[]bls12381.G2Affine{negG2Gen, pubAggAff},
		)
		if err != nil {
			// PairingCheck doesn't typically fail on valid-length
			// inputs, but surface any library-level issue.
			return results, fmt.Errorf("signatures/bls: aggregate pairing check: %w", err)
		}
	} else {
		aggregatedOK = true
	}

	if aggregatedOK {
		// Optimistic path: every parsed pair verified simultaneously.
		// Mark all parsed indices true. Unparsed indices stay false.
		for _, i := range validIndices {
			results[i] = true
		}
		return results, nil
	}

	// ─────────────────────────────────────────────────────────────
	// STEP 4: Fallback — per-signature attribution
	// ─────────────────────────────────────────────────────────────
	//
	// The aggregated check failed. Identify which specific signatures
	// are invalid by running independent pairing checks per pair.
	// Each check is ~2 ms; cost is 1 + N total (the aggregated check
	// above plus N individual checks). Amortized across production
	// workloads where sad paths are rare, this is acceptable.

	for _, i := range validIndices {
		individualOK, err := bls12381.PairingCheck(
			[]bls12381.G1Affine{parsedSigs[i], hashPoint},
			[]bls12381.G2Affine{negG2Gen, parsedPubs[i]},
		)
		if err != nil {
			// Library-level failure on a single pair. Mark as invalid
			// (conservative) rather than propagating the error — the
			// rest of the verification is sound, and the caller should
			// get attribution for all other pairs.
			results[i] = false
			continue
		}
		results[i] = individualOK
	}

	return results, nil
}

// -------------------------------------------------------------------------------------------------
// 4) VerifyBLSPoP — proof-of-possession verification (REGISTRAR PRIMITIVE)
// -------------------------------------------------------------------------------------------------

// VerifyBLSPoP verifies a proof-of-possession signature against the
// public key it claims to prove. This function is the security boundary
// for the rogue-key attack: registrars that admit BLS public keys to
// witness sets MUST call VerifyBLSPoP on every submission and reject
// keys whose PoP fails verification.
//
// # VERIFICATION EQUATION
//
// Given pub ∈ G2 and popBytes (48 bytes, compressed G1):
//
//	pop = Decompress(popBytes)
//	H   = HashToG1(Compress(pub), BLSPoPDomainTag)
//	Check: e(pop, G2_gen) == e(H, pub)
//
// By bilinearity, this holds iff pop = sk · H where pub = sk · G2_gen
// for the same sk. Producing a valid PoP requires knowledge of sk.
//
// # WHY THIS STOPS THE ROGUE-KEY ATTACK
//
// An attacker constructing pk_rogue = g2^x - Σ pk_honest knows x (the
// discrete log of the aggregate sum) but does not know sk_rogue (the
// discrete log of pk_rogue alone). Forging a valid PoP for pk_rogue
// would require solving the discrete logarithm problem on a specific
// BLS12-381 G2 point, which is computationally infeasible.
//
// Registration without PoP: attacker submits pk_rogue with no proof,
// is admitted, forges cosignatures.
//
// Registration with PoP (this function): attacker submits pk_rogue,
// cannot produce a valid PoP, is rejected before entering any witness
// set. The rogue-key attack is impossible.
//
// # REGISTRAR OBLIGATIONS
//
// The SDK cannot enforce PoP verification at cosignature-verification
// time because the verifier has no visibility into which public keys
// arrived through PoP-gated registration and which did not. The
// responsibility lives with the registration code path: every admission
// of a BLS public key to a witness set must be preceded by a
// VerifyBLSPoP call, and admissions that fail verification must be
// rejected with no retry.
//
// Domain networks (judicial-network, recording-network) implement the
// registrar. The SDK provides the primitive; the domain enforces the
// invariant.
//
// # RETURN VALUES
//
// Returns nil on successful verification — the PoP is valid, the public
// key may be admitted.
//
// Returns a typed error on any failure:
//   - ErrBLSInvalidPoPLength: popBytes is not 48 bytes
//   - ErrBLSPoPNotOnCurve: popBytes decompresses to an invalid point
//   - ErrBLSPoPNotInSubgroup: pop is not in the G1 prime-order subgroup
//   - ErrBLSInvalidPoP: pairing check failed (the PoP does not
//     correspond to the claimed public key)
//   - ErrBLSNilPublicKey: pub is nil (caller bug)
//   - ErrBLSHashToCurveFailed: gnark's HashToG1 failed (effectively
//     never occurs in practice)
//
// # THREAD-SAFETY
//
// Stateless.
func VerifyBLSPoP(pub *bls12381.G2Affine, popBytes []byte) error {
	if pub == nil {
		return ErrBLSNilPublicKey
	}

	// Length check.
	if len(popBytes) != BLSG1CompressedLen {
		return fmt.Errorf("%w: got %d bytes, expected %d",
			ErrBLSInvalidPoPLength, len(popBytes), BLSG1CompressedLen)
	}

	// Decompress PoP to G1 point. Validates on-curve implicitly.
	var pop bls12381.G1Affine
	if _, err := pop.SetBytes(popBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrBLSPoPNotOnCurve, err)
	}

	// Subgroup check. Critical: a G1 point outside the prime-order
	// subgroup can make the pairing check satisfy spuriously.
	if !pop.IsInSubGroup() {
		return ErrBLSPoPNotInSubgroup
	}

	// Hash pub.Compress() with the PoP DST. The DST separation from
	// BLSDomainTag is the defense against cross-protocol signature
	// reuse — a cosignature cannot be replayed as a PoP because the
	// two DSTs produce different G1 targets even for identical input
	// bytes.
	pubBytes := pub.Bytes()
	hashPoint, err := bls12381.HashToG1(pubBytes[:], []byte(BLSPoPDomainTag))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBLSHashToCurveFailed, err)
	}

	// Pairing check: e(pop, G2_gen) ?= e(H, pub).
	// Rearranged for PairingCheck's product-equals-identity form:
	//   e(pop, -G2_gen) · e(H, pub) = 1
	_, _, _, g2Gen := bls12381.Generators()
	var negG2Gen bls12381.G2Affine
	negG2Gen.Neg(&g2Gen)

	// Gate: muEnableBLSPoPVerify (bls_verifier_mutation_switches.go).
	// When off, the PairingCheck is bypassed and any well-formed
	// PoP shape returns nil — rogue-key attacks succeed because PoP
	// no longer attests to scalar knowledge.
	if !muEnableBLSPoPVerify {
		return nil
	}

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pop, hashPoint},
		[]bls12381.G2Affine{negG2Gen, *pub},
	)
	if err != nil {
		return fmt.Errorf("signatures/bls: PoP pairing check: %w", err)
	}
	if !ok {
		return ErrBLSInvalidPoP
	}

	return nil
}
