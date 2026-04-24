// Package artifact implements Umbral Threshold Proxy Re-Encryption
// on secp256k1 with Pedersen VSS binding (ADR-005).
//
// Relationship to AES-256-GCM (api.go):
//
//	AES-256-GCM = storage encryption (artifact at rest, permanent)
//	Umbral PRE  = access control (who can decrypt, additive)
//	Composable: Umbral wraps/transforms the AES key
//	Schemas declare which access model: aes_gcm | umbral_pre
//
// Cryptographic binding (ADR-005 §3.5):
//
//	KFrags and CFrags carry a Pedersen commitment BK_i = b_i·H.
//	CFrag verification gates on two independent checks:
//
//	  1. DLEQ — proxy used a consistent rk_i for re-encryption
//	     (VK_i = rk_i·G AND E' = rk_i·E)
//
//	  2. Pedersen — (VK_i, BK_i) lies on the polynomial committed
//	     at grant time:  VK_i + BK_i = Σ i^j · C_j
//
//	Either failing rejects the CFrag. This closes the KFrag-
//	substitution attack where a coalition of compromised proxies
//	jointly forge a re-encryption key. DLEQ alone is insufficient
//	(M proxies can agree on a forged rk' and produce mutually
//	consistent DLEQ proofs). Pedersen alone is insufficient
//	(a proxy could present a valid (VK, BK) pair without having
//	used rk_i for re-encryption).
//
// Combine-before-verify defense (ADR-005 §3.5):
//
//	PRE_DecryptFrags verifies every CFrag against the commitment
//	set BEFORE Lagrange combination. Combination of unverified
//	CFrags is the substitution vulnerability this package closes.
//	The verification gate lives in the primitive, not in callers;
//	a caller that forgets verification cannot reintroduce the
//	attack window.
//
// Wire format (ADR-005 §8.3):
//
//	CFrag: 196 bytes.
//
//	Offset  Length  Field
//	   0      33    E'       (compressed)
//	  33      33    VK       (compressed)
//	  66      33    BK       (compressed)
//	  99       1    ID
//	 100      32    ProofE   (DLEQ challenge, F_n)
//	 132      32    ProofZ   (DLEQ response,  F_n)
//	 164      32    Reserved (MUST be zero)
//
// Blinding scalar isolation (ADR-005 §3.5.1):
//
//	The Pedersen blinding scalar b_i is owner-local. It is computed
//	inside PRE_GenerateKFrags, consumed once to produce BK_i, then
//	zeroized. It never enters a KFrag, never crosses a process
//	boundary, never reaches a proxy. The proxy treats BK_i as an
//	opaque 33-byte blob and relays it from KFrag into CFrag.
//
// Memory zeroization limits:
//
//	The Go runtime makes no guarantee that secret bytes are erased
//	from heap memory after a variable goes out of scope. Callers
//	explicitly zero 32-byte scalar/coordinate slices on the best-
//	effort path, but intermediate *big.Int allocations are opaque
//	to user code and may persist in memory until a subsequent GC
//	pass reclaims them, at which point the bytes may or may not be
//	overwritten. Deployments with strict zeroization requirements
//	MUST run sk_owner operations inside a hardware enclave (HSM or
//	TEE) where the secret never enters Go-managed memory.
//
// Mutation audit switches (see muEnable* constants below):
//
//	Each security gate reads a boolean compile-time constant to
//	determine whether to enforce. Set all constants to true for
//	production; flip one to false and rerun tests to audit the
//	corresponding test suite's coverage of that gate.
package artifact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// ═════════════════════════════════════════════════════════════════════
//
//                    ⚠️  MUTATION AUDIT SWITCHES  ⚠️
//
//    ┌────────────────────────────────────────────────────────────┐
//    │                                                            │
//    │  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.  │
//    │                                                            │
//    └────────────────────────────────────────────────────────────┘
//
// Setting any of these constants to `false` DISABLES a production
// security gate. The SDK becomes exploitable. Never commit a value
// of `false`. Never deploy a build produced with `false`. Never
// release a tag with `false`. Any `false` you see below is a merge
// blocker and a release blocker.
//
// These exist solely to satisfy the mutation discipline audit
// required by ADR-005 §9.2. Each switch maps to specific tests
// that MUST fail when the gate is disabled. If the tests pass
// with a gate disabled, the tests are fake and the SDK is
// provably untested — a finding that must be fixed before Phase C
// closes.
//
// Mutation audit procedure (run once before every release):
//
//	for each muEnable* constant:
//	   1. set the constant to false
//	   2. run the "Tests that MUST fail" listed in its comment
//	   3. verify those tests fail
//	   4. set the constant back to true
//	   5. rerun those tests and verify they pass
//	   6. stage the change in git — if the diff is anything other
//	      than `true` on both endpoints, STOP and investigate
//
// A pre-commit hook or CI check SHOULD grep for `muEnable.*= false`
// and fail the build if any match is found. (See scripts/ci-check.sh)
//
// ═════════════════════════════════════════════════════════════════════

const (
	// muEnableCommitmentsGate controls the empty-commitments gate
	// shared by PRE_VerifyCFrag and PRE_DecryptFrags.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: PRE_* accepts empty/zero-threshold commitments and
	// proceeds into verification. Rejection still happens deeper
	// (vss package detects empty commitments and errors on transcript
	// construction), but with a wrong error shape and no early bail.
	//
	// Tests that MUST fail when this is false:
	//   - TestDecryptFrags_RequiresCommitments
	//   - TestPRE_EmptyCommitments_Rejected
	muEnableCommitmentsGate = true

	// muEnableOnCurveGate controls the on-curve check for VK, E',
	// and capsule.E in PRE_VerifyCFrag.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: malformed points that happen to deserialize can
	// reach the subsequent cryptographic arithmetic. Most paths will
	// still fail deeper (decompressPoint validates y²=x³+7), but
	// this gate is the first defense and the fastest rejection.
	//
	// Tests that MUST fail when this is false:
	//   - TestPRE_VerifyCFrag_NilCFrag (indirectly)
	//   - Tests that construct off-curve points explicitly
	muEnableOnCurveGate = true

	// muEnableDLEQCheck controls ADR-005 §3.5 CHECK 1: DLEQ proof
	// verification.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: a malicious proxy can forge E' without using a
	// consistent rk_i. Substituting ProofE, ProofZ, VK, or E' is
	// accepted. Pedersen check still catches some of these via
	// independent defense-in-depth, but proof-value tamper (ProofE,
	// ProofZ) and some E' substitutions pass silently.
	//
	// Tests that MUST fail when this is false:
	//   - TestPRE_SubstitutedEPrime_Rejected
	//   - TestPRE_SubstitutedProofE_Rejected
	//   - TestPRE_SubstitutedProofZ_Rejected
	//
	// Tests that may still pass (due to Pedersen defense-in-depth):
	//   - TestPRE_SubstitutedVK_Rejected
	//   - TestPRE_AdaptiveBK_Rejected
	muEnableDLEQCheck = true

	// muEnablePedersenCheck controls ADR-005 §3.5 CHECK 2: Pedersen
	// polynomial-consistency binding.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: the SDK regresses to the v7.5 coalition-attack
	// vulnerability. A coalition of M compromised proxies can agree
	// on a forged rk', produce internally-consistent DLEQ proofs,
	// and decrypt any capsule granted through them. This is the
	// headline attack ADR-005 exists to prevent.
	//
	// Tests that MUST fail when this is false:
	//   - TestPRE_SubstitutedRKShare_Rejected
	//   - TestPRE_CoalitionAttack_Rejected
	//   - TestPRE_WrongCommitments_Rejected
	muEnablePedersenCheck = true

	// muEnableSufficientCFragsGate controls the threshold-sufficiency
	// check in PRE_DecryptFrags.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: PRE_DecryptFrags accepts fewer than M CFrags and
	// proceeds to verify-then-combine. The subsequent Lagrange
	// interpolation produces a mathematically-meaningless result
	// (not the intended secret), AES-GCM decryption fails, and the
	// caller gets a cryptic decrypt error instead of a clean
	// insufficient-CFrags rejection.
	//
	// Tests that MUST fail when this is false:
	//   - TestDecryptFrags_InsufficientCFrags
	muEnableSufficientCFragsGate = true

	// muEnableVerifyBeforeCombine controls the per-CFrag verification
	// loop in PRE_DecryptFrags (the gateAllCFragsVerify gate).
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: Lagrange combination proceeds over UNVERIFIED
	// CFrags. This reintroduces the v7.5 substitution attack window
	// at the decrypt layer: attacker-chosen CFrags combine into an
	// attacker-chosen re-encryption key, and decryption succeeds
	// with attacker-controlled output. The ADR-005 §3.5 "combine-
	// before-verify" invariant is broken.
	//
	// Tests that MUST fail when this is false:
	//   - TestDecryptFrags_VerifiesEveryFrag
	//   - TestDecryptFrags_NilCFragRejected
	muEnableVerifyBeforeCombine = true

	// muEnableKFragReservedCheck controls the reserved-zone zero-byte
	// enforcement in DeserializeKFrag.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: DeserializeKFrag accepts KFrag wire payloads whose
	// reserved zone (offset 99..195) contains non-zero bytes, making
	// the reserved region a free side-channel for attacker-controlled
	// bytes that downstream code may mistake for legitimate payload
	// once the format evolves. The reserved zone is the versioning
	// margin that lets us rev KFrag layouts without a wire-length
	// collision with v7.75 — silent drift across it is a protocol-
	// level bug waiting to happen.
	//
	// Tests that MUST fail when this is false:
	//   - TestKFrag_ReservedBytesNonZeroRejected_EachPosition
	//   - TestKFrag_ReservedBytesNonZeroRejected_SingleBit
	muEnableKFragReservedCheck = true

	// muEnableCommitmentOnCurveGate controls the on-curve validation
	// of every point in a PREGrantCommitment's CommitmentSet at
	// deserialize and at verify time.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: off-curve points admitted into CommitmentSet reach
	// downstream VSS arithmetic. commitmentCombine already rejects
	// off-curve points in the core primitive, but the gate in this
	// package is the structural first line — a misformed commitment
	// set should never reach the primitive layer.
	//
	// Tests that MUST fail when this is false:
	//   - TestPREGrantCommitment_VerifyRejectsOffCurvePoint
	muEnableCommitmentOnCurveGate = true

	// muEnableCommitmentSetLengthCheck controls the invariant that
	// len(CommitmentSet) == M. A commitment set that claims threshold
	// M but carries M-1 or M+1 points is structurally malformed and
	// MUST reject before any cryptographic reasoning.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: VerifyPREGrantCommitment accepts a short or long
	// commitment set. Downstream VerifyPoints would still fail, but
	// the rejection comes deep in the primitive rather than at the
	// structural gate — a noisy and confusing path for auditors.
	//
	// Tests that MUST fail when this is false:
	//   - TestPREGrantCommitment_VerifyRejectsShortCommitmentSet
	//   - TestPREGrantCommitment_VerifyRejectsLongCommitmentSet
	muEnableCommitmentSetLengthCheck = true

	// muEnableThresholdBoundsCheck controls the (2 <= M <= N <= 255)
	// threshold-bounds check on PREGrantCommitment.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: degenerate thresholds (M=0, M=1, M>N, N>255) are
	// admitted. A 1-of-N split is not a threshold scheme — every
	// share is the secret; relaxing this gate regresses the security
	// model to per-share disclosure.
	//
	// Tests that MUST fail when this is false:
	//   - TestPREGrantCommitment_VerifyRejectsThresholdBelowMin
	//   - TestPREGrantCommitment_VerifyRejectsMAboveN
	//   - TestPREGrantCommitment_VerifyRejectsNZero
	muEnableThresholdBoundsCheck = true

	// muEnableSplitIDRecomputation controls the verify-time check
	// that SplitID recomputes from (grantorDID, recipientDID,
	// artifactCID). This is the load-bearing binding between the
	// commitment entry and the grant context it claims to cover.
	//
	// Production value: true. MUST be true on any committed code.
	//
	// When false: a commitment entry can carry any SplitID while
	// still appearing to bind the grant. An attacker who obtains
	// one legitimate commitment entry could re-publish it under a
	// different (grantor, recipient, artifact) tuple and verifiers
	// would accept it — the commitment-entry-to-grant binding
	// collapses.
	//
	// Tests that MUST fail when this is false:
	//   - TestPREGrantCommitment_VerifyRejectsWrongSplitID
	//   - TestPREGrantCommitment_VerifyRejectsWrongGrantor
	//   - TestPREGrantCommitment_VerifyRejectsWrongRecipient
	//   - TestPREGrantCommitment_VerifyRejectsWrongCID
	muEnableSplitIDRecomputation = true
)

// ═════════════════════════════════════════════════════════════════════
// END MUTATION AUDIT SWITCHES
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// Curve helpers
// ─────────────────────────────────────────────────────────────────────

func curve() elliptic.Curve { return secp256k1.S256() }
func curveN() *big.Int      { return curve().Params().N }
func curveP() *big.Int      { return curve().Params().P }

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrDLEQVerificationFailed is returned when a CFrag's DLEQ proof
	// does not verify. Indicates the proxy did not use a consistent
	// scalar rk_i for both VK_i = rk_i·G and E' = rk_i·E.
	ErrDLEQVerificationFailed = errors.New("pre: DLEQ proof verification failed")

	// ErrPedersenVerificationFailed is returned when a CFrag's
	// (VK_i, BK_i) pair does not lie on the committed polynomial.
	// Indicates KFrag substitution — the proxy's key pair is
	// internally consistent but does not correspond to a legitimate
	// delegation split.
	ErrPedersenVerificationFailed = errors.New("pre: Pedersen commitment verification failed")

	// ErrInvalidCFragFormat is returned when a CFrag has an invalid
	// wire format or contains off-curve points.
	ErrInvalidCFragFormat = errors.New("pre: CFrag wire format invalid")

	// ErrInvalidKFragFormat mirrors ErrInvalidCFragFormat for KFrags.
	ErrInvalidKFragFormat = errors.New("pre: KFrag wire format invalid")

	// ErrEmptyCommitments is returned when a verifier is handed an
	// empty commitment set.
	ErrEmptyCommitments = errors.New("pre: empty commitment set")

	// ErrInsufficientCFrags is returned when fewer CFrags than the
	// threshold M are supplied to PRE_DecryptFrags.
	ErrInsufficientCFrags = errors.New("pre: insufficient cfrags for threshold")

	// ErrInvalidPoint is returned when a point argument is nil or
	// off-curve.
	ErrInvalidPoint = errors.New("pre: invalid curve point")

	// ErrReservedBytesNonZero is returned by DeserializeCFrag when
	// the 32-byte reserved zone (offset 164..195) contains any
	// non-zero byte.
	ErrReservedBytesNonZero = errors.New("pre: CFrag reserved bytes must be zero")

	// ErrKFragReservedBytesNonZero is returned by DeserializeKFrag
	// when the 97-byte reserved zone (offset 99..195) contains any
	// non-zero byte. Parallel to ErrReservedBytesNonZero for the
	// CFrag wire. The KFrag reserved zone lets the SDK rev KFrag
	// layouts without colliding with v7.75's 196-byte length; any
	// non-zero byte in the reserved range rejects at deserialize.
	ErrKFragReservedBytesNonZero = errors.New("pre: KFrag reserved bytes must be zero")
)

// ─────────────────────────────────────────────────────────────────────
// Wire constants (ADR-005 §8.3)
// ─────────────────────────────────────────────────────────────────────

// CFragWireLen is the fixed on-wire size of a serialized CFrag per
// ADR-005 §8.3. 196 bytes: 132 bytes of point content (E', VK, BK),
// 1 byte ID, 64 bytes DLEQ proof (ProofE, ProofZ), 32 bytes reserved.
const CFragWireLen = 196

const (
	cfragOffsetEPrime   = 0
	cfragOffsetVK       = 33
	cfragOffsetBK       = 66
	cfragOffsetID       = 99
	cfragOffsetProofE   = 100
	cfragOffsetProofZ   = 132
	cfragOffsetReserved = 164
	cfragReservedLen    = 32
)

// KFragBKLen is the fixed size of the compressed BK commitment.
const KFragBKLen = 33

// KFragWireLen is the fixed on-wire size of a serialized KFrag
// plaintext per ADR-005 §5. 196 bytes: 99 active bytes (ID + RKShare
// + VK compressed + BK compressed) + 97 reserved bytes
// (zero-enforced).
//
// Matching the CFrag wire length is intentional: a v7.75 deserializer
// consuming a KFrag or CFrag uses the length discriminator (196 bytes)
// to reject legacy v7.5 163-byte CFrags at length check, and the
// type-specific layout is disambiguated by the active-field offsets.
const KFragWireLen = 196

const (
	kfragOffsetID       = 0
	kfragOffsetRKShare  = 1
	kfragOffsetVK       = 33
	kfragOffsetBK       = 66
	kfragOffsetReserved = 99
	kfragReservedLen    = 97
)

// assertReservedZoneZero verifies that every byte in data[offset:offset+length]
// is zero. Returns the sentinel on the first non-zero byte seen.
// Shared by DeserializeCFrag and DeserializeKFrag so any drift in the
// reserved-zone discipline is caught in one place — and because the
// KFrag and CFrag wire formats both depend on this invariant for
// version discrimination, they share the helper.
func assertReservedZoneZero(data []byte, offset, length int, sentinel error) error {
	end := offset + length
	if end > len(data) {
		return fmt.Errorf("%w: reserved range [%d,%d) out of bounds (data len %d)",
			sentinel, offset, end, len(data))
	}
	for i := offset; i < end; i++ {
		if data[i] != 0 {
			return fmt.Errorf("%w at offset %d", sentinel, i)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// Capsule is the curve point pair produced during encryption.
// Contains the ephemeral point E and verification point V. Capsule
// contains only curve points — no private material. Stored in Domain
// Payload permanently. Any party with capsule + M cfrags +
// sk_recipient can decrypt.
//
// V = r * U where U = hashToPoint(pk_owner). V is NOT the DH shared
// secret (r * pk_owner). The DH shared secret is computed internally
// during encryption and NEVER stored in the capsule. V serves only
// as a binding proof that E was generated for a specific pk_owner.
type Capsule struct {
	EX, EY   *big.Int
	VX, VY   *big.Int
	CheckVal [32]byte
}

// KFrag is a re-encryption key fragment. M-of-N threshold; each
// KFrag is independently verifiable.
//
// The blinding scalar b_i is owner-local (ADR-005 §3.5.1): computed
// inside PRE_GenerateKFrags, used once to compute BK = b_i·H, then
// zeroized. It does NOT appear in this struct. The proxy receives BK
// as opaque bytes and relays it to the verifier via the CFrag.
//
// Proxies should call ZeroizeKFrag on end-of-life to clear the
// RKShare scalar.
type KFrag struct {
	ID       byte
	RKShare  *big.Int
	VKX, VKY *big.Int
	BK       [KFragBKLen]byte
}

// CFrag is a ciphertext fragment produced by re-encrypting with one
// KFrag. Wire length 196 bytes (ADR-005 §8.3).
//
// ProofE and ProofZ together are the Schnorr-style DLEQ proof. The
// challenge ProofE is on the wire so the verifier can reconstruct R
// and R' from the response; the locked transcript (vss.DLEQChallenge)
// then gates the challenge against adaptive BK selection.
type CFrag struct {
	EPrimeX, EPrimeY *big.Int
	ID               byte
	VKX, VKY         *big.Int
	BK               [KFragBKLen]byte
	ProofE           *big.Int
	ProofZ           *big.Int
}

// ─────────────────────────────────────────────────────────────────────
// ZeroizeKFrag — lifecycle-end zeroization helper
// ─────────────────────────────────────────────────────────────────────

// ZeroizeKFrag zeros the secret material in a KFrag. Best-effort on
// *big.Int per the package-level zeroization note. Safe on nil.
func ZeroizeKFrag(kf *KFrag) {
	if kf == nil {
		return
	}
	if kf.RKShare != nil {
		kf.RKShare.SetInt64(0)
	}
	for i := range kf.BK {
		kf.BK[i] = 0
	}
	kf.ID = 0
}

// ─────────────────────────────────────────────────────────────────────
// PRE_Encrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_Encrypt encrypts plaintext for pk_owner using an ephemeral DH
// key exchange. Returns a Capsule (public, storable in Domain
// Payload) and ciphertext.
//
// The DH shared secret (r * pk_owner) is used to derive the DEM key
// but is NEVER stored in the capsule. The capsule's V field is
// r * U where U = hashToPoint(pk_owner) — a secondary generator that
// binds the capsule to pk_owner without leaking the shared secret.
func PRE_Encrypt(pk []byte, plaintext []byte) (*Capsule, []byte, error) {
	c := curve()
	pkX, pkY := elliptic.Unmarshal(c, pk)
	if pkX == nil {
		return nil, nil, errors.New("pre: invalid public key")
	}
	if !c.IsOnCurve(pkX, pkY) {
		return nil, nil, errors.New("pre: owner public key is not on the secp256k1 curve")
	}

	r, err := rand.Int(rand.Reader, curveN())
	if err != nil {
		return nil, nil, fmt.Errorf("pre: generating random: %w", err)
	}

	eX, eY := c.ScalarBaseMult(padBigInt(r))
	sharedX, sharedY := c.ScalarMult(pkX, pkY, padBigInt(r))
	demKey := kdf(sharedX, sharedY)

	uX, uY := hashToPoint(pk)
	vX, vY := c.ScalarMult(uX, uY, padBigInt(r))

	ct, err := aesGCMEncrypt(demKey[:], plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("pre: encrypting: %w", err)
	}

	check := hashPoints(eX, eY, vX, vY)

	return &Capsule{
		EX: eX, EY: eY,
		VX: vX, VY: vY,
		CheckVal: check,
	}, ct, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_Decrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_Decrypt decrypts ciphertext using sk_owner and the capsule.
// Direct decryption — no re-encryption involved.
func PRE_Decrypt(sk []byte, capsule *Capsule, ciphertext []byte) ([]byte, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	c := curve()
	vX, vY := c.ScalarMult(capsule.EX, capsule.EY, sk)
	demKey := kdf(vX, vY)
	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// PRE_GenerateKFrags
// ─────────────────────────────────────────────────────────────────────

// PRE_GenerateKFrags generates N threshold re-encryption key
// fragments plus the Pedersen commitment set that Phase D consumers
// publish on-log before distributing KFrags to proxies.
//
// Blinding scalar isolation (ADR-005 §3.5.1): b_i is consumed on the
// iteration that produces BK_i, then zeroized. b_i never leaves this
// function and never enters a KFrag.
//
// sk_owner: 32-byte private key scalar (big-endian).
// pk_recipient: 65-byte uncompressed secp256k1 public key.
func PRE_GenerateKFrags(
	skOwner, pkRecipient []byte,
	M, N int,
) ([]KFrag, vss.Commitments, error) {
	if M < 2 || N < M || N > 255 {
		return nil, vss.Commitments{}, fmt.Errorf(
			"pre: invalid M=%d, N=%d (require 2<=M<=N<=255)", M, N)
	}
	c := curve()
	n := curveN()

	rxX, rxY := elliptic.Unmarshal(c, pkRecipient)
	if rxX == nil {
		return nil, vss.Commitments{}, errors.New("pre: invalid recipient public key")
	}
	if !c.IsOnCurve(rxX, rxY) {
		return nil, vss.Commitments{}, errors.New("pre: recipient public key is not on the secp256k1 curve")
	}

	skA := new(big.Int).SetBytes(skOwner)
	if skA.Sign() == 0 || skA.Cmp(n) >= 0 {
		return nil, vss.Commitments{}, errors.New("pre: invalid owner private key")
	}

	dhX, dhY := c.ScalarMult(rxX, rxY, padBigInt(skA))
	d := hashToScalar(dhX, dhY, n)
	if d.Sign() == 0 {
		return nil, vss.Commitments{}, errors.New("pre: degenerate blinding scalar")
	}

	dInv := new(big.Int).ModInverse(d, n)
	if dInv == nil {
		return nil, vss.Commitments{}, errors.New("pre: d has no inverse")
	}
	rk := new(big.Int).Mul(skA, dInv)
	rk.Mod(rk, n)

	var rkBytes [vss.SecretSize]byte
	copy(rkBytes[:], padBigInt(rk))

	skA.SetInt64(0)
	d.SetInt64(0)
	dInv.SetInt64(0)

	vssShares, commitments, err := vss.Split(rkBytes, M, N)
	if err != nil {
		return nil, vss.Commitments{}, fmt.Errorf("pre: Pedersen VSS split: %w", err)
	}

	rk.SetInt64(0)
	zero32(&rkBytes)

	hX, hY, err := vss.HGenerator()
	if err != nil {
		return nil, vss.Commitments{}, fmt.Errorf("pre: H generator: %w", err)
	}

	// Per-iteration (ADR-005 §3.5.2):
	//   1. Extract rk_i and b_i from the vss share.
	//   2. Compute VK_i = rk_i·G and BK_i = b_i·H.
	//   3. Assemble KFrag (BK as compressed bytes; b_i NOT stored).
	//   4. Zeroize b_i in the source share before the next iteration.
	kfrags := make([]KFrag, N)
	for i := range vssShares {
		s := &vssShares[i]

		rkI := new(big.Int).SetBytes(s.Value[:])
		rkI.Mod(rkI, n)

		vkX, vkY := c.ScalarBaseMult(padBigInt(rkI))

		bi := new(big.Int).SetBytes(s.BlindingFactor[:])
		bi.Mod(bi, n)
		bkX, bkY := c.ScalarMult(hX, hY, padBigInt(bi))

		var bkCompressed [KFragBKLen]byte
		copy(bkCompressed[:], compressedPoint(bkX, bkY))

		kfrags[i] = KFrag{
			ID:      s.Index,
			RKShare: rkI,
			VKX:     vkX,
			VKY:     vkY,
			BK:      bkCompressed,
		}

		bi.SetInt64(0)
		zero32(&s.BlindingFactor)
	}

	return kfrags, commitments, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_ReEncrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_ReEncrypt re-encrypts a capsule using a single KFrag. The
// proxy performs no Pedersen arithmetic — it relays BK as opaque
// bytes from the KFrag into the CFrag (ADR-005 §3.5.1).
//
// The DLEQ challenge is computed via vss.DLEQChallenge over the
// locked transcript (ADR-005 §5.2), which absorbs the commitment
// set and BK_i before the standard DLEQ inputs.
func PRE_ReEncrypt(kfrag KFrag, capsule *Capsule, commitments vss.Commitments) (*CFrag, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	if kfrag.RKShare == nil || kfrag.VKX == nil || kfrag.VKY == nil {
		return nil, fmt.Errorf("%w: kfrag has nil fields", ErrInvalidKFragFormat)
	}
	c := curve()
	n := curveN()

	epX, epY := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(kfrag.RKShare))

	bkX, bkY, err := decompressPoint(kfrag.BK[:])
	if err != nil {
		return nil, fmt.Errorf("%w: BK: %v", ErrInvalidKFragFormat, err)
	}

	t, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("pre: generating DLEQ nonce: %w", err)
	}
	if t.Sign() == 0 {
		t, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, fmt.Errorf("pre: generating DLEQ nonce (retry): %w", err)
		}
	}

	rX, rY := c.ScalarBaseMult(padBigInt(t))
	rPrimeX, rPrimeY := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(t))

	challengeBytes, err := vss.DLEQChallenge(
		commitments,
		bkX, bkY,
		kfrag.VKX, kfrag.VKY,
		capsule.EX, capsule.EY,
		epX, epY,
		uint64(kfrag.ID),
		rX, rY,
		rPrimeX, rPrimeY,
	)
	if err != nil {
		return nil, fmt.Errorf("pre: DLEQ challenge: %w", err)
	}
	e := new(big.Int).SetBytes(challengeBytes[:])
	e.Mod(e, n)

	z := new(big.Int).Mul(e, kfrag.RKShare)
	z.Add(z, t)
	z.Mod(z, n)

	t.SetInt64(0)

	return &CFrag{
		EPrimeX: epX, EPrimeY: epY,
		ID:     kfrag.ID,
		VKX:    kfrag.VKX,
		VKY:    kfrag.VKY,
		BK:     kfrag.BK,
		ProofE: e,
		ProofZ: z,
	}, nil
}

// ═════════════════════════════════════════════════════════════════════
// Security gates — factored for mutation audit
// ═════════════════════════════════════════════════════════════════════
//
// Each gate is a single-purpose function with a clear name and reads
// its corresponding muEnable* constant. Setting the constant to false
// short-circuits the gate, simulating the attack path the gate exists
// to close.
//
// PRE_VerifyCFrag gate order:
//
//	gateCFragStructural          — nil checks, ID != 0, proof fields present
//	gateCommitmentsPresent       — commitments.Threshold() > 0
//	gateCFragOnCurve             — VK, E', capsule.E on-curve
//	gateBKDecompress             — BK decompresses to valid on-curve point
//	checkDLEQ                    — CHECK 1: DLEQ proof verifies
//	checkPedersen                — CHECK 2: Pedersen polynomial holds
//
// PRE_DecryptFrags gate order:
//
//	gateDecryptInputs            — capsule non-nil, cfrags non-empty
//	gateCommitmentsPresent       — commitments.Threshold() > 0 (shared)
//	gateSufficientCFrags         — len(cfrags) >= threshold
//	gateAllCFragsVerify          — every cfrag passes PRE_VerifyCFrag
//	gateOwnerKeyValid            — pkOwner parses and is on-curve
//
// ═════════════════════════════════════════════════════════════════════

// gateCFragStructural verifies the CFrag struct has all required
// non-nil fields and a valid ID. Always enforced — structural
// validation is not a security gate in the sense the audit covers
// (it prevents panics, not attacks).
func gateCFragStructural(cfrag *CFrag) error {
	if cfrag == nil {
		return fmt.Errorf("%w: nil cfrag", ErrInvalidCFragFormat)
	}
	if cfrag.ProofE == nil || cfrag.ProofZ == nil {
		return fmt.Errorf("%w: missing DLEQ proof fields", ErrInvalidCFragFormat)
	}
	if cfrag.VKX == nil || cfrag.VKY == nil {
		return fmt.Errorf("%w: missing VK", ErrInvalidCFragFormat)
	}
	if cfrag.EPrimeX == nil || cfrag.EPrimeY == nil {
		return fmt.Errorf("%w: missing E'", ErrInvalidCFragFormat)
	}
	if cfrag.ID == 0 {
		return fmt.Errorf("%w: index 0 is reserved", ErrInvalidCFragFormat)
	}
	return nil
}

// gateCommitmentsPresent verifies the commitment set is non-empty.
// Controlled by muEnableCommitmentsGate.
func gateCommitmentsPresent(commitments vss.Commitments) error {
	if !muEnableCommitmentsGate {
		return nil
	}
	if commitments.Threshold() == 0 {
		return ErrEmptyCommitments
	}
	return nil
}

// gateCFragOnCurve verifies the CFrag's curve points lie on secp256k1.
// Expects gateCFragStructural to have passed. Controlled by
// muEnableOnCurveGate.
func gateCFragOnCurve(cfrag *CFrag, capsule *Capsule) error {
	if capsule == nil {
		return fmt.Errorf("%w: nil capsule", ErrInvalidCFragFormat)
	}
	if !muEnableOnCurveGate {
		return nil
	}
	c := curve()
	if !c.IsOnCurve(cfrag.VKX, cfrag.VKY) {
		return fmt.Errorf("%w: VK not on curve", ErrInvalidCFragFormat)
	}
	if !c.IsOnCurve(cfrag.EPrimeX, cfrag.EPrimeY) {
		return fmt.Errorf("%w: E' not on curve", ErrInvalidCFragFormat)
	}
	if !c.IsOnCurve(capsule.EX, capsule.EY) {
		return fmt.Errorf("%w: capsule E not on curve", ErrInvalidCFragFormat)
	}
	return nil
}

// gateBKDecompress decompresses and validates BK. Returns the
// decompressed coordinates for use in subsequent checks. Always
// enforced — checkDLEQ and checkPedersen require (bkX, bkY).
func gateBKDecompress(cfrag *CFrag) (*big.Int, *big.Int, error) {
	bkX, bkY, err := decompressPoint(cfrag.BK[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: BK decompress: %v", ErrInvalidCFragFormat, err)
	}
	if !curve().IsOnCurve(bkX, bkY) {
		return nil, nil, fmt.Errorf("%w: BK not on curve", ErrInvalidCFragFormat)
	}
	return bkX, bkY, nil
}

// checkDLEQ is ADR-005 §3.5 CHECK 1: DLEQ proof verification.
//
// Reconstructs R = z·G - e·VK and R' = z·E - e·E' from (z, e, VK, E, E'),
// then recomputes the challenge via the locked transcript and compares.
//
// Controlled by muEnableDLEQCheck.
func checkDLEQ(
	cfrag *CFrag,
	capsule *Capsule,
	commitments vss.Commitments,
	bkX, bkY *big.Int,
) error {
	if !muEnableDLEQCheck {
		return nil
	}
	c := curve()
	n := curveN()
	p := curveP()

	eCanon := new(big.Int).Set(cfrag.ProofE)
	eCanon.Mod(eCanon, n)
	zCanon := new(big.Int).Set(cfrag.ProofZ)
	zCanon.Mod(zCanon, n)

	// R = z·G - e·VK
	zGx, zGy := c.ScalarBaseMult(padBigInt(zCanon))
	eVKx, eVKy := c.ScalarMult(cfrag.VKX, cfrag.VKY, padBigInt(eCanon))
	eVKyNeg := new(big.Int).Sub(p, eVKy)
	eVKyNeg.Mod(eVKyNeg, p)
	rX, rY := c.Add(zGx, zGy, eVKx, eVKyNeg)

	// R' = z·E - e·E'
	zEx, zEy := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(zCanon))
	eEPx, eEPy := c.ScalarMult(cfrag.EPrimeX, cfrag.EPrimeY, padBigInt(eCanon))
	eEPyNeg := new(big.Int).Sub(p, eEPy)
	eEPyNeg.Mod(eEPyNeg, p)
	rPrimeX, rPrimeY := c.Add(zEx, zEy, eEPx, eEPyNeg)

	expectedBytes, err := vss.DLEQChallenge(
		commitments,
		bkX, bkY,
		cfrag.VKX, cfrag.VKY,
		capsule.EX, capsule.EY,
		cfrag.EPrimeX, cfrag.EPrimeY,
		uint64(cfrag.ID),
		rX, rY,
		rPrimeX, rPrimeY,
	)
	if err != nil {
		return fmt.Errorf("%w: transcript: %v", ErrDLEQVerificationFailed, err)
	}
	expected := new(big.Int).SetBytes(expectedBytes[:])
	expected.Mod(expected, n)

	if expected.Cmp(eCanon) != 0 {
		return ErrDLEQVerificationFailed
	}
	return nil
}

// checkPedersen is ADR-005 §3.5 CHECK 2: Pedersen binding.
//
// Delegates to vss.VerifyPoints for the polynomial-consistency check:
//
//	VK + BK = Σ i^j · C_j
//
// Controlled by muEnablePedersenCheck.
func checkPedersen(
	cfrag *CFrag,
	commitments vss.Commitments,
	bkX, bkY *big.Int,
) error {
	if !muEnablePedersenCheck {
		return nil
	}
	if err := vss.VerifyPoints(
		cfrag.ID,
		cfrag.VKX, cfrag.VKY,
		bkX, bkY,
		commitments,
	); err != nil {
		return fmt.Errorf("%w: %v", ErrPedersenVerificationFailed, err)
	}
	return nil
}

// gateDecryptInputs verifies the capsule and cfrag slice are usable.
// Always enforced — prevents nil-pointer panics.
func gateDecryptInputs(capsule *Capsule, cfrags []*CFrag) error {
	if capsule == nil {
		return errors.New("pre: nil capsule")
	}
	if len(cfrags) == 0 {
		return errors.New("pre: no cfrags provided")
	}
	return nil
}

// gateSufficientCFrags verifies at least threshold cfrags were
// supplied. Called after gateCommitmentsPresent so threshold > 0
// (under normal execution). Controlled by muEnableSufficientCFragsGate.
func gateSufficientCFrags(cfrags []*CFrag, commitments vss.Commitments) error {
	if !muEnableSufficientCFragsGate {
		return nil
	}
	if len(cfrags) < commitments.Threshold() {
		return fmt.Errorf("%w: have %d, need threshold %d",
			ErrInsufficientCFrags, len(cfrags), commitments.Threshold())
	}
	return nil
}

// gateAllCFragsVerify verifies every CFrag in the slice passes
// PRE_VerifyCFrag. This is the verify-before-combine gate (ADR-005
// §3.5). Controlled by muEnableVerifyBeforeCombine.
func gateAllCFragsVerify(
	cfrags []*CFrag,
	capsule *Capsule,
	commitments vss.Commitments,
) error {
	if !muEnableVerifyBeforeCombine {
		return nil
	}
	for i, cf := range cfrags {
		if cf == nil {
			return fmt.Errorf("pre: cfrag[%d]: %w", i, ErrInvalidCFragFormat)
		}
		if err := PRE_VerifyCFrag(cf, capsule, commitments); err != nil {
			return fmt.Errorf("pre: cfrag[%d] verification: %w", i, err)
		}
	}
	return nil
}

// gateOwnerKeyValid verifies pkOwner parses as a valid on-curve
// secp256k1 point. Returns the decoded coordinates. Always enforced
// — subsequent ScalarMult would produce garbage on invalid input.
func gateOwnerKeyValid(pkOwner []byte) (*big.Int, *big.Int, error) {
	c := curve()
	ownerX, ownerY := elliptic.Unmarshal(c, pkOwner)
	if ownerX == nil {
		return nil, nil, errors.New("pre: invalid owner public key")
	}
	if !c.IsOnCurve(ownerX, ownerY) {
		return nil, nil, errors.New("pre: owner public key is not on the secp256k1 curve")
	}
	return ownerX, ownerY, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_VerifyCFrag — dual check: DLEQ + Pedersen
// ─────────────────────────────────────────────────────────────────────

// PRE_VerifyCFrag gates CFrag acceptance on two independent
// cryptographic checks (ADR-005 §3.5):
//
//  1. DLEQ — the proxy used a consistent rk_i for both
//     VK_i = rk_i·G and E' = rk_i·E.
//
//  2. Pedersen — the (VK_i, BK_i) pair lies on the polynomial
//     committed at grant time:  VK_i + BK_i = Σ i^j · C_j.
//
// Either failing rejects the CFrag. Both checks are mandatory.
//
// Returns nil on success. On failure returns one of:
//   - ErrInvalidCFragFormat — parse or on-curve failure
//   - ErrDLEQVerificationFailed — DLEQ check failed
//   - ErrPedersenVerificationFailed — Pedersen check failed
//   - ErrEmptyCommitments — empty commitment set
//
// Side-effect-free and safe to call from multiple goroutines.
func PRE_VerifyCFrag(
	cfrag *CFrag,
	capsule *Capsule,
	commitments vss.Commitments,
) error {
	if err := gateCFragStructural(cfrag); err != nil {
		return err
	}
	if err := gateCommitmentsPresent(commitments); err != nil {
		return err
	}
	if err := gateCFragOnCurve(cfrag, capsule); err != nil {
		return err
	}
	bkX, bkY, err := gateBKDecompress(cfrag)
	if err != nil {
		return err
	}
	if err := checkDLEQ(cfrag, capsule, commitments, bkX, bkY); err != nil {
		return err
	}
	if err := checkPedersen(cfrag, commitments, bkX, bkY); err != nil {
		return err
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_DecryptFrags — verify-then-combine-then-decrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_DecryptFrags combines M CFrags and decrypts using the
// recipient's private key. Per ADR-005 §3.5, this primitive verifies
// every CFrag against the commitment set BEFORE Lagrange combination.
// Combination of unverified CFrags is the substitution vulnerability
// this package closes; the verification gate lives here, in the
// primitive.
//
// On any CFrag verification failure, returns the typed verification
// error with an annotation identifying the failing CFrag index.
// Lagrange combination and decryption are NOT attempted.
func PRE_DecryptFrags(
	skRecipient []byte,
	cfrags []*CFrag,
	capsule *Capsule,
	ciphertext []byte,
	pkOwner []byte,
	commitments vss.Commitments,
) ([]byte, error) {
	if err := gateDecryptInputs(capsule, cfrags); err != nil {
		return nil, err
	}
	if err := gateCommitmentsPresent(commitments); err != nil {
		return nil, err
	}
	if err := gateSufficientCFrags(cfrags, commitments); err != nil {
		return nil, err
	}
	if err := gateAllCFragsVerify(cfrags, capsule, commitments); err != nil {
		return nil, err
	}

	ownerX, ownerY, err := gateOwnerKeyValid(pkOwner)
	if err != nil {
		return nil, err
	}

	c := curve()
	n := curveN()

	combinedX, combinedY, err := lagrangeCombinePoints(cfrags, n, c)
	if err != nil {
		return nil, fmt.Errorf("pre: combining cfrags: %w", err)
	}

	dhX, dhY := c.ScalarMult(ownerX, ownerY, skRecipient)
	d := hashToScalar(dhX, dhY, n)

	keyX, keyY := c.ScalarMult(combinedX, combinedY, padBigInt(d))
	demKey := kdf(keyX, keyY)

	d.SetInt64(0)

	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// CFrag wire-format (de)serialization (ADR-005 §8.3)
// ─────────────────────────────────────────────────────────────────────

// SerializeCFrag encodes a CFrag into the fixed 196-byte wire format
// per ADR-005 §8.3. Every field is fixed-width; the overall length
// is a compile-time constant.
func SerializeCFrag(cf *CFrag) ([]byte, error) {
	if cf == nil {
		return nil, fmt.Errorf("%w: nil cfrag", ErrInvalidCFragFormat)
	}
	if cf.VKX == nil || cf.VKY == nil {
		return nil, fmt.Errorf("%w: nil VK", ErrInvalidCFragFormat)
	}
	if cf.EPrimeX == nil || cf.EPrimeY == nil {
		return nil, fmt.Errorf("%w: nil E'", ErrInvalidCFragFormat)
	}
	if cf.ProofE == nil || cf.ProofZ == nil {
		return nil, fmt.Errorf("%w: nil DLEQ proof", ErrInvalidCFragFormat)
	}
	if cf.ID == 0 {
		return nil, fmt.Errorf("%w: index 0 is reserved", ErrInvalidCFragFormat)
	}

	out := make([]byte, CFragWireLen)

	copy(out[cfragOffsetEPrime:cfragOffsetEPrime+33], compressedPoint(cf.EPrimeX, cf.EPrimeY))
	copy(out[cfragOffsetVK:cfragOffsetVK+33], compressedPoint(cf.VKX, cf.VKY))
	copy(out[cfragOffsetBK:cfragOffsetBK+33], cf.BK[:])
	out[cfragOffsetID] = cf.ID
	copy(out[cfragOffsetProofE:cfragOffsetProofE+32], padBigInt(cf.ProofE))
	copy(out[cfragOffsetProofZ:cfragOffsetProofZ+32], padBigInt(cf.ProofZ))
	// Reserved bytes at offset 164..195 are already zero from make().

	return out, nil
}

// DeserializeCFrag decodes a 196-byte wire buffer into a CFrag.
// Performs on-curve and structural validation at ingress, and
// rejects non-zero reserved bytes per ADR-005 §8.3.
//
// The returned CFrag is structurally valid but NOT cryptographically
// verified. Callers must pass it to PRE_VerifyCFrag (or call
// PRE_DecryptFrags, which verifies inline).
func DeserializeCFrag(data []byte) (*CFrag, error) {
	if len(data) != CFragWireLen {
		return nil, fmt.Errorf(
			"%w: expected %d bytes, got %d",
			ErrInvalidCFragFormat, CFragWireLen, len(data),
		)
	}

	// Reserved-bytes check FIRST — cheap rejection before any curve
	// arithmetic on potentially malicious inputs.
	if err := assertReservedZoneZero(data, cfragOffsetReserved, cfragReservedLen, ErrReservedBytesNonZero); err != nil {
		return nil, err
	}

	c := curve()

	epX, epY, err := decompressPoint(data[cfragOffsetEPrime : cfragOffsetEPrime+33])
	if err != nil {
		return nil, fmt.Errorf("%w: E': %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(epX, epY) {
		return nil, fmt.Errorf("%w: E' not on curve", ErrInvalidCFragFormat)
	}

	vkX, vkY, err := decompressPoint(data[cfragOffsetVK : cfragOffsetVK+33])
	if err != nil {
		return nil, fmt.Errorf("%w: VK: %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(vkX, vkY) {
		return nil, fmt.Errorf("%w: VK not on curve", ErrInvalidCFragFormat)
	}

	var bk [KFragBKLen]byte
	copy(bk[:], data[cfragOffsetBK:cfragOffsetBK+33])
	bkX, bkY, err := decompressPoint(bk[:])
	if err != nil {
		return nil, fmt.Errorf("%w: BK: %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(bkX, bkY) {
		return nil, fmt.Errorf("%w: BK not on curve", ErrInvalidCFragFormat)
	}

	id := data[cfragOffsetID]
	if id == 0 {
		return nil, fmt.Errorf("%w: index 0 is reserved", ErrInvalidCFragFormat)
	}

	proofE := new(big.Int).SetBytes(data[cfragOffsetProofE : cfragOffsetProofE+32])
	proofZ := new(big.Int).SetBytes(data[cfragOffsetProofZ : cfragOffsetProofZ+32])

	return &CFrag{
		VKX: vkX, VKY: vkY,
		EPrimeX: epX, EPrimeY: epY,
		BK:     bk,
		ID:     id,
		ProofE: proofE,
		ProofZ: proofZ,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// KFrag wire-format (de)serialization (ADR-005 §5)
// ─────────────────────────────────────────────────────────────────────

// SerializeKFrag encodes a KFrag plaintext into the fixed 196-byte
// wire format per ADR-005 §5:
//
//	Offset  Length  Field
//	   0       1    ID
//	   1      32    RKShare (big-endian padded)
//	  33      33    VK      (compressed)
//	  66      33    BK      (compressed, already stored)
//	  99      97    Reserved (MUST be zero)
//
// Total: 196 bytes. 99 bytes of active material + 97 reserved.
//
// Shares the compressedPoint / padBigInt helpers with SerializeCFrag —
// any drift between KFrag and CFrag point encoding would be a cross-
// layer bug. Reserved bytes are left zero by `make([]byte, ...)`.
//
// Callers that transmit KFrag plaintexts over wire boundaries MUST
// use this serialization. KFrag material is secret — the wire form
// is for transport between the grantor and the proxies, always
// wrapped in an ECIES envelope or equivalent confidentiality layer.
func SerializeKFrag(kf KFrag) ([]byte, error) {
	if kf.RKShare == nil {
		return nil, fmt.Errorf("%w: nil RKShare", ErrInvalidKFragFormat)
	}
	if kf.VKX == nil || kf.VKY == nil {
		return nil, fmt.Errorf("%w: nil VK", ErrInvalidKFragFormat)
	}
	if kf.ID == 0 {
		return nil, fmt.Errorf("%w: index 0 is reserved", ErrInvalidKFragFormat)
	}

	out := make([]byte, KFragWireLen)
	out[kfragOffsetID] = kf.ID
	copy(out[kfragOffsetRKShare:kfragOffsetRKShare+32], padBigInt(kf.RKShare))
	copy(out[kfragOffsetVK:kfragOffsetVK+33], compressedPoint(kf.VKX, kf.VKY))
	copy(out[kfragOffsetBK:kfragOffsetBK+33], kf.BK[:])
	// Reserved bytes at offset 99..195 are already zero from make().
	return out, nil
}

// DeserializeKFrag decodes a 196-byte wire buffer into a KFrag
// plaintext. Validates length, rejects non-zero reserved bytes,
// decompresses and on-curve-checks VK and BK, and reconstructs
// RKShare as a secp256k1 scalar.
//
// Reserved-zone enforcement is gated by muEnableKFragReservedCheck.
// In production the gate is always true; flipping it false is a
// mutation-audit probe that MUST fail the corresponding binding test.
func DeserializeKFrag(data []byte) (*KFrag, error) {
	if len(data) != KFragWireLen {
		return nil, fmt.Errorf(
			"%w: expected %d bytes, got %d",
			ErrInvalidKFragFormat, KFragWireLen, len(data),
		)
	}
	if muEnableKFragReservedCheck {
		if err := assertReservedZoneZero(data, kfragOffsetReserved, kfragReservedLen, ErrKFragReservedBytesNonZero); err != nil {
			return nil, err
		}
	}

	id := data[kfragOffsetID]
	if id == 0 {
		return nil, fmt.Errorf("%w: index 0 is reserved", ErrInvalidKFragFormat)
	}

	c := curve()

	vkX, vkY, err := decompressPoint(data[kfragOffsetVK : kfragOffsetVK+33])
	if err != nil {
		return nil, fmt.Errorf("%w: VK: %v", ErrInvalidKFragFormat, err)
	}
	if !c.IsOnCurve(vkX, vkY) {
		return nil, fmt.Errorf("%w: VK not on curve", ErrInvalidKFragFormat)
	}

	var bk [KFragBKLen]byte
	copy(bk[:], data[kfragOffsetBK:kfragOffsetBK+33])
	bkX, bkY, err := decompressPoint(bk[:])
	if err != nil {
		return nil, fmt.Errorf("%w: BK: %v", ErrInvalidKFragFormat, err)
	}
	if !c.IsOnCurve(bkX, bkY) {
		return nil, fmt.Errorf("%w: BK not on curve", ErrInvalidKFragFormat)
	}

	rk := new(big.Int).SetBytes(data[kfragOffsetRKShare : kfragOffsetRKShare+32])
	if rk.Sign() == 0 {
		return nil, fmt.Errorf("%w: RKShare is zero", ErrInvalidKFragFormat)
	}
	if rk.Cmp(curveN()) >= 0 {
		return nil, fmt.Errorf("%w: RKShare >= curve order", ErrInvalidKFragFormat)
	}

	return &KFrag{
		ID:      id,
		RKShare: rk,
		VKX:     vkX,
		VKY:     vkY,
		BK:      bk,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Lagrange combination
// ─────────────────────────────────────────────────────────────────────

// lagrangeCombinePoints combines CFrags using Lagrange interpolation
// on curve points. The result is sum_i λ_i · E'_i where λ_i are the
// standard Lagrange coefficients at x=0 for the supplied share IDs.
//
// Callers MUST have verified every CFrag before invoking this
// function (PRE_DecryptFrags does this). Unverified inputs produce
// a mathematically-correct combination of attacker-chosen values,
// which is the substitution vulnerability this package closes.
func lagrangeCombinePoints(cfrags []*CFrag, n *big.Int, c elliptic.Curve) (*big.Int, *big.Int, error) {
	xs := make([]*big.Int, len(cfrags))
	seen := make(map[byte]bool, len(cfrags))
	for i, cf := range cfrags {
		if cf == nil {
			return nil, nil, fmt.Errorf("%w: nil cfrag at slot %d", ErrInvalidCFragFormat, i)
		}
		if seen[cf.ID] {
			return nil, nil, fmt.Errorf(
				"%w: duplicate share ID %d", ErrInvalidCFragFormat, cf.ID)
		}
		seen[cf.ID] = true
		xs[i] = big.NewInt(int64(cf.ID))
	}

	lambdas := make([]*big.Int, len(cfrags))
	for i := range cfrags {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range cfrags {
			if i == j {
				continue
			}
			neg := new(big.Int).Neg(xs[j])
			neg.Mod(neg, n)
			num.Mul(num, neg)
			num.Mod(num, n)
			diff := new(big.Int).Sub(xs[i], xs[j])
			diff.Mod(diff, n)
			den.Mul(den, diff)
			den.Mod(den, n)
		}
		denInv := new(big.Int).ModInverse(den, n)
		if denInv == nil {
			return nil, nil, errors.New("pre: degenerate Lagrange interpolation")
		}
		lambdas[i] = new(big.Int).Mul(num, denInv)
		lambdas[i].Mod(lambdas[i], n)
	}

	var sumX, sumY *big.Int
	for i, cf := range cfrags {
		px, py := c.ScalarMult(cf.EPrimeX, cf.EPrimeY, padBigInt(lambdas[i]))
		if sumX == nil {
			sumX, sumY = px, py
		} else {
			sumX, sumY = c.Add(sumX, sumY, px, py)
		}
	}
	if sumX == nil {
		return nil, nil, errors.New("pre: empty combination")
	}
	return sumX, sumY, nil
}

// ─────────────────────────────────────────────────────────────────────
// Point encoding / decoding
// ─────────────────────────────────────────────────────────────────────

// compressedPoint returns the 33-byte SEC 1 compressed encoding of
// (x, y) on secp256k1. Prefix 0x02 for even y, 0x03 for odd.
func compressedPoint(x, y *big.Int) []byte {
	out := make([]byte, 33)
	if y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(out[33-len(xBytes):], xBytes)
	return out
}

// decompressPoint decodes a 33-byte compressed secp256k1 point into
// (x, y). Validates the prefix byte and reconstructs y from x via
// y² = x³ + 7 mod p.
func decompressPoint(raw []byte) (*big.Int, *big.Int, error) {
	if len(raw) != 33 {
		return nil, nil, fmt.Errorf("compressed point must be 33 bytes, got %d", len(raw))
	}
	prefix := raw[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil, fmt.Errorf("invalid point prefix 0x%02x", prefix)
	}
	p := curveP()
	x := new(big.Int).SetBytes(raw[1:33])
	if x.Cmp(p) >= 0 {
		return nil, nil, errors.New("x coordinate out of field")
	}

	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(x3, big.NewInt(7))
	rhs.Mod(rhs, p)

	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, p)

	yCheck := new(big.Int).Mul(y, y)
	yCheck.Mod(yCheck, p)
	if yCheck.Cmp(rhs) != 0 {
		return nil, nil, errors.New("x coordinate is not on curve")
	}

	wantOdd := prefix == 0x03
	isOdd := y.Bit(0) == 1
	if wantOdd != isOdd {
		y = new(big.Int).Sub(p, y)
	}

	return x, y, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers — hashing and encoding
// ─────────────────────────────────────────────────────────────────────

// hashToPoint maps arbitrary bytes to a point on secp256k1 using
// try-and-increment. Used to derive the secondary generator
// U = hashToPoint(pk_owner) for the capsule's V component.
//
// This is NOT the same construction as vss.HGenerator's try-and-
// increment. hashToPoint derives U (capsule-facing); HGenerator
// derives H (Pedersen-facing). Separate purposes, separate seeds,
// separate derivations.
func hashToPoint(input []byte) (*big.Int, *big.Int) {
	c := curve()
	p := curveP()

	seven := big.NewInt(7)
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)

	for counter := uint32(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte("ortholog-pre-h2c"))
		h.Write(input)
		var ctr [4]byte
		ctr[0] = byte(counter >> 24)
		ctr[1] = byte(counter >> 16)
		ctr[2] = byte(counter >> 8)
		ctr[3] = byte(counter)
		h.Write(ctr[:])
		digest := h.Sum(nil)

		x := new(big.Int).SetBytes(digest)
		x.Mod(x, p)

		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		x3.Mod(x3, p)
		ySquared := new(big.Int).Add(x3, seven)
		ySquared.Mod(ySquared, p)

		y := new(big.Int).Exp(ySquared, exp, p)
		yCheck := new(big.Int).Mul(y, y)
		yCheck.Mod(yCheck, p)

		if yCheck.Cmp(ySquared) == 0 {
			if y.Bit(0) == 1 {
				y.Sub(p, y)
			}
			if c.IsOnCurve(x, y) {
				return x, y
			}
		}
		if counter > 1000 {
			panic("hashToPoint: exceeded 1000 iterations")
		}
	}
}

// kdf derives a 32-byte AES key from a curve point using SHA-256.
func kdf(x, y *big.Int) [32]byte {
	var data []byte
	data = append(data, padBigInt(x)...)
	data = append(data, padBigInt(y)...)
	return sha256.Sum256(data)
}

// hashPoints produces a check value from two curve points.
func hashPoints(x1, y1, x2, y2 *big.Int) [32]byte {
	var data []byte
	data = append(data, padBigInt(x1)...)
	data = append(data, padBigInt(y1)...)
	data = append(data, padBigInt(x2)...)
	data = append(data, padBigInt(y2)...)
	return sha256.Sum256(data)
}

// hashToScalar hashes a curve point to a non-zero scalar in Z_n.
func hashToScalar(x, y *big.Int, n *big.Int) *big.Int {
	var data []byte
	data = append(data, padBigInt(x)...)
	data = append(data, padBigInt(y)...)
	digest := sha256.Sum256(data)
	result := new(big.Int).SetBytes(digest[:])
	result.Mod(result, n)
	if result.Sign() == 0 {
		result.SetInt64(1)
	}
	return result
}

// padBigInt pads a big.Int to exactly 32 bytes (secp256k1 scalar
// width). big.Int.Bytes() strips leading zeros; callers of
// ScalarMult / ScalarBaseMult expect fixed-width inputs.
func padBigInt(b *big.Int) []byte {
	buf := b.Bytes()
	if len(buf) >= 32 {
		return buf[len(buf)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	return padded
}

// zero32 zeroes a 32-byte array in place. Best-effort — Go's runtime
// may have cached copies in registers or temporary buffers.
func zero32(b *[32]byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─────────────────────────────────────────────────────────────────────
// AES-GCM wrappers
// ─────────────────────────────────────────────────────────────────────

// aesGCMEncrypt encrypts with AES-256-GCM. Nonce is prepended to ciphertext.
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return ct, nil
}

// aesGCMDecrypt decrypts AES-256-GCM. Nonce is read from the prefix
// of the ciphertext.
func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("pre: ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ct := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
