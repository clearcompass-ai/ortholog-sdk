// Package artifact — pre.go implements Umbral Threshold Proxy Re-Encryption
// on secp256k1 with Pedersen VSS binding (v7.75, ADR-005 Draft 3).
//
// Pure crypto functions. Stateless. No DID resolution needed.
// Callers resolve DIDs to public keys before calling these.
//
// Relationship to AES-256-GCM (api.go):
//
//	AES-256-GCM = storage encryption (artifact at rest, permanent)
//	Umbral PRE  = access control (who can decrypt, additive)
//	Composable: Umbral wraps/transforms the AES key
//	Schemas declare which access model: aes_gcm | umbral_pre
//
// v7.75 cryptographic binding (ADR-005 §3.5):
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
// Combine-before-verify defense (ADR-005 §3.5, G2):
//
//	PRE_DecryptFrags verifies every CFrag against the commitment
//	set BEFORE Lagrange combination. Combination of unverified
//	CFrags is the substitution vulnerability this package closes.
//	The verification gate lives in the primitive, not in callers;
//	a caller that forgets verification cannot reintroduce the
//	v7.5 attack window.
//
// Wire format (ADR-005 §8.3):
//
//	v7.5  CFrag: 163 bytes, no Pedersen binding.
//	v7.75 CFrag: 196 bytes.
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
//	A v7.5 verifier handed a v7.75 CFrag rejects at length;
//	and vice versa. Length is the version discriminator.
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
//	overwritten. Process memory dumps, swap partitions, and shared-
//	tenant hypervisor snapshots can therefore capture residual
//	secret material. Deployments with strict zeroization
//	requirements MUST run sk_owner operations inside a hardware
//	enclave (HSM or TEE) where the secret never enters Go-managed
//	memory.
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

// ─────────────────────────────────────────────────────────────────────
// Curve helpers
// ─────────────────────────────────────────────────────────────────────

// curve returns the secp256k1 curve as an elliptic.Curve.
// v7.75 Phase A′ migrated this package from github.com/dustinxie/ecc
// to github.com/decred/dcrd/dcrec/secp256k1/v4. Wire formats are
// unchanged — the curve math is identical; only the backing library
// differs.
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
	// empty commitment set, or when PRE_GenerateKFrags produces one
	// (defensive; should not occur in correct flows).
	ErrEmptyCommitments = errors.New("pre: empty commitment set")

	// ErrInvalidPoint is returned when a point argument is nil or
	// off-curve.
	ErrInvalidPoint = errors.New("pre: invalid curve point")

	// ErrReservedBytesNonZero is returned by DeserializeCFrag when
	// the 32-byte reserved zone (offset 164..195) contains any
	// non-zero byte. Reserved bytes are forward-compatibility space
	// for v8; v7.75 deserializers reject non-zero to prevent silent
	// acceptance of future CFrag extensions.
	ErrReservedBytesNonZero = errors.New("pre: CFrag reserved bytes must be zero")
)

// ─────────────────────────────────────────────────────────────────────
// Wire constants (ADR-005 §8.3)
// ─────────────────────────────────────────────────────────────────────

// CFragWireLen is the fixed on-wire size of a v7.75 serialized CFrag
// per ADR-005 §8.3. 196 bytes: 132 bytes of point content (E', VK, BK),
// 1 byte ID, 64 bytes DLEQ proof (ProofE, ProofZ), 32 bytes reserved.
const CFragWireLen = 196

// cfragOffsetEPrime and friends locate each field in the wire buffer.
// These are the canonical offsets per ADR-005 §8.3. Serializer and
// deserializer MUST use these constants; inlining them risks drift.
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

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// Capsule is the curve point pair produced during encryption.
// Contains the ephemeral point E and verification point V.
// Capsule contains only curve points — no private material.
// Stored in Domain Payload permanently. Any party with capsule +
// M cfrags + sk_recipient can decrypt.
//
// SECURITY: V = r * U where U = hashToPoint(pk_owner). V is NOT the
// DH shared secret (r * pk_owner). The DH shared secret is computed
// internally during encryption and NEVER stored in the capsule. V
// serves only as a binding proof that E was generated for a specific
// pk_owner.
type Capsule struct {
	EX, EY   *big.Int // E = r * G (ephemeral public key)
	VX, VY   *big.Int // V = r * U where U = hashToPoint(pk_owner)
	CheckVal [32]byte // H(E || V) for capsule integrity
}

// KFrag is a re-encryption key fragment (v7.75 wire format).
// M-of-N threshold; each KFrag is independently verifiable.
//
// Fields populated by the OWNER at PRE_GenerateKFrags:
//   - ID, RKShare, VKX/VKY  — Umbral re-encryption share
//   - BK                    — Pedersen commitment to the blinding scalar
//
// The blinding scalar b_i is owner-local (ADR-005 §3.5.1): computed
// inside PRE_GenerateKFrags, used once to compute BK = b_i·H, then
// zeroized. It does NOT appear in this struct. The proxy receives BK
// as opaque bytes and relays it to the verifier via the CFrag.
//
// Proxies holding KFrags should call ZeroizeKFrag on end-of-life to
// clear the RKShare scalar (the proxy's secret material).
type KFrag struct {
	ID       byte             // Share index (1-based, 1..255)
	RKShare  *big.Int         // Shamir share of the re-encryption key (scalar)
	VKX, VKY *big.Int         // Verification key VK_i = RKShare * G
	BK       [KFragBKLen]byte // Pedersen commitment BK_i = b_i·H (compressed).
	// Opaque to the proxy. Relayed verbatim to CFrag for verifier consumption.
}

// CFrag is a ciphertext fragment produced by re-encrypting with one
// KFrag. v7.75 extends the v7.5 CFrag with BK_i; wire length grows
// from 163 to 196 bytes (ADR-005 §8.3).
//
// ProofE and ProofZ together are the Schnorr-style DLEQ proof. The
// challenge ProofE is on the wire so the verifier can reconstruct R
// and R' from the response; the locked transcript (vss.DLEQChallenge)
// then gates the challenge against adaptive BK selection.
type CFrag struct {
	EPrimeX, EPrimeY *big.Int         // E' = rk_i * capsule.E
	ID               byte             // KFrag ID this came from
	VKX, VKY         *big.Int         // VK_i = rk_i·G, carried for verifier convenience
	BK               [KFragBKLen]byte // Pedersen commitment BK_i (compressed), copied from KFrag
	ProofE           *big.Int         // DLEQ challenge, mod n
	ProofZ           *big.Int         // DLEQ response z = t + e·rk_i mod n
}

// ─────────────────────────────────────────────────────────────────────
// ZeroizeKFrag — lifecycle-end zeroization helper
// ─────────────────────────────────────────────────────────────────────

// ZeroizeKFrag zeros the secret material in a KFrag after the proxy
// no longer needs it. Best-effort on *big.Int per the package-level
// zeroization note. Safe to call on nil (no-op).
//
// Fields zeroed:
//   - RKShare (secret scalar — proxy's re-encryption share)
//   - BK (not secret, but cleared for consistency and to prevent stale
//     KFrag reuse by a confused caller)
//   - ID (reset to 0)
//
// VKX/VKY are not zeroed — they are public curve points; clearing them
// adds no security and may cause nil-pointer panics if the caller
// accidentally references them post-zeroize.
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
// PRE_Encrypt — unchanged from v7.5
// ─────────────────────────────────────────────────────────────────────

// PRE_Encrypt encrypts plaintext for pk_owner using an ephemeral DH
// key exchange. Returns a Capsule (public, storable in Domain
// Payload) and ciphertext.
//
// pk is the master public key (secp256k1 uncompressed, 65 bytes).
//
// SECURITY: The DH shared secret (r * pk_owner) is used to derive the
// DEM key but is NEVER stored in the capsule. The capsule's V field
// is r * U where U = hashToPoint(pk_owner) — a secondary generator
// that binds the capsule to pk_owner without leaking the shared
// secret.
func PRE_Encrypt(pk []byte, plaintext []byte) (*Capsule, []byte, error) {
	c := curve()
	pkX, pkY := elliptic.Unmarshal(c, pk)
	if pkX == nil {
		return nil, nil, errors.New("pre: invalid public key")
	}
	if !c.IsOnCurve(pkX, pkY) {
		return nil, nil, errors.New("pre: owner public key is not on the secp256k1 curve")
	}

	// r ← random scalar in [1, n-1]
	r, err := rand.Int(rand.Reader, curveN())
	if err != nil {
		return nil, nil, fmt.Errorf("pre: generating random: %w", err)
	}

	// E = r * G
	eX, eY := c.ScalarBaseMult(padBigInt(r))

	// Shared secret = r * pk_owner (used for DEM key, NEVER stored)
	sharedX, sharedY := c.ScalarMult(pkX, pkY, padBigInt(r))
	demKey := kdf(sharedX, sharedY)

	// V = r * U where U = hashToPoint(pk_owner)
	uX, uY := hashToPoint(pk)
	vX, vY := c.ScalarMult(uX, uY, padBigInt(r))

	// Encrypt plaintext with AES-256-GCM
	ct, err := aesGCMEncrypt(demKey[:], plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("pre: encrypting: %w", err)
	}

	// Check value for capsule integrity
	check := hashPoints(eX, eY, vX, vY)

	return &Capsule{
		EX: eX, EY: eY,
		VX: vX, VY: vY,
		CheckVal: check,
	}, ct, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_Decrypt — unchanged from v7.5
// ─────────────────────────────────────────────────────────────────────

// PRE_Decrypt decrypts ciphertext using sk_owner and the capsule.
// Direct decryption — no re-encryption involved. sk is the private
// key scalar as 32 bytes (big-endian).
func PRE_Decrypt(sk []byte, capsule *Capsule, ciphertext []byte) ([]byte, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	c := curve()

	// V' = sk_owner * E
	vX, vY := c.ScalarMult(capsule.EX, capsule.EY, sk)

	// DEM key = KDF(V')
	demKey := kdf(vX, vY)

	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// PRE_GenerateKFrags (v7.75) — returns Pedersen commitments
// ─────────────────────────────────────────────────────────────────────

// PRE_GenerateKFrags generates N threshold re-encryption key
// fragments plus the Pedersen commitment set that Phase D consumers
// MUST publish on-log before distributing KFrags to proxies.
//
// BREAKING CHANGE vs v7.5: adds vss.Commitments as a return value.
// Callers in v7.5 captured two return values (kfrags, err); v7.75
// callers capture three (kfrags, commitments, err).
//
// The commitment set is the grant's cryptographic anchor. Any party
// holding (CFrag, commitments, pkOwner, pkRecipient) can verify the
// CFrag without interaction with the owner or proxy. Phase D
// publishes the commitment set via the pre-grant-commitment-v1
// schema before the first KFrag is distributed to any proxy.
//
// Blinding scalar isolation (ADR-005 §3.5.1): b_i is consumed on the
// iteration that produces BK_i, then zeroized in the source vss.Share
// before the next iteration. b_i never leaves this function and never
// enters a KFrag.
//
// sk_owner: 32-byte private key scalar (big-endian).
// pk_recipient: 65-byte uncompressed secp256k1 public key.
func PRE_GenerateKFrags(
	skOwner, pkRecipient []byte,
	M, N int,
) ([]KFrag, vss.Commitments, error) {
	if M < 2 || N < M || N > 255 {
		return nil, vss.Commitments{}, fmt.Errorf(
			"pre: invalid M=%d, N=%d (require 2<=M<=N<=255)",
			M, N,
		)
	}
	c := curve()
	n := curveN()

	// Parse recipient public key.
	rxX, rxY := elliptic.Unmarshal(c, pkRecipient)
	if rxX == nil {
		return nil, vss.Commitments{}, errors.New("pre: invalid recipient public key")
	}
	if !c.IsOnCurve(rxX, rxY) {
		return nil, vss.Commitments{}, errors.New("pre: recipient public key is not on the secp256k1 curve")
	}

	// sk_owner as big.Int.
	skA := new(big.Int).SetBytes(skOwner)
	if skA.Sign() == 0 || skA.Cmp(n) >= 0 {
		return nil, vss.Commitments{}, errors.New("pre: invalid owner private key")
	}

	// ECDH shared secret.
	dhX, dhY := c.ScalarMult(rxX, rxY, padBigInt(skA))

	// d = H_scalar(dh_point) — deterministic blinding scalar derived
	// from the shared secret.
	d := hashToScalar(dhX, dhY, n)
	if d.Sign() == 0 {
		return nil, vss.Commitments{}, errors.New("pre: degenerate blinding scalar")
	}

	// rk = sk_owner * inv(d) mod n.
	dInv := new(big.Int).ModInverse(d, n)
	if dInv == nil {
		return nil, vss.Commitments{}, errors.New("pre: d has no inverse")
	}
	rk := new(big.Int).Mul(skA, dInv)
	rk.Mod(rk, n)

	// Pack rk into 32 bytes for the vss primitive.
	var rkBytes [vss.SecretSize]byte
	copy(rkBytes[:], padBigInt(rk))

	// Zero the intermediate scalars we no longer need.
	skA.SetInt64(0)
	d.SetInt64(0)
	dInv.SetInt64(0)

	// Pedersen VSS split:
	//   - N shares, each with Index, Value=f(i), BlindingFactor=r(i),
	//     CommitmentHash
	//   - Commitment set {C_j = a_j·G + b_j·H : j=0..M-1}
	vssShares, commitments, err := vss.Split(rkBytes, M, N)
	if err != nil {
		return nil, vss.Commitments{}, fmt.Errorf("pre: Pedersen VSS split: %w", err)
	}

	// rk has been split into shares; zero the byte form and the scalar.
	rk.SetInt64(0)
	zero32(&rkBytes)

	// Fetch H (cached after first call). Owner-side only.
	hX, hY, err := vss.HGenerator()
	if err != nil {
		return nil, vss.Commitments{}, fmt.Errorf("pre: H generator: %w", err)
	}

	// Build KFrags. Per-iteration (ADR-005 §3.5.2):
	//   1. Extract rk_i and b_i from the vss share.
	//   2. Compute VK_i = rk_i·G and BK_i = b_i·H.
	//   3. Assemble KFrag (BK as compressed bytes; b_i scalar NOT stored).
	//   4. Zeroize b_i in the source share before the next iteration.
	kfrags := make([]KFrag, N)
	for i := range vssShares {
		s := &vssShares[i]

		rkI := new(big.Int).SetBytes(s.Value[:])
		rkI.Mod(rkI, n)

		vkX, vkY := c.ScalarBaseMult(padBigInt(rkI))

		// BK_i = b_i · H  (owner-side computation; b_i never leaves this loop)
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

		// Zero b_i — it has served its purpose. The source share's
		// BlindingFactor byte array is zeroed so that a subsequent
		// memory dump cannot recover it.
		bi.SetInt64(0)
		zero32(&s.BlindingFactor)
	}

	return kfrags, commitments, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_ReEncrypt (v7.75) — produces CFrag with locked DLEQ transcript
// ─────────────────────────────────────────────────────────────────────

// PRE_ReEncrypt re-encrypts a capsule using a single KFrag. Produces
// a CFrag carrying the DLEQ proof AND the KFrag's BK (copied
// verbatim). The proxy performs no Pedersen arithmetic — it relays
// BK as opaque bytes from the KFrag into the CFrag (ADR-005 §3.5.1).
//
// BREAKING CHANGE vs v7.5: the DLEQ challenge is computed via
// vss.DLEQChallenge over the locked transcript (ADR-005 §5.2), which
// absorbs the commitment set and BK_i before the standard DLEQ
// inputs. The commitments argument must match the grant's published
// commitment set; the proxy retains it alongside the KFrag.
//
// The returned CFrag carries ProofE (challenge) and ProofZ (response)
// per ADR-005 §8.3.2. On verification, the verifier reconstructs R
// and R' from (ProofZ, ProofE, VK, E, E'), then re-derives the
// challenge over the transcript and compares.
func PRE_ReEncrypt(kfrag KFrag, capsule *Capsule, commitments vss.Commitments) (*CFrag, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	if commitments.Threshold() == 0 {
		return nil, ErrEmptyCommitments
	}
	if kfrag.RKShare == nil || kfrag.VKX == nil || kfrag.VKY == nil {
		return nil, fmt.Errorf("%w: kfrag has nil fields", ErrInvalidKFragFormat)
	}
	c := curve()
	n := curveN()

	// E' = rk_i * capsule.E
	epX, epY := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(kfrag.RKShare))

	// Decompress BK to (x, y) for the transcript.
	bkX, bkY, err := decompressPoint(kfrag.BK[:])
	if err != nil {
		return nil, fmt.Errorf("%w: BK: %v", ErrInvalidKFragFormat, err)
	}

	// Sample DLEQ nonce t ∈ F_n \ {0}.
	t, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("pre: generating DLEQ nonce: %w", err)
	}
	if t.Sign() == 0 {
		// rand.Int returns [0, n); re-roll is astronomically unlikely
		// but not impossible over a weak reader.
		t, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, fmt.Errorf("pre: generating DLEQ nonce (retry): %w", err)
		}
	}

	// R = t·G, R' = t·E
	rX, rY := c.ScalarBaseMult(padBigInt(t))
	rPrimeX, rPrimeY := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(t))

	// Challenge e = DLEQChallenge(transcript), transcript per ADR-005 §5.2.
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

	// z = t + e · rk_i mod n
	z := new(big.Int).Mul(e, kfrag.RKShare)
	z.Add(z, t)
	z.Mod(z, n)

	// Zero the DLEQ nonce.
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

// ─────────────────────────────────────────────────────────────────────
// PRE_VerifyCFrag (v7.75) — dual check: DLEQ + Pedersen
// ─────────────────────────────────────────────────────────────────────

// PRE_VerifyCFrag gates CFrag acceptance on two independent
// cryptographic checks (ADR-005 §3.5):
//
//  1. DLEQ — the proxy used a consistent rk_i for both
//     VK_i = rk_i·G and E' = rk_i·E. Establishes that the proxy did
//     not lie about its own key pair.
//
//  2. Pedersen — the (VK_i, BK_i) pair lies on the polynomial
//     committed at grant time:  VK_i + BK_i = Σ i^j · C_j.
//     Establishes that the proxy's key pair corresponds to a
//     legitimate split of the re-encryption key, not an attacker-
//     chosen forgery.
//
// Either failing rejects the CFrag. Both checks are mandatory.
//
// BREAKING CHANGE vs v7.5: new commitments parameter. Phase D
// callers fetch commitments from the on-log pre-grant-commitment-v1
// entry before calling this function.
//
// Returns nil on success. On failure returns one of:
//   - ErrInvalidCFragFormat — parse or on-curve failure
//   - ErrDLEQVerificationFailed — DLEQ check failed
//   - ErrPedersenVerificationFailed — Pedersen check failed
//   - ErrEmptyCommitments — empty commitment set
//
// The function is side-effect-free and safe to call from multiple
// goroutines in parallel.
func PRE_VerifyCFrag(
	cfrag *CFrag,
	capsule *Capsule,
	commitments vss.Commitments,
) error {
	// Input structural validation.
	if cfrag == nil {
		return fmt.Errorf("%w: nil cfrag", ErrInvalidCFragFormat)
	}
	if capsule == nil {
		return fmt.Errorf("%w: nil capsule", ErrInvalidCFragFormat)
	}
	if commitments.Threshold() == 0 {
		return ErrEmptyCommitments
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

	c := curve()
	n := curveN()
	p := curveP()

	// On-curve validation for all point inputs.
	if !c.IsOnCurve(cfrag.VKX, cfrag.VKY) {
		return fmt.Errorf("%w: VK not on curve", ErrInvalidCFragFormat)
	}
	if !c.IsOnCurve(cfrag.EPrimeX, cfrag.EPrimeY) {
		return fmt.Errorf("%w: E' not on curve", ErrInvalidCFragFormat)
	}
	if !c.IsOnCurve(capsule.EX, capsule.EY) {
		return fmt.Errorf("%w: capsule E not on curve", ErrInvalidCFragFormat)
	}

	// Decompress and validate BK.
	bkX, bkY, err := decompressPoint(cfrag.BK[:])
	if err != nil {
		return fmt.Errorf("%w: BK decompress: %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(bkX, bkY) {
		return fmt.Errorf("%w: BK not on curve", ErrInvalidCFragFormat)
	}

	// Scalar canonicalization. ProofE and ProofZ may arrive from
	// wire bytes; reduce mod n before using in curve operations.
	eCanon := new(big.Int).Set(cfrag.ProofE)
	eCanon.Mod(eCanon, n)
	zCanon := new(big.Int).Set(cfrag.ProofZ)
	zCanon.Mod(zCanon, n)

	// CHECK 1: DLEQ verification.
	//
	// Reconstruct R and R' from (z, e, VK, E, E'):
	//   R  = z·G - e·VK
	//   R' = z·E - e·E'
	//
	// Then recompute the challenge via the locked transcript and
	// compare.

	// R = z·G - e·VK
	zGx, zGy := c.ScalarBaseMult(padBigInt(zCanon))
	eVKx, eVKy := c.ScalarMult(cfrag.VKX, cfrag.VKY, padBigInt(eCanon))
	eVKyNeg := new(big.Int).Sub(p, eVKy) // -eVK on the curve = (x, p-y)
	eVKyNeg.Mod(eVKyNeg, p)
	rX, rY := c.Add(zGx, zGy, eVKx, eVKyNeg)

	// R' = z·E - e·E'
	zEx, zEy := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(zCanon))
	eEPx, eEPy := c.ScalarMult(cfrag.EPrimeX, cfrag.EPrimeY, padBigInt(eCanon))
	eEPyNeg := new(big.Int).Sub(p, eEPy)
	eEPyNeg.Mod(eEPyNeg, p)
	rPrimeX, rPrimeY := c.Add(zEx, zEy, eEPx, eEPyNeg)

	// Recompute the challenge over the transcript.
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

	// CHECK 2: Pedersen binding.
	//
	// Delegate to vss.VerifyPoints, which performs the polynomial-
	// consistency check:  VK + BK = Σ i^j · C_j
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

// ─────────────────────────────────────────────────────────────────────
// PRE_DecryptFrags (v7.75, G2) — verify-then-combine-then-decrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_DecryptFrags combines M CFrags and decrypts using the
// recipient's private key. Per ADR-005 §3.5, this primitive verifies
// every CFrag against the commitment set BEFORE Lagrange combination.
// Combination of unverified CFrags is the substitution vulnerability
// v7.75 is written to close; the verification gate lives here, in
// the primitive.
//
// BREAKING CHANGE vs v7.5: adds commitments and capsule verification.
// v7.5 signature was
//
//	PRE_DecryptFrags(skRecipient, cfrags, capsule, ciphertext, pkOwner)
//
// v7.75 signature is
//
//	PRE_DecryptFrags(skRecipient, cfrags, capsule, ciphertext, pkOwner, commitments)
//
// On any CFrag verification failure, returns the typed verification
// error with an annotation identifying the failing CFrag index.
// Lagrange combination and decryption are NOT attempted.
//
// sk_recipient: 32-byte private key scalar.
// pk_owner: 65-byte uncompressed public key of the capsule creator.
// commitments: the grant's on-log commitment set (from
//
//	pre-grant-commitment-v1 schema).
func PRE_DecryptFrags(
	skRecipient []byte,
	cfrags []*CFrag,
	capsule *Capsule,
	ciphertext []byte,
	pkOwner []byte,
	commitments vss.Commitments,
) ([]byte, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	if len(cfrags) == 0 {
		return nil, errors.New("pre: no cfrags provided")
	}
	if commitments.Threshold() == 0 {
		return nil, ErrEmptyCommitments
	}
	if len(cfrags) < commitments.Threshold() {
		return nil, fmt.Errorf(
			"pre: insufficient cfrags: have %d, need threshold %d",
			len(cfrags), commitments.Threshold(),
		)
	}

	// VERIFY-BEFORE-COMBINE (ADR-005 §3.5, G2).
	// Every CFrag must pass both DLEQ and Pedersen checks before any
	// combination arithmetic. A single failing CFrag aborts decryption.
	for i, cf := range cfrags {
		if cf == nil {
			return nil, fmt.Errorf(
				"pre: cfrag[%d]: %w", i, ErrInvalidCFragFormat,
			)
		}
		if err := PRE_VerifyCFrag(cf, capsule, commitments); err != nil {
			return nil, fmt.Errorf("pre: cfrag[%d] verification: %w", i, err)
		}
	}

	c := curve()
	n := curveN()

	// Parse owner public key for ECDH.
	ownerX, ownerY := elliptic.Unmarshal(c, pkOwner)
	if ownerX == nil {
		return nil, errors.New("pre: invalid owner public key")
	}
	if !c.IsOnCurve(ownerX, ownerY) {
		return nil, errors.New("pre: owner public key is not on the secp256k1 curve")
	}

	// Combine CFrags via Lagrange interpolation on curve points.
	// At this point every CFrag has been verified; combination is safe.
	combinedX, combinedY, err := lagrangeCombinePoints(cfrags, n, c)
	if err != nil {
		return nil, fmt.Errorf("pre: combining cfrags: %w", err)
	}

	// d = H_scalar(ECDH(sk_recipient, pk_owner)).
	dhX, dhY := c.ScalarMult(ownerX, ownerY, skRecipient)
	d := hashToScalar(dhX, dhY, n)

	// key_point = d * E'_combined.
	keyX, keyY := c.ScalarMult(combinedX, combinedY, padBigInt(d))

	// DEM key = KDF(key_point).
	demKey := kdf(keyX, keyY)

	// Zero the ephemeral scalars.
	d.SetInt64(0)

	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// CFrag wire-format (de)serialization (ADR-005 §8.3)
// ─────────────────────────────────────────────────────────────────────

// SerializeCFrag encodes a CFrag into the fixed 196-byte v7.75 wire
// format per ADR-005 §8.3:
//
//	offset  len  field
//	  0      33  E'        (compressed)
//	 33      33  VK        (compressed)
//	 66      33  BK        (compressed, copied verbatim from KFrag)
//	 99       1  ID
//	100      32  ProofE    (challenge, mod n, padded BE)
//	132      32  ProofZ    (response, mod n, padded BE)
//	164      32  Reserved  (MUST be zero; rejected if non-zero on deserialize)
//	Total:  196 bytes
//
// The encoding is unambiguous: every field is fixed-width and the
// overall length is a compile-time constant. A v7.5 CFrag (163 bytes)
// fed to DeserializeCFrag rejects at the length check.
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

	// E' at offset 0.
	epComp := compressedPoint(cf.EPrimeX, cf.EPrimeY)
	copy(out[cfragOffsetEPrime:cfragOffsetEPrime+33], epComp)

	// VK at offset 33.
	vkComp := compressedPoint(cf.VKX, cf.VKY)
	copy(out[cfragOffsetVK:cfragOffsetVK+33], vkComp)

	// BK at offset 66 (already compressed in the struct).
	copy(out[cfragOffsetBK:cfragOffsetBK+33], cf.BK[:])

	// ID at offset 99.
	out[cfragOffsetID] = cf.ID

	// ProofE at offset 100, ProofZ at offset 132.
	copy(out[cfragOffsetProofE:cfragOffsetProofE+32], padBigInt(cf.ProofE))
	copy(out[cfragOffsetProofZ:cfragOffsetProofZ+32], padBigInt(cf.ProofZ))

	// Reserved bytes at offset 164..195 are already zero from make().
	// This is asserted implicitly and verified on deserialize.

	return out, nil
}

// DeserializeCFrag decodes a 196-byte wire buffer into a CFrag.
// Performs on-curve and structural validation at ingress, and
// rejects non-zero reserved bytes per ADR-005 §8.3.
//
// A v7.5 CFrag (163 bytes) rejects at length check. A v7.75 CFrag
// with non-zero reserved bytes rejects with ErrReservedBytesNonZero.
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
	for i := 0; i < cfragReservedLen; i++ {
		if data[cfragOffsetReserved+i] != 0 {
			return nil, fmt.Errorf(
				"%w at offset %d",
				ErrReservedBytesNonZero, cfragOffsetReserved+i,
			)
		}
	}

	c := curve()

	// E' at offset 0.
	epX, epY, err := decompressPoint(data[cfragOffsetEPrime : cfragOffsetEPrime+33])
	if err != nil {
		return nil, fmt.Errorf("%w: E': %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(epX, epY) {
		return nil, fmt.Errorf("%w: E' not on curve", ErrInvalidCFragFormat)
	}

	// VK at offset 33.
	vkX, vkY, err := decompressPoint(data[cfragOffsetVK : cfragOffsetVK+33])
	if err != nil {
		return nil, fmt.Errorf("%w: VK: %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(vkX, vkY) {
		return nil, fmt.Errorf("%w: VK not on curve", ErrInvalidCFragFormat)
	}

	// BK at offset 66: validate the encoding but preserve the original
	// bytes — the wire-identical form is what vss.DLEQChallenge
	// re-absorbs at the verifier.
	var bk [KFragBKLen]byte
	copy(bk[:], data[cfragOffsetBK:cfragOffsetBK+33])
	bkX, bkY, err := decompressPoint(bk[:])
	if err != nil {
		return nil, fmt.Errorf("%w: BK: %v", ErrInvalidCFragFormat, err)
	}
	if !c.IsOnCurve(bkX, bkY) {
		return nil, fmt.Errorf("%w: BK not on curve", ErrInvalidCFragFormat)
	}

	// ID at offset 99.
	id := data[cfragOffsetID]
	if id == 0 {
		return nil, fmt.Errorf("%w: index 0 is reserved", ErrInvalidCFragFormat)
	}

	// ProofE, ProofZ at offsets 100, 132.
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
// Lagrange combination
// ─────────────────────────────────────────────────────────────────────

// lagrangeCombinePoints combines CFrags using Lagrange interpolation
// on curve points. The result is sum_i λ_i · E'_i where λ_i are the
// standard Lagrange coefficients at x=0 for the supplied share IDs.
//
// Callers MUST have verified every CFrag before invoking this
// function (PRE_DecryptFrags does this). Unverified inputs produce
// a mathematically-correct combination of attacker-chosen values,
// which is the substitution vulnerability v7.75 closes.
func lagrangeCombinePoints(cfrags []*CFrag, n *big.Int, c elliptic.Curve) (*big.Int, *big.Int, error) {
	// Collect share IDs and validate.
	xs := make([]*big.Int, len(cfrags))
	seen := make(map[byte]bool, len(cfrags))
	for i, cf := range cfrags {
		if cf == nil {
			return nil, nil, fmt.Errorf("%w: nil cfrag at slot %d", ErrInvalidCFragFormat, i)
		}
		if seen[cf.ID] {
			return nil, nil, fmt.Errorf(
				"%w: duplicate share ID %d",
				ErrInvalidCFragFormat, cf.ID,
			)
		}
		seen[cf.ID] = true
		xs[i] = big.NewInt(int64(cf.ID))
	}

	// Compute Lagrange coefficients at x=0.
	lambdas := make([]*big.Int, len(cfrags))
	for i := range cfrags {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range cfrags {
			if i == j {
				continue
			}
			// num *= -xs[j] mod n
			neg := new(big.Int).Neg(xs[j])
			neg.Mod(neg, n)
			num.Mul(num, neg)
			num.Mod(num, n)
			// den *= (xs[i] - xs[j]) mod n
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

	// Combined = sum_i λ_i · E'_i
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
//
// This matches the encoding used by core/vss/transcript.go so CFrag
// BK bytes pass through the transcript without re-encoding.
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
// y² = x³ + 7 mod p (secp256k1 has a = 0, b = 7).
//
// Returns an error for:
//   - Wrong length
//   - Invalid prefix byte
//   - x not on curve (no y exists such that y² = x³ + 7)
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

	// y² = x³ + 7 mod p
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(x3, big.NewInt(7))
	rhs.Mod(rhs, p)

	// Compute y via y = rhs^((p+1)/4) mod p (works because p ≡ 3 mod 4).
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, p)

	// Verify y² == rhs (otherwise x was not a valid x-coordinate).
	yCheck := new(big.Int).Mul(y, y)
	yCheck.Mod(yCheck, p)
	if yCheck.Cmp(rhs) != 0 {
		return nil, nil, errors.New("x coordinate is not on curve")
	}

	// Match parity with the prefix byte.
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

// hashToPoint maps arbitrary bytes to a point on secp256k1 using try-
// and-increment. Used to derive the secondary generator U =
// hashToPoint(pk_owner) for the capsule's V component. The output
// is a valid curve point unrelated to pk_owner as a key.
//
// Method: SHA-256(input || counter) → candidate x → compute y² = x³ + 7
// → check quadratic residue. secp256k1 has p ≡ 3 (mod 4), so
// sqrt(a) = a^((p+1)/4) mod p.
//
// NOTE: This is NOT the same construction as vss.HGenerator's try-
// and-increment. hashToPoint derives U (capsule-facing); HGenerator
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

// padBigInt pads a big.Int to exactly 32 bytes (secp256k1 scalar width).
// big.Int.Bytes() strips leading zeros; callers of ScalarMult /
// ScalarBaseMult expect fixed-width inputs.
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
