// Package artifact — pre.go implements Umbral Threshold Proxy Re-Encryption
// on secp256k1. Same curve as entry signatures, ECIES, and witness cosignatures.
//
// Pure crypto functions. Stateless. No DID resolution needed.
// Callers resolve DIDs to public keys before calling these.
//
// Relationship to AES-256-GCM (api.go):
//   AES-256-GCM = storage encryption (artifact at rest, permanent)
//   Umbral PRE  = access control (who can decrypt, additive)
//   Composable: Umbral wraps/transforms the AES key
//   Schemas declare which access model: aes_gcm | umbral_pre
//   Old schemas unchanged. New schemas opt into PRE.
//
// Architecture:
//   PRE_Encrypt wraps a symmetric key using elliptic curve DH.
//   The symmetric key encrypts the actual artifact data.
//   Re-encryption transforms the capsule so a different recipient
//   can recover the same symmetric key without the owner's help.
//
// Honest acknowledgment:
//   ~200 bytes per CFrag (DLEQ proof overhead)
//   ~50ms per CFrag verification
//   KFrag generation touches sk_owner (exchange HSM or enclave)
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

	"github.com/dustinxie/ecc"
)

func curve() elliptic.Curve { return ecc.P256k1() }
func curveN() *big.Int      { return curve().Params().N }

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// Capsule is the curve point pair produced during encryption.
// Contains the ephemeral point E and verification point V.
// Capsule contains only curve points — no private material.
// Stored in Domain Payload permanently. Any party with capsule +
// M cfrags + sk_recipient can decrypt.
//
// SECURITY: V = r * U where U = hashToPoint(pk_owner). V is NOT the DH
// shared secret (r * pk_owner). The DH shared secret is computed internally
// during encryption and NEVER stored in the capsule. V serves only as a
// binding proof that E was generated for a specific pk_owner.
type Capsule struct {
	EX, EY   *big.Int // E = r * G (ephemeral public key)
	VX, VY   *big.Int // V = r * U where U = hashToPoint(pk_owner)
	CheckVal [32]byte // H(E || V) for capsule integrity
}

// KFrag is a re-encryption key fragment. M-of-N threshold.
// Each KFrag is independently verifiable.
// sk_owner touched once per grant (not per access).
type KFrag struct {
	ID       byte     // Share index (1-based)
	RKShare  *big.Int // Shamir share of the re-encryption key (scalar)
	VKX, VKY *big.Int // Verification key = RKShare * G
}

// CFrag is a ciphertext fragment produced by re-encrypting with one KFrag.
// Includes a DLEQ non-interactive ZK proof: proves correct re-encryption
// without revealing the kfrag scalar. Node never sees plaintext.
type CFrag struct {
	EPrimeX, EPrimeY *big.Int // E' = kfrag.RKShare * capsule.E
	ID               byte     // KFrag ID this came from
	ProofC           *big.Int // DLEQ challenge
	ProofZ           *big.Int // DLEQ response
}

// ─────────────────────────────────────────────────────────────────────
// PRE_Encrypt — Encapsulate a symmetric key for pk_owner
// ─────────────────────────────────────────────────────────────────────

// PRE_Encrypt encrypts plaintext for pk_owner using an ephemeral DH key exchange.
// Returns a Capsule (public, storable in Domain Payload) and ciphertext.
// pk is the master public key (secp256k1 uncompressed 65 bytes).
//
// SECURITY: The DH shared secret (r * pk_owner) is used to derive the DEM key
// but is NEVER stored in the capsule. The capsule's V field is r * U where
// U = hashToPoint(pk_owner) — a secondary generator that binds the capsule
// to pk_owner without leaking the shared secret.
func PRE_Encrypt(pk []byte, plaintext []byte) (*Capsule, []byte, error) {
	c := curve()
	pkX, pkY := elliptic.Unmarshal(c, pk)
	if pkX == nil {
		return nil, nil, errors.New("pre: invalid public key")
	}

	// r ← random scalar
	r, err := rand.Int(rand.Reader, curveN())
	if err != nil {
		return nil, nil, fmt.Errorf("pre: generating random: %w", err)
	}

	// E = r * G
	eX, eY := c.ScalarBaseMult(padBigInt(r))

	// Shared secret = r * pk_owner (used for DEM key, NEVER stored)
	sharedX, sharedY := c.ScalarMult(pkX, pkY, padBigInt(r))

	// DEM key = KDF(shared secret)
	demKey := kdf(sharedX, sharedY)

	// V = r * U where U = hashToPoint(pk_owner)
	// V binds the capsule to pk_owner without leaking the shared secret.
	uX, uY := hashToPoint(pk)
	vX, vY := c.ScalarMult(uX, uY, padBigInt(r))

	// Encrypt plaintext with AES-256-GCM
	ct, err := aesGCMEncrypt(demKey[:], plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("pre: encrypting: %w", err)
	}

	// Check value for capsule integrity
	check := hashPoints(eX, eY, vX, vY)

	capsule := &Capsule{
		EX: eX, EY: eY,
		VX: vX, VY: vY,
		CheckVal: check,
	}
	return capsule, ct, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_Decrypt — Direct decryption by master key holder
// ─────────────────────────────────────────────────────────────────────

// PRE_Decrypt decrypts ciphertext using sk_owner and the capsule.
// Direct decryption — no re-encryption involved.
// sk is the private key scalar as 32 bytes (big-endian).
func PRE_Decrypt(sk []byte, capsule *Capsule, ciphertext []byte) ([]byte, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	c := curve()

	// Recompute V' = sk_owner * E
	vX, vY := c.ScalarMult(capsule.EX, capsule.EY, sk)

	// DEM key = KDF(V')
	demKey := kdf(vX, vY)

	// Decrypt
	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// PRE_GenerateKFrags — Threshold re-encryption key fragments
// ─────────────────────────────────────────────────────────────────────

// PRE_GenerateKFrags generates N threshold re-encryption key fragments.
// M fragments are required for re-encryption. sk_owner is touched once
// per grant (not per access).
//
// sk_owner: 32-byte private key scalar.
// pk_recipient: 65-byte uncompressed secp256k1 public key.
func PRE_GenerateKFrags(skOwner, pkRecipient []byte, M, N int) ([]KFrag, error) {
	if M < 1 || N < 1 || M > N || N > 255 {
		return nil, fmt.Errorf("pre: invalid M=%d, N=%d", M, N)
	}
	c := curve()
	n := curveN()

	// Parse recipient public key
	rxX, rxY := elliptic.Unmarshal(c, pkRecipient)
	if rxX == nil {
		return nil, errors.New("pre: invalid recipient public key")
	}

	// sk_owner as big.Int
	skA := new(big.Int).SetBytes(skOwner)
	if skA.Sign() == 0 || skA.Cmp(n) >= 0 {
		return nil, errors.New("pre: invalid owner private key")
	}

	// Compute ECDH shared secret: dh_point = sk_owner * pk_recipient
	dhX, dhY := c.ScalarMult(rxX, rxY, padBigInt(skA))

	// d = H_scalar(dh_point) — deterministic blinding scalar
	d := hashToScalar(dhX, dhY, n)
	if d.Sign() == 0 {
		return nil, errors.New("pre: degenerate blinding scalar")
	}

	// rk = sk_owner * inv(d) mod n
	dInv := new(big.Int).ModInverse(d, n)
	if dInv == nil {
		return nil, errors.New("pre: d has no inverse")
	}
	rk := new(big.Int).Mul(skA, dInv)
	rk.Mod(rk, n)

	// Shamir-split rk into N shares with threshold M in Z_n
	kfrags, err := shamirSplitScalar(rk, M, N, n)
	if err != nil {
		return nil, fmt.Errorf("pre: splitting re-encryption key: %w", err)
	}

	return kfrags, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_ReEncrypt — Single-node re-encryption producing one CFrag
// ─────────────────────────────────────────────────────────────────────

// PRE_ReEncrypt re-encrypts a capsule using a single KFrag.
// Produces a CFrag with a DLEQ proof proving correct re-encryption.
// Node never sees plaintext. Node holds one fragment — insufficient alone.
func PRE_ReEncrypt(kfrag KFrag, capsule *Capsule) (*CFrag, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	c := curve()
	n := curveN()

	// E' = kfrag.RKShare * capsule.E
	epX, epY := c.ScalarMult(capsule.EX, capsule.EY, padBigInt(kfrag.RKShare))

	// DLEQ proof: prove log_G(VK) == log_E(E')
	// where VK = kfrag.RKShare * G, E' = kfrag.RKShare * E
	proofC, proofZ, err := dleqProve(
		kfrag.RKShare,
		c.Params().Gx, c.Params().Gy, // G
		kfrag.VKX, kfrag.VKY, // H = s*G
		capsule.EX, capsule.EY, // P = E
		epX, epY, // Q = s*P
		n,
	)
	if err != nil {
		return nil, fmt.Errorf("pre: generating DLEQ proof: %w", err)
	}

	return &CFrag{
		EPrimeX: epX, EPrimeY: epY,
		ID:     kfrag.ID,
		ProofC: proofC,
		ProofZ: proofZ,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE_VerifyCFrag — Public-key verification of a ciphertext fragment
// ─────────────────────────────────────────────────────────────────────

// PRE_VerifyCFrag verifies a CFrag's DLEQ proof. No private key needed.
// Monitoring services call this — never decrypt, only verify.
// Verifies that E' was correctly computed from the KFrag and capsule.E.
//
// pk_owner: 65-byte uncompressed public key of the capsule creator.
// pk_recipient: 65-byte uncompressed public key of the intended recipient.
// kfrags must be available to extract VK for the cfrag's ID.
func PRE_VerifyCFrag(cfrag *CFrag, capsule *Capsule, vkX, vkY *big.Int) error {
	if cfrag == nil || capsule == nil {
		return errors.New("pre: nil cfrag or capsule")
	}
	c := curve()
	n := curveN()

	// Verify DLEQ: log_G(VK) == log_E(E')
	return dleqVerify(
		c.Params().Gx, c.Params().Gy, // G
		vkX, vkY, // H = VK
		capsule.EX, capsule.EY, // P = E
		cfrag.EPrimeX, cfrag.EPrimeY, // Q = E'
		cfrag.ProofC, cfrag.ProofZ,
		n,
	)
}

// ─────────────────────────────────────────────────────────────────────
// PRE_DecryptFrags — Combine M cfrags and decrypt
// ─────────────────────────────────────────────────────────────────────

// PRE_DecryptFrags combines M cfrags and decrypts using the recipient's
// private key. Verify: len(cfrags) >= M (from original GenerateKFrags).
//
// sk_recipient: 32-byte private key scalar.
// pk_owner: 65-byte uncompressed public key of the capsule creator.
func PRE_DecryptFrags(skRecipient []byte, cfrags []*CFrag, capsule *Capsule, ciphertext []byte, pkOwner []byte) ([]byte, error) {
	if capsule == nil {
		return nil, errors.New("pre: nil capsule")
	}
	if len(cfrags) == 0 {
		return nil, errors.New("pre: no cfrags provided")
	}
	c := curve()
	n := curveN()

	// Parse owner public key for ECDH
	ownerX, ownerY := elliptic.Unmarshal(c, pkOwner)
	if ownerX == nil {
		return nil, errors.New("pre: invalid owner public key")
	}

	// Combine CFrags via Lagrange interpolation in the scalar field.
	// E'_combined = sum(λ_i * E'_i)
	// where λ_i are Lagrange coefficients for the share IDs at x=0.
	combinedX, combinedY, err := lagrangeCombinePoints(cfrags, n, c)
	if err != nil {
		return nil, fmt.Errorf("pre: combining cfrags: %w", err)
	}

	// Compute d = H_scalar(ECDH(sk_recipient, pk_owner))
	// This is the same shared secret the owner used during GenerateKFrags.
	dhX, dhY := c.ScalarMult(ownerX, ownerY, skRecipient)
	d := hashToScalar(dhX, dhY, n)

	// key_point = d * E'_combined
	// = d * (rk * E) = d * (sk_owner/d * r * G) = sk_owner * r * G = V
	keyX, keyY := c.ScalarMult(combinedX, combinedY, padBigInt(d))

	// DEM key = KDF(key_point)
	demKey := kdf(keyX, keyY)

	// Decrypt
	return aesGCMDecrypt(demKey[:], ciphertext)
}

// ─────────────────────────────────────────────────────────────────────
// Shamir secret sharing in Z_n (scalar field)
// ─────────────────────────────────────────────────────────────────────

func shamirSplitScalar(secret *big.Int, M, N int, n *big.Int) ([]KFrag, error) {
	c := curve()

	// Generate random polynomial of degree M-1 with secret as constant term.
	coeffs := make([]*big.Int, M)
	coeffs[0] = new(big.Int).Set(secret)
	for i := 1; i < M; i++ {
		coeff, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		coeffs[i] = coeff
	}

	kfrags := make([]KFrag, N)
	for i := 0; i < N; i++ {
		x := big.NewInt(int64(i + 1))
		// Evaluate polynomial at x
		y := evalPolynomialMod(coeffs, x, n)

		// Verification key = y * G
		vkX, vkY := c.ScalarBaseMult(padBigInt(y))

		kfrags[i] = KFrag{
			ID:      byte(i + 1),
			RKShare: y,
			VKX:     vkX,
			VKY:     vkY,
		}
	}
	return kfrags, nil
}

func evalPolynomialMod(coeffs []*big.Int, x, n *big.Int) *big.Int {
	// Horner's method: result = c[M-1]*x^(M-1) + ... + c[1]*x + c[0]
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, n)
	}
	return result
}

// lagrangeCombinePoints combines CFrags using Lagrange interpolation on curve points.
func lagrangeCombinePoints(cfrags []*CFrag, n *big.Int, c elliptic.Curve) (*big.Int, *big.Int, error) {
	// Collect share IDs
	xs := make([]*big.Int, len(cfrags))
	for i, cf := range cfrags {
		xs[i] = big.NewInt(int64(cf.ID))
	}

	// Compute Lagrange coefficients at x=0
	lambdas := make([]*big.Int, len(cfrags))
	for i := range cfrags {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range cfrags {
			if i == j {
				continue
			}
			// num *= (0 - xs[j]) = -xs[j]
			neg := new(big.Int).Neg(xs[j])
			neg.Mod(neg, n)
			num.Mul(num, neg)
			num.Mod(num, n)
			// den *= (xs[i] - xs[j])
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

	// Combined point = sum(λ_i * E'_i)
	var sumX, sumY *big.Int
	for i, cf := range cfrags {
		// λ_i * E'_i
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
// DLEQ (Discrete Log Equality) proofs
// ─────────────────────────────────────────────────────────────────────

// dleqProve generates a DLEQ proof: log_G(H) == log_P(Q)
// Given scalar s, proves H = s*G and Q = s*P without revealing s.
func dleqProve(s *big.Int, gx, gy, hx, hy, px, py, qx, qy *big.Int, n *big.Int) (*big.Int, *big.Int, error) {
	c := curve()

	// t ← random scalar
	t, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, nil, err
	}

	// T1 = t * G, T2 = t * P
	t1x, t1y := c.ScalarBaseMult(padBigInt(t))
	t2x, t2y := c.ScalarMult(px, py, padBigInt(t))

	// c = H(G, H, P, Q, T1, T2)
	challenge := dleqChallenge(gx, gy, hx, hy, px, py, qx, qy, t1x, t1y, t2x, t2y, n)

	// z = t + c * s mod n
	z := new(big.Int).Mul(challenge, s)
	z.Add(z, t)
	z.Mod(z, n)

	return challenge, z, nil
}

// dleqVerify verifies a DLEQ proof.
func dleqVerify(gx, gy, hx, hy, px, py, qx, qy, proofC, proofZ *big.Int, n *big.Int) error {
	c := curve()

	// T1' = z*G - c*H
	zGx, zGy := c.ScalarBaseMult(padBigInt(proofZ))
	cHx, cHy := c.ScalarMult(hx, hy, padBigInt(proofC))
	// Negate cH: (x, -y)
	cHyNeg := new(big.Int).Neg(cHy)
	cHyNeg.Mod(cHyNeg, c.Params().P)
	t1x, t1y := c.Add(zGx, zGy, cHx, cHyNeg)

	// T2' = z*P - c*Q
	zPx, zPy := c.ScalarMult(px, py, padBigInt(proofZ))
	cQx, cQy := c.ScalarMult(qx, qy, padBigInt(proofC))
	cQyNeg := new(big.Int).Neg(cQy)
	cQyNeg.Mod(cQyNeg, c.Params().P)
	t2x, t2y := c.Add(zPx, zPy, cQx, cQyNeg)

	// c' = H(G, H, P, Q, T1', T2')
	challenge := dleqChallenge(gx, gy, hx, hy, px, py, qx, qy, t1x, t1y, t2x, t2y, n)

	if proofC.Cmp(challenge) != 0 {
		return errors.New("pre: DLEQ verification failed")
	}
	return nil
}

// dleqChallenge computes the Fiat-Shamir challenge hash.
func dleqChallenge(gx, gy, hx, hy, px, py, qx, qy, t1x, t1y, t2x, t2y *big.Int, n *big.Int) *big.Int {
	h := sha256.New()
	for _, v := range []*big.Int{gx, gy, hx, hy, px, py, qx, qy, t1x, t1y, t2x, t2y} {
		b := v.Bytes()
		// Fixed-width 32-byte encoding for determinism
		padded := make([]byte, 32)
		if len(b) <= 32 {
			copy(padded[32-len(b):], b)
		} else {
			copy(padded, b[:32])
		}
		h.Write(padded)
	}
	digest := h.Sum(nil)
	result := new(big.Int).SetBytes(digest)
	result.Mod(result, n)
	return result
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// hashToPoint maps arbitrary bytes to a point on secp256k1 using try-and-increment.
// Used to derive the secondary generator U = hashToPoint(pk_owner) for the capsule's
// V component. The output is a valid curve point unrelated to pk_owner as a key.
//
// Method: SHA-256(input || counter) → candidate x → compute y² = x³ + 7 → check QR.
// secp256k1 has p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p.
func hashToPoint(input []byte) (*big.Int, *big.Int) {
	c := curve()
	p := c.Params().P

	// Constants for secp256k1: y² = x³ + 7
	seven := big.NewInt(7)
	// (p + 1) / 4 for modular square root
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4

	for counter := uint32(0); ; counter++ {
		// Hash input with counter
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

		// Interpret as x coordinate
		x := new(big.Int).SetBytes(digest)
		x.Mod(x, p)

		// Compute y² = x³ + 7 mod p
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		x3.Mod(x3, p)
		ySquared := new(big.Int).Add(x3, seven)
		ySquared.Mod(ySquared, p)

		// Check if y² is a quadratic residue (Euler criterion)
		// For p ≡ 3 mod 4: y = ySquared^((p+1)/4) mod p, then verify y² == ySquared
		y := new(big.Int).Exp(ySquared, exp, p)
		yCheck := new(big.Int).Mul(y, y)
		yCheck.Mod(yCheck, p)

		if yCheck.Cmp(ySquared) == 0 {
			// Valid point. Use even y (canonical).
			if y.Bit(0) == 1 {
				y.Sub(p, y)
			}
			// Verify on curve
			if c.IsOnCurve(x, y) {
				return x, y
			}
		}
		// Not a valid point, try next counter
		if counter > 1000 {
			// Should never happen — roughly half of x values yield valid points
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
	// Ensure non-zero
	if result.Sign() == 0 {
		result.SetInt64(1)
	}
	return result
}

// padBigInt pads a big.Int to exactly 32 bytes (secp256k1 scalar width).
func padBigInt(b *big.Int) []byte {
	buf := b.Bytes()
	if len(buf) >= 32 {
		return buf[len(buf)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	return padded
}

// aesGCMEncrypt encrypts with AES-256-GCM. Nonce prepended to ciphertext.
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

// aesGCMDecrypt decrypts AES-256-GCM with nonce prepended.
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
