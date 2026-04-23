// Package escrow — vss_v2_test.go covers Phase B:
//
//   - SplitV2 / ReconstructV2 round-trip across (M, N) combinations.
//   - Substitution detection: mutating any load-bearing field of a
//     share after Split must cause ReconstructV2 to fail loudly.
//     Never produce a wrong secret silently.
//   - VerifyShareAgainstCommitments at distribution time.
//   - Cross-split rejection.
//   - Wire-format invariants for V2 shares.
//   - V1 API is byte-identical to pre-Phase-B behaviour.
//   - Golden-vector regression against core/vss/testdata/split_vector.json.
//
// Every substitution test satisfies the mutation-discipline contract:
// disabling the check under test (e.g., removing the Pedersen
// verification call from ReconstructV2) must cause the test to fail.
// Tests that "happen to pass" by accident are not acceptable.
package escrow

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// ─────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────

func v2TestSecret() []byte {
	s := make([]byte, SecretSize)
	for i := range s {
		s[i] = byte(i) + 1
	}
	return s
}

func v2TestNonce() [32]byte {
	var n [32]byte
	for i := range n {
		n[i] = byte(i) ^ 0x5A
	}
	return n
}

const v2TestDealerDID = "did:web:test.example.com:dealer"

// ─────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────

// TestSplitV2_ReconstructV2_Roundtrip exercises the load-bearing
// property: SplitV2 + ReconstructV2 yields the original secret for
// every combination of an M-of-N configuration at several Lagrange
// subsets. Any subset of M of the N shares reconstructs correctly.
func TestSplitV2_ReconstructV2_Roundtrip(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, splitID, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("len(shares) = %d, want 5", len(shares))
	}
	if splitID == [32]byte{} {
		t.Fatal("SplitID is zero")
	}

	subsets := [][]int{
		{0, 1, 2},
		{2, 3, 4},
		{0, 2, 4},
		{1, 3, 4},
	}
	for _, idx := range subsets {
		subset := []Share{shares[idx[0]], shares[idx[1]], shares[idx[2]]}
		got, err := ReconstructV2(subset, commits)
		if err != nil {
			t.Fatalf("Reconstruct subset %v: %v", idx, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("subset %v: reconstruct mismatch\n got %x\nwant %x", idx, got, secret)
		}
	}
}

// TestSplitV2_MinimumThreshold locks M=2, N=2.
func TestSplitV2_MinimumThreshold(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 2, 2, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	got, err := ReconstructV2(shares, commits)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("2-of-2 round-trip mismatch")
	}
}

// TestSplitV2_MaximumN locks N=255, M=2. Only exercises two shares
// on the reconstruction side to keep the test cheap, but Split
// produces all 255.
func TestSplitV2_MaximumN(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 2, 255, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	if len(shares) != 255 {
		t.Fatalf("share count = %d, want 255", len(shares))
	}
	subset := []Share{shares[0], shares[100]}
	got, err := ReconstructV2(subset, commits)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("255-max round-trip mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────
// Substitution rejection — the load-bearing V2 property
// ─────────────────────────────────────────────────────────────────

// TestSplitV2_SubstitutedValue_Rejected is the headline test.
// Mutating a share's Value after Split MUST cause ReconstructV2 to
// fail loudly with ErrCommitmentMismatch — never produce a
// silently-wrong secret. This is the property V2 provides and V1
// does not.
func TestSplitV2_SubstitutedValue_Rejected(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}

	// Flip one bit in share[1].Value. The share's other fields
	// (SplitID, CommitmentHash, BlindingFactor) remain consistent,
	// so structural validation passes; only the Pedersen equation
	// catches this.
	shares[1].Value[0] ^= 0x01

	subset := []Share{shares[0], shares[1], shares[2]}
	got, err := ReconstructV2(subset, commits)
	if err == nil {
		t.Fatalf("substituted Value: Reconstruct returned secret %x without error — Pedersen check is silently passing", got)
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("substituted Value: want ErrCommitmentMismatch, got %v", err)
	}
}

func TestSplitV2_SubstitutedBlindingFactor_Rejected(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	shares[1].BlindingFactor[0] ^= 0x01

	subset := []Share{shares[0], shares[1], shares[2]}
	got, err := ReconstructV2(subset, commits)
	if err == nil {
		t.Fatalf("substituted BlindingFactor: Reconstruct returned %x without error", got)
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("substituted BlindingFactor: want ErrCommitmentMismatch, got %v", err)
	}
}

// TestSplitV2_SubstitutedCommitmentHash_Rejected: flipping the
// share's CommitmentHash causes it to disagree with commitments.Hash().
// The core vss Verify catches this at the hash-match gate, before
// the polynomial equation even runs.
func TestSplitV2_SubstitutedCommitmentHash_Rejected(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	shares[1].CommitmentHash[0] ^= 0x01

	subset := []Share{shares[0], shares[1], shares[2]}
	_, err = ReconstructV2(subset, commits)
	if err == nil {
		t.Fatal("substituted CommitmentHash: Reconstruct returned secret without error")
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("substituted CommitmentHash: want ErrCommitmentMismatch (wrapping vss hash mismatch), got %v", err)
	}
}

// TestSplitV2_SubstitutedSplitID_Rejected: flipping SplitID on one
// share causes VerifyShareSet's SplitID-consistency gate to reject
// the set before any cryptographic work runs.
func TestSplitV2_SubstitutedSplitID_Rejected(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	shares[1].SplitID[0] ^= 0x01

	subset := []Share{shares[0], shares[1], shares[2]}
	_, err = ReconstructV2(subset, commits)
	if err == nil {
		t.Fatal("substituted SplitID: Reconstruct returned secret without error")
	}
	if !errors.Is(err, ErrSplitIDMismatch) {
		t.Fatalf("substituted SplitID: want ErrSplitIDMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Distribution-time verification
// ─────────────────────────────────────────────────────────────────

func TestVerifyShareAgainstCommitments_Valid(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	for _, s := range shares {
		if err := VerifyShareAgainstCommitments(s, commits); err != nil {
			t.Fatalf("share %d: VerifyShareAgainstCommitments returned %v", s.Index, err)
		}
	}
}

func TestVerifyShareAgainstCommitments_NotV2(t *testing.T) {
	// A V1-shaped share must be rejected by the V2 verification
	// primitive. Callers don't mix schemes; this is a defensive
	// belt-and-braces.
	s := validV1Share(1, 3)
	err := VerifyShareAgainstCommitments(s, vss.Commitments{})
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("V1 share: want ErrUnsupportedVersion, got %v", err)
	}
}

func TestVerifyShareAgainstCommitments_ZeroBlinding(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	bad := shares[0]
	bad.BlindingFactor = [32]byte{}
	err = VerifyShareAgainstCommitments(bad, commits)
	if !errors.Is(err, ErrV2FieldEmpty) {
		t.Fatalf("zero blinding: want ErrV2FieldEmpty, got %v", err)
	}
}

func TestVerifyShareAgainstCommitments_ZeroCommitmentHash(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	bad := shares[0]
	bad.CommitmentHash = [32]byte{}
	err = VerifyShareAgainstCommitments(bad, commits)
	if !errors.Is(err, ErrV2FieldEmpty) {
		t.Fatalf("zero commit hash: want ErrV2FieldEmpty, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Cross-split rejection
// ─────────────────────────────────────────────────────────────────

// TestSplitV2_CrossSplit_Rejected: shares from split A presented
// against commitments B (different secret, different dealer) fail.
// This defends against a coalition mixing shares from two active
// splits to produce an attacker-favourable reconstruction.
func TestSplitV2_CrossSplit_Rejected(t *testing.T) {
	secretA := v2TestSecret()
	secretB := make([]byte, SecretSize)
	for i := range secretB {
		secretB[i] = byte(i) + 100
	}

	sharesA, commitsA, _, err := SplitV2(secretA, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("Split A: %v", err)
	}

	var nonceB [32]byte
	for i := range nonceB {
		nonceB[i] = 0xFF - byte(i)
	}
	sharesB, _, _, err := SplitV2(secretB, 3, 5, "did:web:test.example.com:otherDealer", nonceB)
	if err != nil {
		t.Fatalf("Split B: %v", err)
	}

	// Mix: two A shares + one B share, reconstructed against A's
	// commitment set. The B share has wrong SplitID and wrong
	// CommitmentHash for A, so VerifyShareSet rejects before any
	// cryptographic work runs.
	mixed := []Share{sharesA[0], sharesB[1], sharesA[2]}
	_, err = ReconstructV2(mixed, commitsA)
	if err == nil {
		t.Fatal("cross-split reconstruction succeeded — attacker-favourable secret path is open")
	}
	if !errors.Is(err, ErrSplitIDMismatch) {
		t.Fatalf("cross-split: want ErrSplitIDMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Wire format invariants
// ─────────────────────────────────────────────────────────────────

// TestShareV2_WireFormat locks the V2 share's wire-format shape.
// Offsets follow the v7.5 layout (132 bytes total including the
// trailing FieldTag byte). Any drift from this layout is a
// wire-compatibility break.
//
// Note: ADR-005 §8.1 shows a 131-byte layout with a different field
// order than the implementation; the implementation (132 bytes,
// FieldTag at offset 131) is authoritative and the ADR §8.1 text
// is an ADR-level documentation debt flagged for Draft 3 reconcile.
// Phase B does not change the wire format.
func TestShareV2_WireFormat(t *testing.T) {
	secret := v2TestSecret()
	shares, _, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	wire, err := SerializeShare(shares[0])
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(wire) != ShareWireLen {
		t.Fatalf("wire length = %d, want %d", len(wire), ShareWireLen)
	}
	if wire[offsetVersion] != VersionV2 {
		t.Fatalf("wire[Version] = 0x%02x, want 0x%02x (V2)", wire[offsetVersion], VersionV2)
	}
	if wire[offsetFieldTag] != SchemePedersenTag {
		t.Fatalf("wire[FieldTag] = 0x%02x, want 0x%02x (Pedersen)", wire[offsetFieldTag], SchemePedersenTag)
	}
}

func TestShareV2_RoundTripSerialization(t *testing.T) {
	secret := v2TestSecret()
	shares, _, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	for _, orig := range shares {
		wire, err := SerializeShare(orig)
		if err != nil {
			t.Fatalf("Serialize %d: %v", orig.Index, err)
		}
		got, err := DeserializeShare(wire)
		if err != nil {
			t.Fatalf("Deserialize %d: %v", orig.Index, err)
		}
		if got != orig {
			t.Fatalf("round-trip mismatch for share %d", orig.Index)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// V1 compatibility — critical backwards-compat lock
// ─────────────────────────────────────────────────────────────────

// TestSplitV1_Unchanged: the v7.5 Split path must continue to round-
// trip identically. This is the merge-blocker: if Phase B's additions
// somehow affect V1 behaviour, this test fails.
func TestSplitV1_Unchanged(t *testing.T) {
	secret := make([]byte, SecretSize)
	for i := range secret {
		secret[i] = byte(i) + 1
	}
	shares, splitID, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("V1 Split: %v", err)
	}
	if splitID == [32]byte{} {
		t.Fatal("V1 SplitID is zero")
	}
	for _, s := range shares {
		if s.Version != VersionV1 {
			t.Fatalf("V1 Split produced non-V1 share: 0x%02x", s.Version)
		}
		if !zeroArray32(s.BlindingFactor) {
			t.Fatal("V1 Split populated V2-only field BlindingFactor")
		}
		if !zeroArray32(s.CommitmentHash) {
			t.Fatal("V1 Split populated V2-only field CommitmentHash")
		}
	}
	got, err := Reconstruct(shares[:3])
	if err != nil {
		t.Fatalf("V1 Reconstruct: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("V1 round-trip mismatch:\n got %x\nwant %x", got, secret)
	}
}

// TestValidateShareFormat_V1_Accepts: a V1 share with zero
// BlindingFactor and zero CommitmentHash still passes V1 validation.
// This is the critical backwards-compat lock.
func TestValidateShareFormat_V1_Accepts(t *testing.T) {
	s := validV1Share(1, 3)
	if err := ValidateShareFormat(s); err != nil {
		t.Fatalf("V1 share with empty V2 fields rejected: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Golden-vector regression (cross-implementation anchor)
// ─────────────────────────────────────────────────────────────────

// splitVectorFixture mirrors core/vss/testdata/split_vector.json.
type splitVectorFixture struct {
	Input struct {
		SecretHex string `json:"secret_hex"`
		M         int    `json:"m"`
		N         int    `json:"n"`
		DRBGSeed  string `json:"drbg_seed"`
	} `json:"input"`
	Expected struct {
		CommitmentHashHex string `json:"commitment_hash_hex"`
		Shares            []struct {
			Index             int    `json:"index"`
			ValueHex          string `json:"value_hex"`
			BlindingFactorHex string `json:"blinding_factor_hex"`
			CommitmentHashHex string `json:"commitment_hash_hex"`
		} `json:"shares"`
	} `json:"expected"`
}

// drbgReader: SHA-256(seed || BE_uint64(counter)) expansion.
// Mirror of the core/vss test-only DRBG; test-local since escrow's
// test file shouldn't import the vss test internals.
type drbgReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func newDRBG(seed string) *drbgReader { return &drbgReader{seed: []byte(seed)} }

func (r *drbgReader) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], r.counter)
		h := sha256.New()
		h.Write(r.seed)
		h.Write(ctr[:])
		r.buf = append(r.buf, h.Sum(nil)...)
		r.counter++
	}
	n := copy(p, r.buf[:len(p)])
	r.buf = r.buf[n:]
	return n, nil
}

// Assert drbgReader satisfies io.Reader; defensive in case of a
// typo in the method receiver.
var _ io.Reader = (*drbgReader)(nil)

// TestSplitV2_GoldenVector is the cross-implementation contract.
// Feeds SplitV2 with the pinned DRBG seed from Phase A's fixture
// and asserts every share's Value, BlindingFactor, and
// CommitmentHash match byte-for-byte.
//
// A Rust or TypeScript port that produces different bytes fails
// this test. A refactor that changes the coefficient-sampling
// order or the commitment-hash serialization ALSO fails here —
// caught before it ships.
//
// The fixture was generated in Phase A; Phase B's SplitV2 wraps
// the vss primitive such that its CommitmentHash byte layout
// (vss.Commitments.Hash: BE_uint32(M) || C_j_uncompressed...)
// exactly matches the fixture. If this test ever fails, either
// the fixture is stale (regenerate deliberately) or SplitV2
// introduced a layout divergence (fix and retest).
func TestSplitV2_GoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "core", "vss", "testdata", "split_vector.json"))
	if err != nil {
		t.Fatalf("read split_vector.json: %v", err)
	}
	var fx splitVectorFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	secret, err := hex.DecodeString(fx.Input.SecretHex)
	if err != nil {
		t.Fatalf("secret hex: %v", err)
	}

	// Use the same test-only DRBG that Phase A used to pin the
	// fixture. Any dealer DID + nonce are fine — they affect only
	// the SplitID, which is a wrapper concern that the fixture
	// does not pin.
	r := newDRBG(fx.Input.DRBGSeed)
	shares, commits, _, err := splitV2WithReader(secret, fx.Input.M, fx.Input.N, v2TestDealerDID, v2TestNonce(), r)
	if err != nil {
		t.Fatalf("splitV2WithReader: %v", err)
	}
	if len(shares) != fx.Input.N {
		t.Fatalf("share count = %d, want %d", len(shares), fx.Input.N)
	}
	if len(fx.Expected.Shares) != fx.Input.N {
		t.Fatalf("fixture share count = %d, want %d", len(fx.Expected.Shares), fx.Input.N)
	}

	// Commitment hash (what each share's CommitmentHash field carries).
	gotCH := commits.Hash()
	wantCH := fx.Expected.CommitmentHashHex
	if hex.EncodeToString(gotCH[:]) != wantCH {
		t.Fatalf("commitment hash:\n got %x\nwant %s", gotCH, wantCH)
	}

	for i, s := range shares {
		want := fx.Expected.Shares[i]
		if int(s.Index) != want.Index {
			t.Fatalf("share %d: Index = %d, want %d", i, s.Index, want.Index)
		}
		if hex.EncodeToString(s.Value[:]) != want.ValueHex {
			t.Fatalf("share %d: Value = %x, want %s", i, s.Value[:], want.ValueHex)
		}
		if hex.EncodeToString(s.BlindingFactor[:]) != want.BlindingFactorHex {
			t.Fatalf("share %d: BlindingFactor = %x, want %s", i, s.BlindingFactor[:], want.BlindingFactorHex)
		}
		if hex.EncodeToString(s.CommitmentHash[:]) != want.CommitmentHashHex {
			t.Fatalf("share %d: CommitmentHash = %x, want %s", i, s.CommitmentHash[:], want.CommitmentHashHex)
		}
	}

	// End-to-end: round-trip against the same fixture inputs. If
	// SplitV2 and ReconstructV2 are both on-spec, the round-trip
	// recovers the input secret.
	subset := []Share{shares[0], shares[2], shares[4]}
	got, err := ReconstructV2(subset, commits)
	if err != nil {
		t.Fatalf("golden round-trip Reconstruct: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("golden round-trip mismatch:\n got %x\nwant %x", got, secret)
	}
}

// ─────────────────────────────────────────────────────────────────
// Zero-secret edge case
// ─────────────────────────────────────────────────────────────────

// TestSplitV2_ZeroSecret_Rejected: SplitV2 forwards to vss.Split,
// which rejects the zero scalar (application-layer concern per
// ADR-005 §3.2). Phase B must not silently bypass this guard.
func TestSplitV2_ZeroSecret_Rejected(t *testing.T) {
	zero := make([]byte, SecretSize)
	_, _, _, err := SplitV2(zero, 3, 5, v2TestDealerDID, v2TestNonce())
	if err == nil {
		t.Fatal("zero secret: want error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────
// Error message quality
// ─────────────────────────────────────────────────────────────────

// TestReconstructV2_MixedVersions_Clear: presenting one V1 share in
// an otherwise-V2 set must produce a typed error. ErrVersionMismatch
// (existing sentinel) covers this case. The error must identify the
// offending version so operators can attribute.
func TestReconstructV2_MixedVersions_Clear(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	// Substitute shares[1] with a V1 share sharing the same Index.
	v1 := validV1Share(shares[1].Index, 3)
	mixed := []Share{shares[0], v1, shares[2]}
	_, err = ReconstructV2(mixed, commits)
	if err == nil {
		t.Fatal("mixed V1/V2 reconstruction succeeded")
	}
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("mixed V1/V2: want ErrVersionMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// SplitID derivation
// ─────────────────────────────────────────────────────────────────

// TestSplitV2_SplitIDDeterministic: two SplitV2 calls with the same
// (dealerDID, nonce) produce the same SplitID. Distinct nonces
// produce distinct SplitIDs.
func TestSplitV2_SplitIDDeterministic(t *testing.T) {
	secret := v2TestSecret()
	nonce := v2TestNonce()
	_, _, id1, err := SplitV2(secret, 3, 5, v2TestDealerDID, nonce)
	if err != nil {
		t.Fatalf("split 1: %v", err)
	}
	_, _, id2, err := SplitV2(secret, 3, 5, v2TestDealerDID, nonce)
	if err != nil {
		t.Fatalf("split 2: %v", err)
	}
	if id1 != id2 {
		t.Fatal("same (dealer, nonce) produced different SplitIDs")
	}

	var nonce2 [32]byte
	for i := range nonce2 {
		nonce2[i] = 0xAA
	}
	_, _, id3, err := SplitV2(secret, 3, 5, v2TestDealerDID, nonce2)
	if err != nil {
		t.Fatalf("split 3: %v", err)
	}
	if id1 == id3 {
		t.Fatal("different nonces produced same SplitID")
	}
}

// TestComputeEscrowSplitID_Golden locks the exact DST + universal
// length-prefix encoding for the escrow SplitID construction per
// ADR-005 §2 (v7.75 migration). The fixture at
// testdata/split_id_vector.json is the authoritative cross-
// implementation anchor; this test reads it and asserts the
// in-process derivation matches byte-for-byte.
//
// The v7.75 migration is a hard break: every SplitID produced by
// pre-migration raw-concat code differs from the LengthPrefixed
// output. Any implementation still emitting the old bytes fails
// this test, which is the intended behaviour.
func TestComputeEscrowSplitID_Golden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "split_id_vector.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		DST                string `json:"dst"`
		DealerDID          string `json:"dealer_did"`
		NonceHex           string `json:"nonce_hex"`
		ExpectedSplitIDHex string `json:"expected_split_id_hex"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fx.DST != escrowSplitIDDST {
		t.Fatalf("fixture DST %q != package DST %q", fx.DST, escrowSplitIDDST)
	}
	nonceBytes, err := hex.DecodeString(fx.NonceHex)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	if len(nonceBytes) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(nonceBytes))
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)

	got := ComputeEscrowSplitID(fx.DealerDID, nonce)
	if hex.EncodeToString(got[:]) != fx.ExpectedSplitIDHex {
		t.Fatalf("escrow SplitID mismatch:\n got  %x\n want %s", got[:], fx.ExpectedSplitIDHex)
	}
}

// ─────────────────────────────────────────────────────────────────
// VerifyShareAgainstCommitmentHash (fast pre-check)
// ─────────────────────────────────────────────────────────────────

func TestVerifyShareAgainstCommitmentHash_MatchAndMismatch(t *testing.T) {
	secret := v2TestSecret()
	shares, commits, _, err := SplitV2(secret, 3, 5, v2TestDealerDID, v2TestNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	if err := VerifyShareAgainstCommitmentHash(shares[0], commits); err != nil {
		t.Fatalf("valid share: %v", err)
	}
	bad := shares[0]
	bad.CommitmentHash[0] ^= 0x01
	if err := VerifyShareAgainstCommitmentHash(bad, commits); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("mismatched hash: want ErrCommitmentMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Input-validation edges
// ─────────────────────────────────────────────────────────────────

func TestSplitV2_RejectsWrongSecretSize(t *testing.T) {
	_, _, _, err := SplitV2(make([]byte, 16), 3, 5, v2TestDealerDID, v2TestNonce())
	if err == nil {
		t.Fatal("16-byte secret: want error, got nil")
	}
}

func TestSplitV2_RejectsEmptyDealerDID(t *testing.T) {
	_, _, _, err := SplitV2(v2TestSecret(), 3, 5, "", v2TestNonce())
	if err == nil {
		t.Fatal("empty dealerDID: want error, got nil")
	}
}

func TestSplitV2_RejectsSubthresholdM(t *testing.T) {
	_, _, _, err := SplitV2(v2TestSecret(), 1, 5, v2TestDealerDID, v2TestNonce())
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("M=1: want ErrInvalidThreshold, got %v", err)
	}
}

func TestSplitV2_RejectsMAboveN(t *testing.T) {
	_, _, _, err := SplitV2(v2TestSecret(), 5, 3, v2TestDealerDID, v2TestNonce())
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("M>N: want ErrInvalidThreshold, got %v", err)
	}
}

func TestSplitV2_RejectsNAbove255(t *testing.T) {
	_, _, _, err := SplitV2(v2TestSecret(), 3, 256, v2TestDealerDID, v2TestNonce())
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("N=256: want ErrInvalidThreshold, got %v", err)
	}
}
