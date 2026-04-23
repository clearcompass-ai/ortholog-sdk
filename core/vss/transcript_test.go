// Package vss — transcript_test.go locks the DLEQ + Pedersen
// Fiat-Shamir transcript byte layout (ADR-005 §5.2) against a
// golden vector, plus covers domain-separation and error paths.
package vss

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─────────────────────────────────────────────────────────────────
// DST is frozen
// ─────────────────────────────────────────────────────────────────

// TestTranscript_DSTFrozen pins the 32-byte transcript prefix.
// Any change invalidates every CFrag DLEQ proof ever produced.
// A reviewer modifying the printable portion by one character
// sees this test fail immediately.
func TestTranscript_DSTFrozen(t *testing.T) {
	want := "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1"
	got := string(TranscriptDST[:len(want)])
	if got != want {
		t.Fatalf("TranscriptDST printable prefix = %q, want %q", got, want)
	}
	if len(TranscriptDST) != 32 {
		t.Fatalf("TranscriptDST length = %d, want 32", len(TranscriptDST))
	}
}

// ─────────────────────────────────────────────────────────────────
// Byte length and structure
// ─────────────────────────────────────────────────────────────────

// TestTranscript_ByteLengthForM3 confirms the transcript is exactly
// 341 bytes when M=3:
//
//	32 (DST) + 4 (len prefix) + 33·3 (commitments) + 33·4 (BK,VK,E,E')
//	+ 8 (index BE uint64) + 33·2 (R, R') = 341 bytes.
//
// Any divergence means the layout spec has drifted.
func TestTranscript_ByteLengthForM3(t *testing.T) {
	commits, freePts := buildSyntheticInputs(t, 3)
	bytes, err := TranscriptBytes(
		commits,
		freePts.bkX, freePts.bkY,
		freePts.vkX, freePts.vkY,
		freePts.eX, freePts.eY,
		freePts.ePX, freePts.ePY,
		2,
		freePts.rX, freePts.rY,
		freePts.rPX, freePts.rPY,
	)
	if err != nil {
		t.Fatalf("TranscriptBytes: %v", err)
	}
	if len(bytes) != 341 {
		t.Fatalf("transcript length = %d, want 341 (M=3)", len(bytes))
	}
}

// TestTranscript_ByteLengthForM5 confirms the linear growth:
// each additional commitment adds 33 bytes.
func TestTranscript_ByteLengthForM5(t *testing.T) {
	commits, freePts := buildSyntheticInputs(t, 5)
	bytes, err := TranscriptBytes(
		commits,
		freePts.bkX, freePts.bkY,
		freePts.vkX, freePts.vkY,
		freePts.eX, freePts.eY,
		freePts.ePX, freePts.ePY,
		2,
		freePts.rX, freePts.rY,
		freePts.rPX, freePts.rPY,
	)
	if err != nil {
		t.Fatalf("TranscriptBytes: %v", err)
	}
	if len(bytes) != 341+66 {
		t.Fatalf("transcript length = %d, want %d (M=5)", len(bytes), 341+66)
	}
}

// TestTranscript_LengthPrefixDistinguishesM disambiguates commitment
// vectors of different size. Without the BE_uint32(M) prefix, an
// M=2 vector could collide with the first 66 bytes of an M=3
// vector's commitment block. The prefix prevents that.
func TestTranscript_LengthPrefixDistinguishesM(t *testing.T) {
	commits3, free := buildSyntheticInputs(t, 3)
	commits2 := Commitments{Points: commits3.Points[:2]}
	h3, err := DLEQChallenge(commits3, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	if err != nil {
		t.Fatalf("M=3: %v", err)
	}
	h2, err := DLEQChallenge(commits2, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	if err != nil {
		t.Fatalf("M=2: %v", err)
	}
	if h3 == h2 {
		t.Fatal("M=2 and M=3 produced identical challenges — length prefix broken")
	}
}

// ─────────────────────────────────────────────────────────────────
// Challenge = SHA-256(transcript)
// ─────────────────────────────────────────────────────────────────

// TestTranscript_ChallengeIsSha256OfBytes confirms DLEQChallenge
// and TranscriptBytes agree: the challenge is exactly the SHA-256
// of the transcript byte sequence, no extra wrapping.
func TestTranscript_ChallengeIsSha256OfBytes(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	tbytes, err := TranscriptBytes(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)
	if err != nil {
		t.Fatalf("TranscriptBytes: %v", err)
	}
	expected := sha256.Sum256(tbytes)
	got, err := DLEQChallenge(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)
	if err != nil {
		t.Fatalf("DLEQChallenge: %v", err)
	}
	if got != expected {
		t.Fatalf("mismatch:\n got %x\nwant %x", got, expected)
	}
}

// ─────────────────────────────────────────────────────────────────
// Domain separation / absorption
// ─────────────────────────────────────────────────────────────────

// TestTranscript_BKAbsorbed verifies the whole point of §5.2:
// mutating BK_i must change the challenge. Without this property
// an adaptive adversary could choose BK_i after observing the
// challenge, breaking soundness.
func TestTranscript_BKAbsorbed(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	h1, _ := DLEQChallenge(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)

	// Flip BK to a different point on H (2·H instead of original).
	curve := secp256k1.S256()
	hX, hY, _ := HGenerator()
	bk2X, bk2Y := curve.ScalarMult(hX, hY, padScalar(big.NewInt(2)))
	h2, _ := DLEQChallenge(commits, bk2X, bk2Y, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)
	if h1 == h2 {
		t.Fatal("mutating BK did not change challenge — absorption broken")
	}
}

// TestTranscript_CommitmentSetAbsorbed: mutating any commitment
// point must change the challenge. Locks the Pedersen-binding
// property of the transcript.
func TestTranscript_CommitmentSetAbsorbed(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	h1, _ := DLEQChallenge(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)

	// Swap C_0 and C_1. Order-sensitivity is part of the spec.
	permuted := Commitments{Points: [][]byte{
		commits.Points[1], commits.Points[0], commits.Points[2],
	}}
	h2, _ := DLEQChallenge(permuted, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)
	if h1 == h2 {
		t.Fatal("permuting commitments did not change challenge — order absorption broken")
	}
}

// TestTranscript_IndexAbsorbed: index is in the transcript; two
// CFrags with the same proxy, different indices, produce different
// challenges.
func TestTranscript_IndexAbsorbed(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	h1, _ := DLEQChallenge(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	h2, _ := DLEQChallenge(commits, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 2, free.rX, free.rY, free.rPX, free.rPY)
	if h1 == h2 {
		t.Fatal("changing index did not change challenge — index absorption broken")
	}
}

// ─────────────────────────────────────────────────────────────────
// Error paths
// ─────────────────────────────────────────────────────────────────

func TestTranscript_RejectsEmptyCommitments(t *testing.T) {
	_, free := buildSyntheticInputs(t, 3)
	_, err := DLEQChallenge(Commitments{}, free.bkX, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	if !errors.Is(err, ErrTranscriptEmptyCommitments) {
		t.Fatalf("want ErrTranscriptEmptyCommitments, got %v", err)
	}
}

func TestTranscript_RejectsNilPoint(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	_, err := DLEQChallenge(commits, nil, free.bkY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	if !errors.Is(err, ErrTranscriptNilPoint) {
		t.Fatalf("want ErrTranscriptNilPoint, got %v", err)
	}
}

func TestTranscript_RejectsOffCurvePoint(t *testing.T) {
	commits, free := buildSyntheticInputs(t, 3)
	// (1, 1) is off-curve on secp256k1.
	badX := big.NewInt(1)
	badY := big.NewInt(1)
	_, err := DLEQChallenge(commits, badX, badY, free.vkX, free.vkY,
		free.eX, free.eY, free.ePX, free.ePY, 1, free.rX, free.rY, free.rPX, free.rPY)
	if !errors.Is(err, ErrTranscriptInvalidPoint) {
		t.Fatalf("want ErrTranscriptInvalidPoint, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Golden fixture: testdata/transcript_vector.json
// ─────────────────────────────────────────────────────────────────

type transcriptFixture struct {
	Input struct {
		ThresholdM                 int      `json:"threshold_m"`
		CommitmentSetCompressedHex []string `json:"commitment_set_compressed_hex"`
		BKHex                      string   `json:"bk_compressed_hex"`
		VKHex                      string   `json:"vk_compressed_hex"`
		EHex                       string   `json:"e_compressed_hex"`
		EPrimeHex                  string   `json:"e_prime_compressed_hex"`
		Index                      uint64   `json:"index"`
		RHex                       string   `json:"r_compressed_hex"`
		RPrimeHex                  string   `json:"r_prime_compressed_hex"`
	} `json:"input"`
	Expected struct {
		TranscriptLength int    `json:"transcript_length"`
		TranscriptHex    string `json:"transcript_hex"`
		ChallengeHex     string `json:"challenge_hex"`
	} `json:"expected"`
}

func loadTranscriptFixture(t *testing.T) transcriptFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "transcript_vector.json"))
	if err != nil {
		t.Fatalf("read transcript_vector.json: %v", err)
	}
	var fx transcriptFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return fx
}

// TestFixture_TranscriptGolden is the cross-implementation interop
// anchor. Any port of core/vss to another language MUST reproduce
// both the transcript bytes and the challenge digest below for
// the pinned inputs.
func TestFixture_TranscriptGolden(t *testing.T) {
	fx := loadTranscriptFixture(t)

	decodePt := func(hexStr string) (*big.Int, *big.Int) {
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("bad hex: %v", err)
		}
		curve := secp256k1.S256()
		x, y, err := unmarshalOnCurve(curve, raw)
		if err != nil {
			t.Fatalf("point decode: %v", err)
		}
		return x, y
	}

	commits := Commitments{Points: make([][]byte, len(fx.Input.CommitmentSetCompressedHex))}
	for i, h := range fx.Input.CommitmentSetCompressedHex {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("commit %d hex: %v", i, err)
		}
		// Commitments type stores uncompressed by convention; our
		// unmarshalOnCurve accepts both, and the transcript code
		// re-compresses internally. Feed the compressed bytes as-is.
		commits.Points[i] = raw
	}

	bkX, bkY := decodePt(fx.Input.BKHex)
	vkX, vkY := decodePt(fx.Input.VKHex)
	eX, eY := decodePt(fx.Input.EHex)
	ePX, ePY := decodePt(fx.Input.EPrimeHex)
	rX, rY := decodePt(fx.Input.RHex)
	rPX, rPY := decodePt(fx.Input.RPrimeHex)

	gotBytes, err := TranscriptBytes(commits, bkX, bkY, vkX, vkY,
		eX, eY, ePX, ePY, fx.Input.Index, rX, rY, rPX, rPY)
	if err != nil {
		t.Fatalf("TranscriptBytes: %v", err)
	}
	if len(gotBytes) != fx.Expected.TranscriptLength {
		t.Fatalf("length = %d, want %d", len(gotBytes), fx.Expected.TranscriptLength)
	}
	wantBytes, err := hex.DecodeString(fx.Expected.TranscriptHex)
	if err != nil {
		t.Fatalf("fixture transcript_hex: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("transcript bytes mismatch:\n got %x\nwant %x", gotBytes, wantBytes)
	}

	gotChallenge, err := DLEQChallenge(commits, bkX, bkY, vkX, vkY,
		eX, eY, ePX, ePY, fx.Input.Index, rX, rY, rPX, rPY)
	if err != nil {
		t.Fatalf("DLEQChallenge: %v", err)
	}
	wantChallenge, err := hex.DecodeString(fx.Expected.ChallengeHex)
	if err != nil {
		t.Fatalf("fixture challenge_hex: %v", err)
	}
	if !bytes.Equal(gotChallenge[:], wantChallenge) {
		t.Fatalf("challenge mismatch:\n got %x\nwant %x", gotChallenge[:], wantChallenge)
	}
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

type syntheticFreePoints struct {
	bkX, bkY *big.Int
	vkX, vkY *big.Int
	eX, eY   *big.Int
	ePX, ePY *big.Int
	rX, rY   *big.Int
	rPX, rPY *big.Int
}

// buildSyntheticInputs produces deterministic test inputs: each C_j
// is (j+1)·G; BK = 7·H; VK, E, E', R, R' are small scalar multiples
// of G. Use ONLY for testing transcript serialization — these
// values do not represent a real DLEQ statement.
func buildSyntheticInputs(t *testing.T, M int) (Commitments, syntheticFreePoints) {
	t.Helper()
	curve := secp256k1.S256()
	gX, gY := curve.Params().Gx, curve.Params().Gy
	hX, hY, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}

	mul := func(k int64, bx, by *big.Int) (*big.Int, *big.Int) {
		return curve.ScalarMult(bx, by, padScalar(big.NewInt(k)))
	}

	commits := Commitments{Points: make([][]byte, M)}
	for j := 0; j < M; j++ {
		cx, cy := mul(int64(j+1), gX, gY)
		commits.Points[j] = compressedPoint(cx, cy)
	}

	var free syntheticFreePoints
	free.bkX, free.bkY = mul(7, hX, hY)
	free.vkX, free.vkY = mul(11, gX, gY)
	free.eX, free.eY = mul(13, gX, gY)
	free.ePX, free.ePY = mul(17, gX, gY)
	free.rX, free.rY = mul(19, gX, gY)
	free.rPX, free.rPY = mul(23, gX, gY)
	return commits, free
}
