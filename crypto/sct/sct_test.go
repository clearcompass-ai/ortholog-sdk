package sct_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// SigningPayload
// ─────────────────────────────────────────────────────────────────────

func TestSigningPayload_GoldenBytes(t *testing.T) {
	// Frozen golden vector. Two independent computations must
	// agree byte-for-byte: the hand-built `want` slice (which
	// uses binary.BigEndian.PutUint64 directly) and the literal
	// `expectedHex` string (which I computed offline). If either
	// drifts from the production SigningPayload output, this
	// test fails loud.
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	got, err := sct.SigningPayload("did:key:zSigner", "ecdsa-secp256k1-sha256", "did:key:zLog", hash, 1700000000000000)
	if err != nil {
		t.Fatalf("SigningPayload: %v", err)
	}

	// Hand-build expected: independent code path validates the
	// production AppendUint16/AppendUint64 output.
	var want []byte
	want = append(want, sct.DomainSep...)
	want = append(want, sct.Version)
	want = append(want, 0, byte(len("did:key:zSigner")))
	want = append(want, "did:key:zSigner"...)
	want = append(want, 0, byte(len("ecdsa-secp256k1-sha256")))
	want = append(want, "ecdsa-secp256k1-sha256"...)
	want = append(want, 0, byte(len("did:key:zLog")))
	want = append(want, "did:key:zLog"...)
	want = append(want, hash[:]...)
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(1700000000000000))
	want = append(want, tsBuf...)

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("payload bytes mismatch\n got=%s\nwant=%s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Pin the absolute hex too — any silent re-layout breaks this.
	// Tail: 00060a24181e4000 = BE uint64 of 1700000000000000.
	const expectedHex = "4f5254484f4c4f475f5343545f5631000100" + // domain + version + signerDID len high
		"0f" + // signerDID len low (15)
		"6469643a6b65793a7a5369676e6572" + // signerDID
		"0016" + // sigAlgoID len = 22
		"65636473612d736563703235366b312d736861323536" +
		"000c" + // logDID len = 12
		"6469643a6b65793a7a4c6f67" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"00060a24181e4000"
	if hex.EncodeToString(got) != expectedHex {
		t.Fatalf("golden hex drifted; layout regressed\n got=%s\nwant=%s",
			hex.EncodeToString(got), expectedHex)
	}
}

func TestSigningPayload_EmptyFields(t *testing.T) {
	// Three zero-length variable fields produce length-prefix 0
	// followed by no bytes. Total layout:
	//   16 (DomainSep)
	// +  1 (Version)
	// +  2 + 0 (signerDID len + bytes)
	// +  2 + 0 (sigAlgoID len + bytes)
	// +  2 + 0 (logDID len + bytes)
	// + 32 (canonical_hash)
	// +  8 (log_time_micros)
	// = 63 bytes total.
	out, err := sct.SigningPayload("", "", "", [32]byte{}, 0)
	if err != nil {
		t.Fatalf("SigningPayload empty: %v", err)
	}
	if len(out) != 63 {
		t.Fatalf("len(out)=%d, want 63", len(out))
	}
}

// BUG #5 fix: SigningPayload rejects negative LogTimeMicros instead
// of silently casting to uint64. The pre-fix test pinned the buggy
// behavior (asserting an all-ones 0xFF...FF tail from the int64→
// uint64 wrap). The new contract: producer fails to construct,
// consumer fails to verify — symmetric refusal.
func TestSigningPayload_NegativeLogTime_Errors(t *testing.T) {
	for _, ts := range []int64{-1, -1000, -1 << 62} {
		_, err := sct.SigningPayload("a", "b", "c", [32]byte{}, ts)
		if err == nil {
			t.Errorf("LogTimeMicros=%d should be rejected", ts)
			continue
		}
		if !errors.Is(err, sct.ErrNegativeLogTime) {
			t.Errorf("LogTimeMicros=%d: error %v should be ErrNegativeLogTime", ts, err)
		}
	}
}

// Boundary: zero is the unix epoch and must remain valid (e.g.,
// truly-fresh-deployment SCTs at t=0 in deterministic tests).
func TestSigningPayload_ZeroLogTime_Accepted(t *testing.T) {
	if _, err := sct.SigningPayload("a", "b", "c", [32]byte{}, 0); err != nil {
		t.Errorf("LogTimeMicros=0 must be accepted: %v", err)
	}
}

func TestSigningPayload_MaxLengthFields(t *testing.T) {
	big := strings.Repeat("a", sct.MaxFieldLen)
	if _, err := sct.SigningPayload(big, "x", "y", [32]byte{}, 0); err != nil {
		t.Fatalf("max-length signerDID rejected: %v", err)
	}
	if _, err := sct.SigningPayload("x", big, "y", [32]byte{}, 0); err != nil {
		t.Fatalf("max-length sigAlgoID rejected: %v", err)
	}
	if _, err := sct.SigningPayload("x", "y", big, [32]byte{}, 0); err != nil {
		t.Fatalf("max-length logDID rejected: %v", err)
	}
}

func TestSigningPayload_OversizeFields(t *testing.T) {
	tooBig := strings.Repeat("a", sct.MaxFieldLen+1)
	cases := []struct {
		name     string
		signer   string
		algo     string
		logDID   string
		wantSent error
	}{
		{"signerDID", tooBig, "x", "y", sct.ErrSignerDIDTooLong},
		{"sigAlgoID", "x", tooBig, "y", sct.ErrSigAlgoTooLong},
		{"logDID", "x", "y", tooBig, sct.ErrLogDIDTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sct.SigningPayload(tc.signer, tc.algo, tc.logDID, [32]byte{}, 0)
			if !errors.Is(err, tc.wantSent) {
				t.Fatalf("got %v, want %v", err, tc.wantSent)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Verify — happy path round-trip and tamper detection
// ─────────────────────────────────────────────────────────────────────

func mintSCT(t *testing.T) (*sct.SignedCertificateTimestamp, *did.DIDKeyPairSecp256k1) {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	logTime := time.UnixMicro(1700000123456789).UTC()
	payload, err := sct.SigningPayload(kp.DID, sct.SigAlgoECDSASecp256k1SHA256, "did:key:zLog", hash, logTime.UnixMicro())
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	digest := sha256.Sum256(payload)
	sig, err := signatures.SignEntry(digest, kp.PrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &sct.SignedCertificateTimestamp{
		Version:       sct.Version,
		SignerDID:     kp.DID,
		SigAlgoID:     sct.SigAlgoECDSASecp256k1SHA256,
		LogDID:        "did:key:zLog",
		CanonicalHash: hex.EncodeToString(hash[:]),
		LogTimeMicros: logTime.UnixMicro(),
		LogTime:       logTime.Format(time.RFC3339Nano),
		Signature:     hex.EncodeToString(sig),
	}, kp
}

func TestVerify_HappyPath(t *testing.T) {
	s, kp := mintSCT(t)
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_NilPub(t *testing.T) {
	s, _ := mintSCT(t)
	if err := sct.Verify(nil, s); !errors.Is(err, sct.ErrNilPubKey) {
		t.Fatalf("got %v, want ErrNilPubKey", err)
	}
}

func TestVerify_NilSCT(t *testing.T) {
	_, kp := mintSCT(t)
	if err := sct.Verify(&kp.PrivateKey.PublicKey, nil); !errors.Is(err, sct.ErrNilSCT) {
		t.Fatalf("got %v, want ErrNilSCT", err)
	}
}

func TestVerify_BadVersion(t *testing.T) {
	s, kp := mintSCT(t)
	s.Version = 99
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrUnsupportedVer) {
		t.Fatalf("got %v, want ErrUnsupportedVer", err)
	}
}

func TestVerify_EmptySignerDID(t *testing.T) {
	s, kp := mintSCT(t)
	s.SignerDID = ""
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrMissingSignerDID) {
		t.Fatalf("got %v, want ErrMissingSignerDID", err)
	}
}

func TestVerify_BadAlgo(t *testing.T) {
	s, kp := mintSCT(t)
	s.SigAlgoID = "ed25519"
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrUnsupportedAlgo) {
		t.Fatalf("got %v, want ErrUnsupportedAlgo", err)
	}
}

func TestVerify_LogTimeMismatch(t *testing.T) {
	s, kp := mintSCT(t)
	s.LogTime = time.UnixMicro(s.LogTimeMicros + 1).UTC().Format(time.RFC3339Nano)
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrLogTimeMismatch) {
		t.Fatalf("got %v, want ErrLogTimeMismatch", err)
	}
}

func TestVerify_BadCanonicalHashHex(t *testing.T) {
	s, kp := mintSCT(t)
	s.CanonicalHash = "not-hex-zz"
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrBadCanonicalHash) {
		t.Fatalf("got %v, want ErrBadCanonicalHash", err)
	}
}

func TestVerify_WrongLengthHash(t *testing.T) {
	s, kp := mintSCT(t)
	s.CanonicalHash = "deadbeef"
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrBadHashLength) {
		t.Fatalf("got %v, want ErrBadHashLength", err)
	}
}

func TestVerify_BadSignatureHex(t *testing.T) {
	s, kp := mintSCT(t)
	s.Signature = "not-hex-zz"
	if err := sct.Verify(&kp.PrivateKey.PublicKey, s); !errors.Is(err, sct.ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerify_OversizeFieldPropagates(t *testing.T) {
	s, kp := mintSCT(t)
	s.SignerDID = strings.Repeat("a", sct.MaxFieldLen+1)
	err := sct.Verify(&kp.PrivateKey.PublicKey, s)
	if !errors.Is(err, sct.ErrSignerDIDTooLong) {
		t.Fatalf("got %v, want ErrSignerDIDTooLong propagated from SigningPayload", err)
	}
}

func TestVerify_TamperedHashFailsCrypto(t *testing.T) {
	s, kp := mintSCT(t)
	var tampered [32]byte
	for i := range tampered {
		tampered[i] = 0xff
	}
	s.CanonicalHash = hex.EncodeToString(tampered[:])
	err := sct.Verify(&kp.PrivateKey.PublicKey, s)
	if err == nil {
		t.Fatalf("expected crypto verify failure")
	}
	if !strings.Contains(err.Error(), "VerifyEntry") {
		t.Fatalf("got %q, want wrapped VerifyEntry error", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	s, _ := mintSCT(t)
	other, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if err := sct.Verify(&other.PrivateKey.PublicKey, s); err == nil {
		t.Fatalf("verify with wrong key unexpectedly succeeded")
	}
}

func TestSCTStruct_Fields(t *testing.T) {
	s := sct.SignedCertificateTimestamp{
		Version:       1,
		SignerDID:     "x",
		SigAlgoID:     "y",
		LogDID:        "z",
		CanonicalHash: "00",
		LogTimeMicros: 1,
		LogTime:       "t",
		Signature:     "s",
	}
	if s.Version != 1 || s.SignerDID == "" || s.SigAlgoID == "" || s.LogDID == "" {
		t.Fatal("struct fields not addressable")
	}
}
