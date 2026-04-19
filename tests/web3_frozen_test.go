/*
FILE PATH:

	tests/web3_frozen_test.go

DESCRIPTION:

	Frozen protocol constants — the highest-severity class of invariants.
	Any test in this file failing means a silent protocol break: signatures
	produced by prior code will no longer verify, or vice versa. All values
	locked here are computed from the shipped code and MUST NEVER drift
	without an explicit breaking-version bump.

KEY ARCHITECTURAL DECISIONS:
  - Hex literals are pasted, not recomputed. If a test fails, the right
    answer is almost always "revert the code change," not "update the
    fixture." The test exists precisely to prevent the drift.
  - ValidateAlgorithmID is tested exhaustively across every uint16 value,
    not just by spot-check. Spot-checks miss cases where a new constant
    is added but the registry isn't updated.
  - AppendSignature / ReadSignature are tested for their symmetric
    validation — both reject unknown algoIDs, both reject length mismatches.
*/
package tests

import (
	"bytes"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Algorithm ID constants — values frozen
// -------------------------------------------------------------------------------------------------

func TestAlgorithmID_FROZEN_Values(t *testing.T) {
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"SigAlgoECDSA", envelope.SigAlgoECDSA, 0x0001},
		{"SigAlgoEd25519", envelope.SigAlgoEd25519, 0x0002},
		{"SigAlgoEIP191", envelope.SigAlgoEIP191, 0x0003},
		{"SigAlgoEIP712", envelope.SigAlgoEIP712, 0x0004},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("%s changed: got 0x%04x, want 0x%04x — this invalidates every entry ever signed under this ID",
				c.name, c.got, c.want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Algorithm ID — exhaustive uint16 sweep
// -------------------------------------------------------------------------------------------------

func TestAlgorithmID_ExhaustiveSweep(t *testing.T) {
	registered := map[uint16]bool{
		envelope.SigAlgoECDSA:   true,
		envelope.SigAlgoEd25519: true,
		envelope.SigAlgoEIP191:  true,
		envelope.SigAlgoEIP712:  true,
	}
	// Iterate every possible uint16 value. Tight loop, runs in <50 ms.
	for i := 0; i < 65536; i++ {
		algoID := uint16(i)
		err := envelope.ValidateAlgorithmID(algoID)
		if registered[algoID] {
			if err != nil {
				t.Fatalf("registered algoID 0x%04x rejected: %v", algoID, err)
			}
		} else {
			if err == nil {
				t.Fatalf("unregistered algoID 0x%04x accepted — namespace contamination", algoID)
			}
			if !errors.Is(err, envelope.ErrUnknownAlgorithmID) {
				t.Fatalf("unregistered algoID 0x%04x rejected with wrong error type: %v", algoID, err)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Signature length — frozen per algorithm
// -------------------------------------------------------------------------------------------------

func TestSignatureLengthForAlgorithm_FROZEN(t *testing.T) {
	cases := []struct {
		name   string
		algoID uint16
		want   int
	}{
		{"SigAlgoECDSA", envelope.SigAlgoECDSA, 64},
		{"SigAlgoEd25519", envelope.SigAlgoEd25519, 64},
		{"SigAlgoEIP191", envelope.SigAlgoEIP191, 65},
		{"SigAlgoEIP712", envelope.SigAlgoEIP712, 65},
		{"unknown 0xBEEF", 0xBEEF, 0},
	}
	for _, c := range cases {
		if got := envelope.SignatureLengthForAlgorithm(c.algoID); got != c.want {
			t.Fatalf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 4) AppendSignature — validates both sides of the wire symmetrically
// -------------------------------------------------------------------------------------------------

func TestAppendSignature_RejectsUnknownAlgoID(t *testing.T) {
	canonical := []byte("canonical entry bytes")
	sig := make([]byte, 64)
	_, err := envelope.AppendSignature(canonical, 0xBEEF, sig)
	if err == nil {
		t.Fatal("AppendSignature accepted unregistered algoID 0xBEEF")
	}
	if !errors.Is(err, envelope.ErrUnknownAlgorithmID) {
		t.Fatalf("wrong error type: %v", err)
	}
}

func TestAppendSignature_RejectsLengthMismatch(t *testing.T) {
	canonical := []byte("canonical")
	cases := []struct {
		name   string
		algoID uint16
		sigLen int
	}{
		{"ECDSA with 65-byte sig", envelope.SigAlgoECDSA, 65},
		{"Ed25519 with 63-byte sig", envelope.SigAlgoEd25519, 63},
		{"EIP-191 with 64-byte sig", envelope.SigAlgoEIP191, 64},
		{"EIP-712 with 66-byte sig", envelope.SigAlgoEIP712, 66},
	}
	for _, c := range cases {
		_, err := envelope.AppendSignature(canonical, c.algoID, make([]byte, c.sigLen))
		if err == nil {
			t.Fatalf("%s: AppendSignature accepted length mismatch", c.name)
		}
		if !errors.Is(err, envelope.ErrSignatureLengthMismatch) {
			t.Fatalf("%s: wrong error type: %v", c.name, err)
		}
	}
}

func TestAppendSignature_AcceptsAllRegisteredAlgorithms(t *testing.T) {
	canonical := []byte("canonical")
	for _, c := range []struct {
		algoID uint16
		sigLen int
	}{
		{envelope.SigAlgoECDSA, 64},
		{envelope.SigAlgoEd25519, 64},
		{envelope.SigAlgoEIP191, 65},
		{envelope.SigAlgoEIP712, 65},
	} {
		wire, err := envelope.AppendSignature(canonical, c.algoID, make([]byte, c.sigLen))
		if err != nil {
			t.Fatalf("algoID 0x%04x: unexpected error %v", c.algoID, err)
		}
		if len(wire) != len(canonical)+2+c.sigLen {
			t.Fatalf("algoID 0x%04x: wire length %d, expected %d",
				c.algoID, len(wire), len(canonical)+2+c.sigLen)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 5) ReadSignature — symmetric validation
// -------------------------------------------------------------------------------------------------

func TestReadSignature_RejectsUnknownAlgoID(t *testing.T) {
	canonical := []byte("canonical")
	// Craft wire directly: [canonical][0xBE][0xEF][64 sig bytes]
	wire := append([]byte{}, canonical...)
	wire = append(wire, 0xBE, 0xEF)
	wire = append(wire, make([]byte, 64)...)
	_, _, err := envelope.ReadSignature(wire, len(canonical))
	if err == nil {
		t.Fatal("ReadSignature accepted algoID 0xBEEF")
	}
	if !errors.Is(err, envelope.ErrUnknownAlgorithmID) {
		t.Fatalf("wrong error type: %v", err)
	}
}

func TestReadSignature_RejectsLengthMismatch(t *testing.T) {
	canonical := []byte("canonical")
	// Tag with ECDSA (expects 64) but append 65 bytes.
	wire := append([]byte{}, canonical...)
	wire = append(wire, 0x00, 0x01) // SigAlgoECDSA
	wire = append(wire, make([]byte, 65)...)
	_, _, err := envelope.ReadSignature(wire, len(canonical))
	if err == nil {
		t.Fatal("ReadSignature accepted 65-byte trailer for SigAlgoECDSA")
	}
	if !errors.Is(err, envelope.ErrSignatureLengthMismatch) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) StripSignature — unambiguous framing
// -------------------------------------------------------------------------------------------------

func TestStripSignature_RoundTrip_EachAlgorithm(t *testing.T) {
	canonical := []byte("canonical entry bytes")
	for _, c := range []struct {
		algoID uint16
		sigLen int
	}{
		{envelope.SigAlgoECDSA, 64},
		{envelope.SigAlgoEd25519, 64},
		{envelope.SigAlgoEIP191, 65},
		{envelope.SigAlgoEIP712, 65},
	} {
		sig := make([]byte, c.sigLen)
		for i := range sig {
			sig[i] = byte(i + 1) // non-zero so we can verify byte-preservation
		}
		wire, err := envelope.AppendSignature(canonical, c.algoID, sig)
		if err != nil {
			t.Fatalf("algoID 0x%04x: AppendSignature: %v", c.algoID, err)
		}
		gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
		if err != nil {
			t.Fatalf("algoID 0x%04x: StripSignature: %v", c.algoID, err)
		}
		if !bytes.Equal(gotCanon, canonical) {
			t.Fatalf("algoID 0x%04x: canonical drift", c.algoID)
		}
		if gotAlgo != c.algoID {
			t.Fatalf("algoID 0x%04x: got algo 0x%04x", c.algoID, gotAlgo)
		}
		if !bytes.Equal(gotSig, sig) {
			t.Fatalf("algoID 0x%04x: sig bytes drift", c.algoID)
		}
	}
}

func TestStripSignature_TooShort(t *testing.T) {
	// 10 bytes cannot contain even a 64-byte trailer + 2-byte algo.
	_, _, _, err := envelope.StripSignature(make([]byte, 10))
	if err == nil {
		t.Fatal("StripSignature accepted 10-byte wire")
	}
	if !errors.Is(err, envelope.ErrWireTooShort) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) EIP-712 domain constants — frozen forever
// -------------------------------------------------------------------------------------------------

// Values computed from the shipped code on protocol v5 launch.
// Recomputing these MUST NOT be done casually — changing any value
// invalidates every signature ever produced against the protocol.
//
// To audit: keccak256("ortholog.v1.entry-signature") must equal the salt.
// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)") must equal the domain type hash.
// keccak256("OrthologEntry(bytes32 canonicalHash)") must equal the entry type hash.

const (
	frozenProtocolSalt      = "81ec03154b75ffe861768e00c874a6ad5f82d6495cd456dccbf983152e54b58e"
	frozenEntryTypeHash     = "d2147cb2986ba2ea70de9b7e55c0f29c45ca3607e242f436daa2d4544cae69f5"
	frozenDomainSeparator   = "f39667371bd9adcd1c3c72034702444784b646f87fd894eb4322dfa63057a939"
	frozenDigestCanonZero   = "0f2bfa7044ab0551d7ce36428c2fcf6b8a2e30dec03508627cea83be3425831a"
	frozenDigestCanonAll11  = "0f2baf68177124e6835cef41402ac95bfd9d9ade1aa5611d15dca9fc3072a38f"
	frozenDigestCanonAllFF  = "8e2fa68df52c2a3220873c4cb031cff17838612e99be9145d7ba7ac8b744a531"
	frozenEIP191DigestZeros = "5e4106618209740b9f773a94c5667b9659a7a4e2691c7c8a78336e9889a6be07"
	frozenEIP191DigestAll11 = "245a48de257ae28de2b11cb8fc02361fe87a20566dc63bec4492c3854b1aae52"
)

func TestEIP712_ProtocolSalt_FROZEN(t *testing.T) {
	got := signatures.EIP712ProtocolSalt()
	want := mustHex32(t, frozenProtocolSalt)
	if got != want {
		t.Fatalf("EIP-712 protocol salt changed.\nThis invalidates every EIP-712 signature ever produced.\ngot:  %x\nwant: %x", got, want)
	}
}

func TestEIP712_EntryTypeHash_FROZEN(t *testing.T) {
	got := signatures.EIP712EntryTypeHash()
	want := mustHex32(t, frozenEntryTypeHash)
	if got != want {
		t.Fatalf("EIP-712 entry type hash changed.\nThis invalidates every EIP-712 signature ever produced.\ngot:  %x\nwant: %x", got, want)
	}
}

func TestEIP712_DomainSeparator_FROZEN(t *testing.T) {
	got := signatures.EIP712DomainSeparator()
	want := mustHex32(t, frozenDomainSeparator)
	if got != want {
		t.Fatalf("EIP-712 domain separator changed.\nThis invalidates every EIP-712 signature ever produced.\ngot:  %x\nwant: %x", got, want)
	}
}

func TestEIP712_EntrySigningDigest_KnownVectors(t *testing.T) {
	cases := []struct {
		name    string
		canon   [32]byte
		wantHex string
	}{
		{"all-zero canonical hash", [32]byte{}, frozenDigestCanonZero},
		{"all-0x11 canonical hash", fill32(0x11), frozenDigestCanonAll11},
		{"all-0xff canonical hash", fill32(0xff), frozenDigestCanonAllFF},
	}
	for _, c := range cases {
		got := signatures.EntrySigningDigest(c.canon)
		want := mustHex32(t, c.wantHex)
		if got != want {
			t.Fatalf("%s: digest drift.\ngot:  %x\nwant: %x", c.name, got, want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 8) EIP-191 — frozen prefix + known-vector digests
// -------------------------------------------------------------------------------------------------

func TestEIP191_Digest_KnownVectors(t *testing.T) {
	cases := []struct {
		name    string
		msg     []byte
		wantHex string
	}{
		{"32 zero bytes", make([]byte, 32), frozenEIP191DigestZeros},
		{"32 0x11 bytes", bytes.Repeat([]byte{0x11}, 32), frozenEIP191DigestAll11},
	}
	for _, c := range cases {
		got := signatures.EIP191Digest(c.msg)
		want := mustHex32(t, c.wantHex)
		if got != want {
			t.Fatalf("%s: digest drift.\ngot:  %x\nwant: %x", c.name, got, want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 9) Multicodec prefixes — frozen per W3C did:key spec
// -------------------------------------------------------------------------------------------------

func TestMulticodec_FROZEN_Prefixes(t *testing.T) {
	if did.MulticodecEd25519 != [2]byte{0xed, 0x01} {
		t.Fatalf("Ed25519 multicodec changed: %x", did.MulticodecEd25519)
	}
	if did.MulticodecSecp256k1 != [2]byte{0xe7, 0x01} {
		t.Fatalf("secp256k1 multicodec changed: %x", did.MulticodecSecp256k1)
	}
	if did.MulticodecP256 != [2]byte{0x12, 0x00} {
		t.Fatalf("P-256 multicodec changed: %x", did.MulticodecP256)
	}
}

// -------------------------------------------------------------------------------------------------
// 10) Verification method types — frozen per W3C DID Core Vocabulary
// -------------------------------------------------------------------------------------------------

func TestVerificationMethodTypes_FROZEN(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"Ed25519", did.VerificationMethodEd25519, "Ed25519VerificationKey2020"},
		{"Secp256k1", did.VerificationMethodSecp256k1, "EcdsaSecp256k1VerificationKey2019"},
		{"P256", did.VerificationMethodP256, "EcdsaSecp256r1VerificationKey2019"},
		{"Secp256k1Recovery", did.VerificationMethodSecp256k1Recovery, "EcdsaSecp256k1RecoveryMethod2020"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("%s: got %q, want %q — W3C type string drift breaks interop",
				c.name, c.got, c.want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}
