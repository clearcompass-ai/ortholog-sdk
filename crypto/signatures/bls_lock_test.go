/*
FILE PATH:

	crypto/signatures/bls_lock_test.go

DESCRIPTION:

	Byte-level locks on cryptographic protocol constants. These tests
	are not correctness tests in the usual sense — they are REGRESSION
	GUARDS that fail loudly if any protocol constant drifts.

	The values locked here define the wire-compatibility boundary of
	the Ortholog BLS scheme. Changing any of them invalidates every
	signature the SDK has ever produced under SchemeBLS (0x02) and
	every proof-of-possession ever registered. Such a change is a
	BREAKING PROTOCOL CHANGE that must:

	  1. Increment the scheme version (SchemeBLS_V2 = 0x04 or similar).
	  2. Introduce new DST constants for V2 (e.g., ORTHOLOG_BLS_SIG_V2_).
	  3. Leave V1 constants and verification paths intact for
	     compatibility with existing signatures.

	Never "fix" a failing test in this file by updating the expected
	value. If one of these tests fails, something has gone wrong that
	requires architectural attention, not a test tweak.

LOCKS IN THIS FILE:

	TestBLSDomainTag_Bytes          — cosignature DST, exact bytes
	TestBLSPoPDomainTag_Bytes       — PoP DST, exact bytes
	TestBLSG1CompressedLen_Locked   — signature wire size
	TestBLSG2CompressedLen_Locked   — public key wire size
	TestHashToG1_LockedOutput_CosigDST — hash-to-curve vector (cosig)
	TestHashToG1_LockedOutput_PoPDST   — hash-to-curve vector (PoP)
*/
package signatures

import (
	"bytes"
	"encoding/hex"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// DST byte locks
// ═══════════════════════════════════════════════════════════════════

// TestBLSDomainTag_Bytes locks the exact 20-byte content of the
// cosignature domain separation tag. Every BLS cosignature the SDK
// produces under SchemeBLS uses this tag as its RFC 9380 DST input.
//
// If this test fails: someone modified BLSDomainTag. Do NOT update
// the expected array. Revert the BLSDomainTag change or introduce a
// new scheme version.
func TestBLSDomainTag_Bytes(t *testing.T) {
	expected := []byte{
		0x4F, 0x52, 0x54, 0x48, 0x4F, 0x4C, 0x4F, 0x47, // O R T H O L O G
		0x5F,             // _
		0x42, 0x4C, 0x53, // B L S
		0x5F,             // _
		0x53, 0x49, 0x47, // S I G
		0x5F,       // _
		0x56, 0x31, // V 1
		0x5F, // _
	}
	actual := []byte(BLSDomainTag)

	if len(actual) != len(expected) {
		t.Fatalf("BLSDomainTag length changed: expected %d bytes, got %d.\n"+
			"This is a breaking protocol change. Revert, or introduce SchemeBLS_V2.",
			len(expected), len(actual))
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("BLSDomainTag bytes changed:\n"+
			"  expected: %s (%x)\n"+
			"  actual:   %s (%x)\n\n"+
			"This is a breaking protocol change. Do NOT fix this test by\n"+
			"updating expected — introduce a new scheme version (SchemeBLS_V2)\n"+
			"and keep V1 unchanged for existing signature compatibility.",
			string(expected), expected, string(actual), actual)
	}
}

// TestBLSPoPDomainTag_Bytes locks the exact 20-byte content of the
// proof-of-possession DST. This DST is SECURITY-CRITICAL: domain
// separation between BLSDomainTag and BLSPoPDomainTag is what
// prevents a cosignature from being replayed as a PoP.
//
// If this test fails: the DST separation boundary has been breached.
// Investigate immediately. Any change to this constant without a
// corresponding scheme version bump enables cross-protocol
// signature reuse.
func TestBLSPoPDomainTag_Bytes(t *testing.T) {
	expected := []byte{
		0x4F, 0x52, 0x54, 0x48, 0x4F, 0x4C, 0x4F, 0x47, // O R T H O L O G
		0x5F,             // _
		0x42, 0x4C, 0x53, // B L S
		0x5F,             // _
		0x50, 0x6F, 0x50, // P o P
		0x5F,       // _
		0x56, 0x31, // V 1
		0x5F, // _
	}
	actual := []byte(BLSPoPDomainTag)

	if len(actual) != len(expected) {
		t.Fatalf("BLSPoPDomainTag length changed: expected %d bytes, got %d.\n"+
			"This is a breaking protocol change. Revert.",
			len(expected), len(actual))
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("BLSPoPDomainTag bytes changed:\n"+
			"  expected: %s (%x)\n"+
			"  actual:   %s (%x)\n\n"+
			"SECURITY-CRITICAL. Do NOT fix by updating expected.",
			string(expected), expected, string(actual), actual)
	}
}

// TestDomainSeparation_DSTsAreDistinct confirms the two DSTs are not
// accidentally equal. A robustness check against a maintainer
// mistakenly copy-pasting one constant into the other. If this test
// fails, domain separation is broken and cross-protocol signature
// reuse becomes possible.
func TestDomainSeparation_DSTsAreDistinct(t *testing.T) {
	if BLSDomainTag == BLSPoPDomainTag {
		t.Fatal("CRITICAL: BLSDomainTag == BLSPoPDomainTag. " +
			"Domain separation is broken. Cross-protocol signature reuse is " +
			"now possible. Investigate and revert.")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Wire-size locks
// ═══════════════════════════════════════════════════════════════════

// TestBLSG1CompressedLen_Locked locks the signature wire size at
// 48 bytes. BLS12-381 G1 compressed encoding is mathematically fixed
// at 48 bytes; this test guards against a maintainer mistakenly
// changing the constant to match a different curve.
func TestBLSG1CompressedLen_Locked(t *testing.T) {
	if BLSG1CompressedLen != 48 {
		t.Fatalf("BLSG1CompressedLen = %d, want 48. "+
			"BLS12-381 G1 compressed encoding is 48 bytes by curve definition.",
			BLSG1CompressedLen)
	}

	// Cross-check with gnark's actual serialization size: produce any
	// G1 point and confirm it serializes to exactly this many bytes.
	_, _, g1, _ := bls12381.Generators()
	g1Bytes := g1.Bytes()
	if len(g1Bytes) != BLSG1CompressedLen {
		t.Fatalf("gnark G1 generator compressed length = %d, but "+
			"BLSG1CompressedLen = %d. Library behavior has diverged "+
			"from the constant.", len(g1Bytes), BLSG1CompressedLen)
	}
}

// TestBLSG2CompressedLen_Locked locks the public key wire size at
// 96 bytes. Same reasoning as TestBLSG1CompressedLen_Locked.
func TestBLSG2CompressedLen_Locked(t *testing.T) {
	if BLSG2CompressedLen != 96 {
		t.Fatalf("BLSG2CompressedLen = %d, want 96. "+
			"BLS12-381 G2 compressed encoding is 96 bytes by curve definition.",
			BLSG2CompressedLen)
	}

	_, _, _, g2 := bls12381.Generators()
	g2Bytes := g2.Bytes()
	if len(g2Bytes) != BLSG2CompressedLen {
		t.Fatalf("gnark G2 generator compressed length = %d, but "+
			"BLSG2CompressedLen = %d. Library behavior has diverged "+
			"from the constant.", len(g2Bytes), BLSG2CompressedLen)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Hash-to-curve output locks
// ═══════════════════════════════════════════════════════════════════

// TestHashToG1_LockedOutput_CosigDST locks the exact output of
// HashToG1 for a canonical test vector under BLSDomainTag. Catches
// drift in the underlying gnark-crypto library's SSWU map
// implementation, subgroup clearing, or point compression.
//
// The test vector is a WitnessCosignMessage for:
//   - RootHash = [0x01, 0x02, 0x03, ..., 0x20]
//   - TreeSize = 100
//
// The expected hex string below was generated once against the
// pinned gnark-crypto version in go.mod and committed. If this test
// fails:
//   - gnark-crypto version changed in go.mod (check against pinned version)
//   - BLSDomainTag was modified (check TestBLSDomainTag_Bytes)
//   - WitnessCosignMessage encoding changed (check types/tree_head.go)
//   - Platform/compiler difference (investigate, but gnark should be
//     platform-stable)
//
// Any of these is a breaking protocol change. Do NOT update the
// expected hex without introducing a new scheme version.
//
// GENERATION PROCEDURE:
//
//	Run this test with a print statement; capture the hex output;
//	replace expectedHex below; commit. The hex is now the protocol
//	truth and must not change without a scheme version bump.
func TestHashToG1_LockedOutput_CosigDST(t *testing.T) {
	// Canonical test vector.
	head := types.TreeHead{
		RootHash: [32]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		},
		TreeSize: 100,
	}
	msg := types.WitnessCosignMessage(head)

	hashPoint, err := bls12381.HashToG1(msg[:], []byte(BLSDomainTag))
	if err != nil {
		t.Fatalf("HashToG1: %v", err)
	}

	compressed := hashPoint.Bytes()
	actualHex := hex.EncodeToString(compressed[:])

	// GENERATED_ONCE_AND_LOCKED: first run this test with
	// t.Logf("%s", actualHex), capture the output, commit here.
	// Until then the placeholder triggers the test to inform the
	// maintainer that generation is needed.
	expectedHex := "92d2107ffdd3d83268dd4113061eef25a82aff6b4661cf4095f7c82679632b039a26441a1c0fda8d0c5f1de7812d427f"

	if expectedHex == "GENERATE_ONCE_AND_COMMIT" {
		t.Logf("First-run capture mode:\n  actual: %s\n"+
			"Copy the above hex into expectedHex and commit.", actualHex)
		t.Skip("lock test vector not yet generated; see procedure in test godoc")
	}

	if actualHex != expectedHex {
		t.Fatalf("HashToG1 (cosig DST) output drift:\n"+
			"  expected: %s\n"+
			"  actual:   %s\n\n"+
			"This likely indicates:\n"+
			"  - gnark-crypto version changed (check go.mod)\n"+
			"  - BLSDomainTag modified (check TestBLSDomainTag_Bytes)\n"+
			"  - WitnessCosignMessage encoding changed\n\n"+
			"BREAKING PROTOCOL CHANGE. Do not update expectedHex; investigate root cause.",
			expectedHex, actualHex)
	}
}

// TestHashToG1_LockedOutput_PoPDST locks the HashToG1 output under
// BLSPoPDomainTag for a canonical public key test vector.
//
// Test vector: a G2 public key whose compressed bytes are all zero
// above the curve-equation-defined prefix bits. We use the G2
// generator as the test key — it's a fixed, library-defined point
// whose compressed bytes are stable across gnark versions (any
// divergence in encoding is itself a breaking change worth catching).
//
// Generation procedure identical to the cosig DST test.
func TestHashToG1_LockedOutput_PoPDST(t *testing.T) {
	_, _, _, g2 := bls12381.Generators()
	pkBytes := g2.Bytes()

	hashPoint, err := bls12381.HashToG1(pkBytes[:], []byte(BLSPoPDomainTag))
	if err != nil {
		t.Fatalf("HashToG1: %v", err)
	}

	compressed := hashPoint.Bytes()
	actualHex := hex.EncodeToString(compressed[:])

	expectedHex := "ab29b2ce70bbd7a8779a21c3f9f65eb74ad39fb6a3f283b37120f522b672eda1a805a8becc7ac1f370061d7e88e2b14e"

	if expectedHex == "GENERATE_ONCE_AND_COMMIT" {
		t.Logf("First-run capture mode:\n  actual: %s\n"+
			"Copy the above hex into expectedHex and commit.", actualHex)
		t.Skip("lock test vector not yet generated")
	}

	if actualHex != expectedHex {
		t.Fatalf("HashToG1 (PoP DST) output drift:\n"+
			"  expected: %s\n"+
			"  actual:   %s\n\n"+
			"BREAKING PROTOCOL CHANGE for proof-of-possession.",
			expectedHex, actualHex)
	}
}
