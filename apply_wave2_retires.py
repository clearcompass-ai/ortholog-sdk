#!/usr/bin/env python3
"""
apply_wave2_retires.py — Wave 2 retirements.

Removes 9 tests whose v5-specific invariants have no v6 equivalent (or
whose invariant is preserved elsewhere at a more appropriate layer).
Each retirement includes a comment explaining where the equivalent
coverage lives.

Scope:
  tests/web3_frozen_test.go — 5 retirements
    1. TestSignatureLengthForAlgorithm_FROZEN
       - SignatureLengthForAlgorithm deleted in v6. Length is a per-sig
         uint32 field, not an algorithm property.
    2. TestAppendSignature_RejectsLengthMismatch
       - v6 deliberately removed per-algo length enforcement to admit
         variable-length algorithms like SigAlgoJWZ (1-4 KB).
    3. TestReadSignature_RejectsLengthMismatch
       - Same reason as above.
    4. TestStripSignature_RoundTrip_EachAlgorithm
       - StripSignature deleted. v6 round-trip covered by
         TestCanonicalHash_RoundTrip.
    5. TestStripSignature_TooShort
       - StripSignature deleted; ErrWireTooShort no longer a defined
         sentinel in v6.

  tests/web3_witness_boundary_test.go — 2 retirements
    6. TestWitness_RejectsEthereumSigLengths
       - Tested encoding-level rejection of 65-byte sigs tagged as
         SigAlgoECDSA. v6 removed encoding-level length enforcement
         (per the architectural decision documented in
         core/envelope/signatures_section.go). The invariant that
         witness path rejects wallet sigs is preserved and tested
         correctly by TestWitness_OnlyECDSASignaturesAccepted in the
         same file, which exercises the cryptographic verifier directly.
    7. TestWitness_AlgorithmClassification
       - Tests SignatureLengthForAlgorithm values; function deleted.

  [NOTE: Wave 2 also includes 7 rewrites to existing broken tests.
   Those are delivered as separate hand-written replacement files:
     tests/web3_frozen_test.go       (4 tests rewritten)
     tests/web3_fuzz_test.go         (2 tests rewritten)
     tests/web3_entry_signature_test.go (2 tests rewritten - tests #5/#6)
   This script handles ONLY the retirements. After running it, apply
   the rewrite files (they are complete file replacements).]

Run from repo root:
    cd ~/workspace/ortholog-sdk
    python3 apply_wave2_retires.py
"""

import sys
from pathlib import Path


# ============================================================================
# Core: literal replacement with idempotent safety checks
# ============================================================================

def apply_replacements(label, path, replacements):
    """
    Apply (old, new, description) replacements to a file idempotently.
    - old_count == 1: apply.
    - old_count == 0 and new_count >= 1: skip (already migrated).
    - old_count == 0 otherwise: FAIL (anchor drifted).
    - old_count > 1: FAIL (ambiguous).
    """
    if not path.exists():
        return 0, 0, [f"{label}: {path} not found"]

    original = path.read_text()
    updated = original
    applied = 0
    skipped = 0
    failures = []

    for old, new, desc in replacements:
        old_count = updated.count(old)
        new_count = updated.count(new) if new else 0

        if old_count == 1:
            updated = updated.replace(old, new, 1)
            applied += 1
            print(f"  [{label}] applied: {desc}")
        elif old_count == 0 and new_count >= 1:
            skipped += 1
            print(f"  [{label}] skipped (already migrated): {desc}")
        elif old_count == 0:
            failures.append(f"{label}: anchor not found — {desc}")
        else:
            failures.append(
                f"{label}: anchor appears {old_count} times — ambiguous — {desc}")

    if failures:
        return applied, skipped, failures

    if updated != original:
        backup = path.with_suffix(path.suffix + ".bak")
        backup.write_text(original)
        path.write_text(updated)
        print(f"  [{label}] wrote {path} (backup at {backup})")
    else:
        print(f"  [{label}] no changes needed")

    return applied, skipped, []


# ============================================================================
# File 1: tests/web3_frozen_test.go — 5 retirements
# ============================================================================

FROZEN_RETIRES = [
    # Retire 1: TestSignatureLengthForAlgorithm_FROZEN
    (
        '''func TestSignatureLengthForAlgorithm_FROZEN(t *testing.T) {
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
}''',
        '''// TestSignatureLengthForAlgorithm_FROZEN was retired in the v6
// migration. envelope.SignatureLengthForAlgorithm was removed because
// v6 signatures carry their own length as an explicit uint32 field in
// the wire format (see core/envelope/signatures_section.go). Length is
// no longer an algorithm-level property — it is a per-signature field.
// This design admits variable-length algorithms like SigAlgoJWZ
// (Polygon ID ZK proofs, 1-4 KB typical) without wire-format changes.''',
        "retire TestSignatureLengthForAlgorithm_FROZEN",
    ),

    # Retire 2: TestAppendSignature_RejectsLengthMismatch
    (
        '''func TestAppendSignature_RejectsLengthMismatch(t *testing.T) {
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
}''',
        '''// TestAppendSignature_RejectsLengthMismatch was retired in the v6
// migration. v6 deliberately removed per-algorithm length enforcement
// at the encoding layer because algorithms like SigAlgoJWZ are
// variable-length by design. Each signature now carries its own
// explicit uint32 length field. The invariant that cryptographic
// verifiers reject wrong-length sigs is preserved at the verify layer
// (see TestWitness_OnlyECDSASignaturesAccepted in
// tests/web3_witness_boundary_test.go), which is the correct layer
// for that invariant — the cryptographic primitive is the authority
// on what shapes it accepts.''',
        "retire TestAppendSignature_RejectsLengthMismatch",
    ),

    # Retire 3: TestReadSignature_RejectsLengthMismatch
    (
        '''func TestReadSignature_RejectsLengthMismatch(t *testing.T) {
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
}''',
        '''// TestReadSignature_RejectsLengthMismatch was retired in the v6
// migration. See TestAppendSignature_RejectsLengthMismatch retirement
// comment above for rationale — v6 removed per-algorithm length
// enforcement in favor of explicit per-signature length fields.''',
        "retire TestReadSignature_RejectsLengthMismatch",
    ),

    # Retire 4: TestStripSignature_RoundTrip_EachAlgorithm
    (
        '''func TestStripSignature_RoundTrip_EachAlgorithm(t *testing.T) {
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
}''',
        '''// TestStripSignature_RoundTrip_EachAlgorithm was retired in the v6
// migration. AppendSignature and StripSignature were removed — v6
// signatures are part of the canonical entry, not a separable wire
// trailer. The v6-native round-trip invariant ("an entry with
// signatures round-trips through Serialize/Deserialize preserving
// every field including signatures") is covered by
// TestCanonicalHash_RoundTrip in tests/canonical_hash_test.go.''',
        "retire TestStripSignature_RoundTrip_EachAlgorithm",
    ),

    # Retire 5: TestStripSignature_TooShort
    (
        '''func TestStripSignature_TooShort(t *testing.T) {
	// 10 bytes cannot contain even a 64-byte trailer + 2-byte algo.
	_, _, _, err := envelope.StripSignature(make([]byte, 10))
	if err == nil {
		t.Fatal("StripSignature accepted 10-byte wire")
	}
	if !errors.Is(err, envelope.ErrWireTooShort) {
		t.Fatalf("wrong error type: %v", err)
	}
}''',
        '''// TestStripSignature_TooShort was retired in the v6 migration.
// StripSignature was removed; ErrWireTooShort no longer a defined
// error sentinel. v6 short-input rejection behavior for
// envelope.Deserialize is covered by the envelope_v5_test.go and
// envelope parser tests (invalid inputs return wrapped errors from
// io.ReadFull or binary.Read, not a specific "too short" sentinel).''',
        "retire TestStripSignature_TooShort",
    ),
]


# ============================================================================
# File 2: tests/web3_witness_boundary_test.go — 2 retirements
# ============================================================================

WITNESS_RETIRES = [
    # Retire 6: TestWitness_RejectsEthereumSigLengths
    (
        '''func TestWitness_RejectsEthereumSigLengths(t *testing.T) {
	canonical := []byte("canonical witness payload")

	// Attempt to frame a 65-byte signature (EIP-191/712 size) as SDK ECDSA.
	eth65 := make([]byte, 65)
	_, err := envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, eth65)
	if err == nil {
		t.Fatal("AppendSignature accepted 65-byte sig tagged as SigAlgoECDSA — boundary violation")
	}
	if !errors.Is(err, envelope.ErrSignatureLengthMismatch) {
		t.Fatalf("wrong error type: %v", err)
	}

	// Attempt to frame a 65-byte signature (EIP-191/712 size) as SDK Ed25519.
	_, err = envelope.AppendSignature(canonical, envelope.SigAlgoEd25519, eth65)
	if err == nil {
		t.Fatal("AppendSignature accepted 65-byte sig tagged as SigAlgoEd25519 — boundary violation")
	}
}''',
        '''// TestWitness_RejectsEthereumSigLengths was retired in the v6
// migration. This test exercised an encoding-level length check that
// v6 deliberately removed (algorithms like SigAlgoJWZ are
// variable-length). The real security invariant — "the witness
// signature path rejects Ethereum-format 65-byte wallet signatures" —
// is preserved and tested correctly by
// TestWitness_OnlyECDSASignaturesAccepted below, which exercises the
// cryptographic verifier (signatures.VerifyEntry) directly. That is
// the correct layer for the invariant: the verifier is the authority
// on what signatures it accepts, not the framing code.''',
        "retire TestWitness_RejectsEthereumSigLengths",
    ),

    # Retire 7: TestWitness_AlgorithmClassification
    (
        '''func TestWitness_AlgorithmClassification(t *testing.T) {
	// SDK-native: 64-byte
	if envelope.SignatureLengthForAlgorithm(envelope.SigAlgoECDSA) != 64 {
		t.Fatal("SigAlgoECDSA classified as non-64 — witness deserialize depends on this")
	}
	if envelope.SignatureLengthForAlgorithm(envelope.SigAlgoEd25519) != 64 {
		t.Fatal("SigAlgoEd25519 classified as non-64")
	}

	// Wallet-format: 65-byte. These must NEVER be used for witness cosigs,
	// but the classification must still be correct for the dispatch code
	// that routes away from the witness path to make sense.
	if envelope.SignatureLengthForAlgorithm(envelope.SigAlgoEIP191) != 65 {
		t.Fatal("SigAlgoEIP191 classified as non-65")
	}
	if envelope.SignatureLengthForAlgorithm(envelope.SigAlgoEIP712) != 65 {
		t.Fatal("SigAlgoEIP712 classified as non-65")
	}
}''',
        '''// TestWitness_AlgorithmClassification was retired in the v6
// migration. envelope.SignatureLengthForAlgorithm was removed because
// v6 signatures are length-prefixed per-sig in the wire format, making
// algorithm-level length classification meaningless. See
// TestSignatureLengthForAlgorithm_FROZEN retirement comment in
// tests/web3_frozen_test.go for full rationale.''',
        "retire TestWitness_AlgorithmClassification",
    ),
]


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    if not Path("go.mod").exists():
        print("ERROR: no go.mod in cwd — run from repo root (~/workspace/ortholog-sdk)",
              file=sys.stderr)
        return 1

    all_failures = []
    total_applied = 0
    total_skipped = 0

    files_and_edits = [
        ("frozen", Path("tests/web3_frozen_test.go"), FROZEN_RETIRES),
        ("witness_boundary", Path("tests/web3_witness_boundary_test.go"), WITNESS_RETIRES),
    ]

    for label, path, edits in files_and_edits:
        print(f"\n--- {label} ({path}) ---")
        applied, skipped, failures = apply_replacements(label, path, edits)
        total_applied += applied
        total_skipped += skipped
        all_failures.extend(failures)

    print()
    print("=" * 70)
    print(f"Wave 2 retirements: {total_applied} applied, {total_skipped} skipped")
    print("=" * 70)

    if all_failures:
        print("\nFAILURES:", file=sys.stderr)
        for msg in all_failures:
            print(f"  - {msg}", file=sys.stderr)
        return 2

    print("""
Retirements complete. Next step: apply the three hand-written rewrite
files that replace broken tests with v6-native equivalents:

  1. tests/web3_frozen_test_rewrites.go  (4 rewrites)
     Download and REPLACE the corresponding test functions in
     tests/web3_frozen_test.go per the integration instructions.

  2. tests/web3_fuzz_test_rewrites.go  (2 rewrites)
     Same pattern.

  3. tests/web3_entry_signature_test_rewrites.go  (2 rewrites)
     Same pattern.

After all rewrites are integrated:

  go build ./... 2>&1 | head -20                          # should be empty
  go test -count=0 -gcflags='-e' ./tests/ 2>&1 | head     # should have 0 errors
  go test ./... 2>&1 | tail -30                           # runtime check
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())