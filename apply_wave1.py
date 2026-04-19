#!/usr/bin/env python3
"""
apply_wave1.py — Wave 1 of the v6 test migration.

Mechanical, unambiguous edits to four test files. Each edit preserves
test intent 1:1 under v6 semantics — no invariant changes, no fixture
regeneration.

Scope:

  1. tests/phase6_part_c_test.go (8 errors)
       a. Rewrite newOperatorEntryServer helper to read sig fields from
          envelope.Deserialize(meta.CanonicalBytes).Signatures[0] instead
          of the removed sidecar fields meta.SignatureAlgoID and
          meta.SignatureBytes.
       b. Delete TestHTTPEntryFetcher_WithSignature — the test asserted
          v5 sidecar preservation (SignatureAlgoID/SignatureBytes fields),
          which no longer exist on types.EntryWithMetadata. The v6
          equivalent (fetcher preserves canonical bytes including
          signatures inside them) is covered by
          TestHTTPEntryFetcher_Deserializable.

  2. tests/canonical_hash_test.go (2 errors)
       - Delete TestCanonicalHash_SignatureWireRoundTrip — locked a v5
         wire primitive (AppendSignature/StripSignature) with no v6
         equivalent. Replaced by a retirement comment pointing to
         TestCanonicalHash_RoundTrip (existing v6-native test).

  3. tests/web3_e2e_test.go (16 errors in 8 tests)
       - Drop the wire round-trip boilerplate between the sign call and
         the registry.Verify call. The test's actual assertion is
         registry dispatch; the wire round-trip was boilerplate.
         Replace with direct registry.Verify on the signed bytes.

  4. tests/web3_entry_signature_test.go (10 errors in 4 tests)
       - Same treatment for tests #1-#4. Tests #5 (CanonicalHashIndependent
         OfAlgoID) and #6 (WireLengthArithmetic) exercise wire-level
         invariants that transformed under v6 — those go to Wave 3.

Each edit is a literal string replacement against anchors extracted
verbatim from the current file contents. If an anchor is not found, the
script reports what it couldn't find and exits without touching that
file. Idempotent: already-migrated sections skip silently.

Run from the repo root:
    cd ~/workspace/ortholog-sdk
    python3 apply_wave1.py
"""

import sys
from pathlib import Path


# ============================================================================
# Core: apply a list of (old, new, description) replacements idempotently.
# ============================================================================

def apply_replacements(label, path, replacements):
    """
    Apply literal replacements to a file. Each (old, new, description).

    For each replacement:
      - If old appears exactly once: replace it.
      - If old appears zero times AND new appears at least once: skip
        (already applied).
      - If old appears zero times AND new doesn't: FAIL (anchor drifted).
      - If old appears multiple times: FAIL (ambiguous).

    Returns (applied, skipped, failures).
    Writes backup file on success.
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
                f"{label}: anchor appears {old_count} times (expected 1) — "
                f"ambiguous — {desc}"
            )

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
# File 1: tests/phase6_part_c_test.go
# ============================================================================

PHASE6_PART_C_EDITS = [
    # Edit 1.1: Rewrite newOperatorEntryServer's sidecar-field access.
    # Anchor verified against lines 260-269 of current file.
    (
        # OLD — reads removed sidecar fields
        '''		resp := map[string]any{
			"sequence":            seq,
			"canonical_hex":       hex.EncodeToString(meta.CanonicalBytes),
			"log_time_unix_micro": meta.LogTime.UnixMicro(),
			"sig_algo_id":         meta.SignatureAlgoID,
		}
		if len(meta.SignatureBytes) > 0 {
			resp["signature_hex"] = hex.EncodeToString(meta.SignatureBytes)
		}''',
        # NEW — deserializes canonical bytes to extract sig metadata
        '''		resp := map[string]any{
			"sequence":            seq,
			"canonical_hex":       hex.EncodeToString(meta.CanonicalBytes),
			"log_time_unix_micro": meta.LogTime.UnixMicro(),
		}
		// Under v6, signatures live inside the canonical entry bytes.
		// Deserialize to extract the primary signature's algo and bytes
		// for the sidecar JSON fields that the operator's HTTP API still
		// exposes for diagnostics.
		if recovered, derr := envelope.Deserialize(meta.CanonicalBytes); derr == nil && len(recovered.Signatures) > 0 {
			resp["sig_algo_id"] = recovered.Signatures[0].AlgoID
			if len(recovered.Signatures[0].Bytes) > 0 {
				resp["signature_hex"] = hex.EncodeToString(recovered.Signatures[0].Bytes)
			}
		}''',
        "newOperatorEntryServer: extract sig from canonical bytes",
    ),

    # Edit 1.2: Delete TestHTTPEntryFetcher_WithSignature.
    # Anchor verified against lines 404-428 of current file.
    (
        '''func TestHTTPEntryFetcher_WithSignature(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:sig"}, nil)
	sig := make([]byte, 64)
	sig[0] = 0xAB
	entries := map[uint64]*types.EntryWithMetadata{
		1: {
			CanonicalBytes:  envelope.Serialize(entry),
			LogTime:         time.Now(),
			SignatureAlgoID: 1,
			SignatureBytes:  sig,
		},
	}
	ts := newOperatorEntryServer(entries)
	defer ts.Close()

	fetcher := logpkg.NewHTTPEntryFetcher(logpkg.HTTPEntryFetcherConfig{
		BaseURL: ts.URL, LogDID: testLogDID,
	})
	meta, _ := fetcher.Fetch(pos(1))
	if meta.SignatureAlgoID != 1 {
		t.Fatalf("algo: %d", meta.SignatureAlgoID)
	}
	if len(meta.SignatureBytes) != 64 || meta.SignatureBytes[0] != 0xAB {
		t.Fatal("signature bytes mismatch")
	}
}''',
        '''// TestHTTPEntryFetcher_WithSignature was retired in the v6 migration.
// It asserted that EntryWithMetadata.SignatureAlgoID and SignatureBytes
// round-trip through the HTTP fetcher. Those sidecar fields were removed
// in v6 because signatures now live inside CanonicalBytes. The v6-native
// equivalent — "the fetcher preserves canonical bytes byte-for-byte,
// including any signatures inside them" — is covered by
// TestHTTPEntryFetcher_Deserializable above, which deserializes the
// fetched bytes and verifies the resulting entry's full structure.''',
        "retire TestHTTPEntryFetcher_WithSignature (v5 sidecar test)",
    ),
]


# ============================================================================
# File 2: tests/canonical_hash_test.go
# ============================================================================

CANONICAL_HASH_EDITS = [
    # Delete TestCanonicalHash_SignatureWireRoundTrip.
    # Expected at lines 221-242 based on earlier paste.
    (
        '''func TestCanonicalHash_SignatureWireRoundTrip(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:sigtest"}, []byte("signed"))
	canonical := envelope.Serialize(entry)
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	wire := envelope.MustAppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
	gotCanonical, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCanonical, canonical) {
		t.Fatal("stripped canonical bytes don't match")
	}
	if gotAlgo != envelope.SigAlgoECDSA {
		t.Fatalf("algo mismatch")
	}
	if !bytes.Equal(gotSig, fakeSig) {
		t.Fatal("stripped sig doesn't match")
	}
}''',
        '''// TestCanonicalHash_SignatureWireRoundTrip was retired in the v6
// migration. It locked a v5 wire primitive (MustAppendSignature /
// StripSignature over canonical bytes + trailer) that has no v6
// equivalent — signatures now live inside envelope.Serialize(entry)
// rather than as a separable wire trailer. The v6-native round-trip
// invariant ("a signed entry round-trips through Serialize/Deserialize
// preserving its signatures") is covered by TestCanonicalHash_RoundTrip
// at the top of this file.''',
        "retire TestCanonicalHash_SignatureWireRoundTrip (v5 wire primitive)",
    ),
]


# ============================================================================
# File 3: tests/web3_e2e_test.go
# ============================================================================
#
# Eight tests drop the wire round-trip between sign and registry.Verify.
# Each test has unique variables (message/canonicalHash, algorithm constant,
# DID identifier) so each gets its own anchor pair.

WEB3_E2E_EDITS = [
    # Edit 3.1: TestE2E_DIDKey_Ed25519
    (
        '''	// Wire round-trip
	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, message) || gotAlgo != envelope.SigAlgoEd25519 {
		t.Fatal("wire round-trip mismatch")
	}

	// Verify via registry
	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}''',
        '''	// Verify via registry. Under v6 the wire round-trip through
	// AppendSignature/StripSignature no longer exists; the real
	// assertion of this test is that registry dispatch routes to the
	// Ed25519 verifier and accepts a valid signature.
	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, message, sig, envelope.SigAlgoEd25519); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}''',
        "TestE2E_DIDKey_Ed25519: drop wire round-trip",
    ),

    # Edit 3.2: TestE2E_DIDKey_Secp256k1_ECDSA
    (
        '''	// Wire round-trip
	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) E2E — did:key + P-256 + SigAlgoECDSA''',
        '''	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, canonicalHash[:], sig, envelope.SigAlgoECDSA); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) E2E — did:key + P-256 + SigAlgoECDSA''',
        "TestE2E_DIDKey_Secp256k1_ECDSA: drop wire round-trip",
    ),

    # Edit 3.3: TestE2E_DIDKey_P256_ECDSA
    (
        '''	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4)''',
        '''	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, canonicalHash[:], sig, envelope.SigAlgoECDSA); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4)''',
        "TestE2E_DIDKey_P256_ECDSA: drop wire round-trip",
    ),

    # Edit 3.4: TestE2E_DIDPKH_EIP191
    (
        '''	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP191, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) E2E — did:pkh + EIP-712''',
        '''	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, canonicalHash[:], sig, envelope.SigAlgoEIP191); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) E2E — did:pkh + EIP-712''',
        "TestE2E_DIDPKH_EIP191: drop wire round-trip",
    ),

    # Edit 3.5: TestE2E_DIDPKH_EIP712
    (
        '''	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) E2E — did:web + secp256k1 + SigAlgoECDSA''',
        '''	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, canonicalHash[:], sig, envelope.SigAlgoEIP712); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) E2E — did:web + secp256k1 + SigAlgoECDSA''',
        "TestE2E_DIDPKH_EIP712: drop wire round-trip",
    ),

    # Edit 3.6: TestE2E_DIDWeb_Secp256k1_ECDSA
    (
        '''	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 8) E2E — did:web + Ed25519 + SigAlgoEd25519''',
        '''	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, canonicalHash[:], sig, envelope.SigAlgoECDSA); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 8) E2E — did:web + Ed25519 + SigAlgoEd25519''',
        "TestE2E_DIDWeb_Secp256k1_ECDSA: drop wire round-trip",
    ),

    # Edit 3.7: TestE2E_DIDWeb_Ed25519
    (
        '''	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 9) E2E — did:web + secp256k1 recovery''',
        '''	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, message, sig, envelope.SigAlgoEd25519); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 9) E2E — did:web + secp256k1 recovery''',
        "TestE2E_DIDWeb_Ed25519: drop wire round-trip",
    ),

    # Edit 3.8: TestE2E_DIDWeb_RecoveryMethod
    (
        '''	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 10) E2E — unregistered DID method''',
        '''	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(testDestinationDID, resolver)

	if err := registry.Verify(didStr, canonicalHash[:], sig, envelope.SigAlgoEIP712); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 10) E2E — unregistered DID method''',
        "TestE2E_DIDWeb_RecoveryMethod: drop wire round-trip",
    ),
]


# ============================================================================
# File 4: tests/web3_entry_signature_test.go
# ============================================================================
#
# Four tests (#1-#4) drop the wire round-trip before calling the
# primitive verifier. Tests #5 and #6 are Wave 3, not touched here.

WEB3_ENTRY_SIG_EDITS = [
    # Edit 4.1: TestEntrySignature_RoundTrip_ECDSA
    (
        '''	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, canonical) || gotAlgo != envelope.SigAlgoECDSA || !bytes.Equal(gotSig, sig) {
		t.Fatal("wire round-trip mismatch")
	}

	// Signature verifies against the key
	if err := signatures.VerifyEntry(canonicalHash, gotSig, &priv.PublicKey); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}''',
        '''	// Signature verifies against the key. Under v6 the wire round-trip
	// through AppendSignature/StripSignature no longer exists; the
	// primitive-level verifier call IS the assertion of interest here.
	if err := signatures.VerifyEntry(canonicalHash, sig, &priv.PublicKey); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}''',
        "TestEntrySignature_RoundTrip_ECDSA: drop wire round-trip",
    ),

    # Edit 4.2: TestEntrySignature_RoundTrip_Ed25519
    (
        '''	// Wire round-trip
	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, message) || gotAlgo != envelope.SigAlgoEd25519 || !bytes.Equal(gotSig, sig) {
		t.Fatal("wire round-trip mismatch")
	}

	// Signature verifies
	if err := signatures.VerifyEd25519(pub, message, sig); err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
}''',
        '''	// Signature verifies. Under v6 the wire round-trip no longer exists;
	// the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifyEd25519(pub, message, sig); err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
}''',
        "TestEntrySignature_RoundTrip_Ed25519: drop wire round-trip",
    ),

    # Edit 4.3: TestEntrySignature_RoundTrip_EIP191
    (
        '''	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoEIP191, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	_, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if gotAlgo != envelope.SigAlgoEIP191 || len(gotSig) != 65 {
		t.Fatal("wire round-trip mismatch")
	}

	// Verify via address recovery
	if err := signatures.VerifySecp256k1EIP191(addr, canonicalHash, gotSig); err != nil {
		t.Fatalf("VerifySecp256k1EIP191: %v", err)
	}
}''',
        '''	// Verify via address recovery. Under v6 the wire round-trip no longer
	// exists; the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifySecp256k1EIP191(addr, canonicalHash, sig); err != nil {
		t.Fatalf("VerifySecp256k1EIP191: %v", err)
	}
}''',
        "TestEntrySignature_RoundTrip_EIP191: drop wire round-trip",
    ),

    # Edit 4.4: TestEntrySignature_RoundTrip_EIP712
    (
        '''	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	_, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if gotAlgo != envelope.SigAlgoEIP712 {
		t.Fatalf("StripSignature algoID mismatch: got 0x%04x", gotAlgo)
	}

	// Verify via address recovery
	if err := signatures.VerifySecp256k1EIP712(addr, canonicalHash, gotSig); err != nil {
		t.Fatalf("VerifySecp256k1EIP712: %v", err)
	}
}''',
        '''	// Verify via address recovery. Under v6 the wire round-trip no longer
	// exists; the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifySecp256k1EIP712(addr, canonicalHash, sig); err != nil {
		t.Fatalf("VerifySecp256k1EIP712: %v", err)
	}
}''',
        "TestEntrySignature_RoundTrip_EIP712: drop wire round-trip",
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
        ("phase6_part_c", Path("tests/phase6_part_c_test.go"), PHASE6_PART_C_EDITS),
        ("canonical_hash", Path("tests/canonical_hash_test.go"), CANONICAL_HASH_EDITS),
        ("web3_e2e", Path("tests/web3_e2e_test.go"), WEB3_E2E_EDITS),
        ("web3_entry_sig", Path("tests/web3_entry_signature_test.go"), WEB3_ENTRY_SIG_EDITS),
    ]

    for label, path, edits in files_and_edits:
        print(f"\n--- {label} ({path}) ---")
        applied, skipped, failures = apply_replacements(label, path, edits)
        total_applied += applied
        total_skipped += skipped
        all_failures.extend(failures)

    print()
    print("=" * 70)
    print(f"Wave 1 summary: {total_applied} edits applied, {total_skipped} skipped")
    print("=" * 70)

    if all_failures:
        print("\nFAILURES:", file=sys.stderr)
        for msg in all_failures:
            print(f"  - {msg}", file=sys.stderr)
        print("\nAnchor not found: file has drifted from expected source.",
              file=sys.stderr)
        print("Share the file and I'll update the anchors.", file=sys.stderr)
        return 2

    print("\nAll Wave 1 edits succeeded. Next steps:")
    print()
    print("  cd ~/workspace/ortholog-sdk")
    print("  go build ./... 2>&1 | head -20")
    print("      # expected: empty")
    print()
    print("  go test -count=0 -gcflags='-e' ./tests/ 2>&1 | head -80")
    print("      # expected: ~32 remaining errors, all in web3_frozen,")
    print("      # web3_fuzz, web3_witness_boundary, and tests #5/#6 of")
    print("      # web3_entry_signature")
    print()
    print("  go test ./... 2>&1 | tail -30")
    print("      # runtime behavior check for what compiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())