#!/usr/bin/env python3
"""
fix_version_policy_v5_to_v6.py

Updates tests/version_policy_test.go from v5-era assertions to v6.
Preserves the test file's good design: parallel markers, symmetric
read/write coverage, unknown-version error tests, and the table-
driven state-rendering test all stay untouched.

Only the literal protocol version number and test names referring
to v5 change. Tests that are protocol-version-agnostic (V4IsUnknown,
UnknownVersion error cases, StringRendersAllStates) remain unchanged.

Per-test decisions:

  TestVersionPolicy_V5IsGenesisActive
    → TestVersionPolicy_V6IsGenesisActive
    Body: PolicyFor(5) becomes PolicyFor(6). Error messages updated.

  TestVersionPolicy_V4IsUnknown
    Function name and logic unchanged — v4 is still not in the policy
    table under v6. Inline comment "(clean v5 genesis)" updated to
    "(clean v6 genesis)" for historical accuracy.

  TestVersionPolicy_ActiveVersionReturnsFive
    → TestVersionPolicy_ActiveVersionReturnsSix
    Body: expect 6 instead of 5.

  TestVersionPolicy_KnownVersionsContainsV5
    → TestVersionPolicy_KnownVersionsContainsV6
    Body: check for 6 instead of 5.

  TestCheckReadAllowed_V5, TestCheckWriteAllowed_V5
    → _V6 variants
    Body: argument 5 becomes 6.

  TestCheckReadAllowed_UnknownVersion, TestCheckWriteAllowed_UnknownVersion
    Unchanged — argument 99 is still unknown under v6.

  TestVersionState_StringRendersAllStates
    Unchanged — VersionState constants are version-independent.

Run from repo root:
    cd ~/workspace/ortholog-sdk
    python3 fix_version_policy_v5_to_v6.py
"""

import sys
from pathlib import Path

FILE = Path("tests/version_policy_test.go")

# Literal substitutions. Each tuple: (old, new, description).
# Order matters for anchors with overlapping prefixes, but here they
# are all distinct enough that order is irrelevant.
EDITS = [
    # Test 1: V5IsGenesisActive → V6IsGenesisActive
    (
        '''func TestVersionPolicy_V5IsGenesisActive(t *testing.T) {
	t.Parallel()
	state, known := envelope.PolicyFor(5)
	if !known {
		t.Fatal("v5 must be in policy table")
	}
	if state != envelope.VersionActive {
		t.Errorf("v5 state = %s, want ACTIVE", state)
	}
}''',
        '''func TestVersionPolicy_V6IsGenesisActive(t *testing.T) {
	t.Parallel()
	state, known := envelope.PolicyFor(6)
	if !known {
		t.Fatal("v6 must be in policy table")
	}
	if state != envelope.VersionActive {
		t.Errorf("v6 state = %s, want ACTIVE", state)
	}
}''',
        "TestVersionPolicy_V5IsGenesisActive → _V6IsGenesisActive",
    ),

    # Test 2: V4IsUnknown — keep everything, only update comment to
    # reflect v6 genesis.
    (
        '''		t.Error("v4 must NOT be in policy table (clean v5 genesis)")''',
        '''		t.Error("v4 must NOT be in policy table (clean v6 genesis)")''',
        "V4IsUnknown: comment updated for v6 genesis",
    ),

    # Test 3: ActiveVersionReturnsFive → ActiveVersionReturnsSix
    (
        '''func TestVersionPolicy_ActiveVersionReturnsFive(t *testing.T) {
	t.Parallel()
	if got := envelope.ActiveVersion(); got != 5 {
		t.Errorf("ActiveVersion() = %d, want 5", got)
	}
}''',
        '''func TestVersionPolicy_ActiveVersionReturnsSix(t *testing.T) {
	t.Parallel()
	if got := envelope.ActiveVersion(); got != 6 {
		t.Errorf("ActiveVersion() = %d, want 6", got)
	}
}''',
        "ActiveVersionReturnsFive → ActiveVersionReturnsSix",
    ),

    # Test 4: KnownVersionsContainsV5 → KnownVersionsContainsV6
    (
        '''func TestVersionPolicy_KnownVersionsContainsV5(t *testing.T) {
	t.Parallel()
	versions := envelope.KnownVersions()
	found := false
	for _, v := range versions {
		if v == 5 {
			found = true
		}
	}
	if !found {
		t.Error("KnownVersions must contain v5")
	}
}''',
        '''func TestVersionPolicy_KnownVersionsContainsV6(t *testing.T) {
	t.Parallel()
	versions := envelope.KnownVersions()
	found := false
	for _, v := range versions {
		if v == 6 {
			found = true
		}
	}
	if !found {
		t.Error("KnownVersions must contain v6")
	}
}''',
        "KnownVersionsContainsV5 → _V6",
    ),

    # Test 5: CheckReadAllowed_V5 → _V6
    (
        '''func TestCheckReadAllowed_V5(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckReadAllowed(5); err != nil {
		t.Errorf("CheckReadAllowed(v5) = %v, want nil", err)
	}
}''',
        '''func TestCheckReadAllowed_V6(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckReadAllowed(6); err != nil {
		t.Errorf("CheckReadAllowed(v6) = %v, want nil", err)
	}
}''',
        "CheckReadAllowed_V5 → _V6",
    ),

    # Test 6: CheckWriteAllowed_V5 → _V6
    (
        '''func TestCheckWriteAllowed_V5(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckWriteAllowed(5); err != nil {
		t.Errorf("CheckWriteAllowed(v5) = %v, want nil", err)
	}
}''',
        '''func TestCheckWriteAllowed_V6(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckWriteAllowed(6); err != nil {
		t.Errorf("CheckWriteAllowed(v6) = %v, want nil", err)
	}
}''',
        "CheckWriteAllowed_V5 → _V6",
    ),
]


def main() -> int:
    if not FILE.exists():
        print(f"ERROR: {FILE} not found — run from repo root", file=sys.stderr)
        return 1

    original = FILE.read_text()
    updated = original
    applied = 0
    skipped = 0
    failures = []

    for old, new, desc in EDITS:
        old_count = updated.count(old)
        new_count = updated.count(new)

        if old_count == 1:
            updated = updated.replace(old, new, 1)
            applied += 1
            print(f"  applied: {desc}")
        elif old_count == 0 and new_count >= 1:
            skipped += 1
            print(f"  skipped (already applied): {desc}")
        elif old_count == 0:
            failures.append(f"anchor not found — {desc}")
        else:
            failures.append(f"anchor appears {old_count} times — ambiguous — {desc}")

    print(f"\n{applied} applied, {skipped} skipped")

    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for msg in failures:
            print(f"  {msg}", file=sys.stderr)
        return 2

    if updated != original:
        FILE.write_text(updated)
        print(f"\nWrote {FILE} (no backup — file is under git).")

    print("""
Next steps:

  go test ./tests/ -run VersionPolicy 2>&1 | tail -20
      # expected: PASS for all seven tests (V6IsGenesisActive,
      # V4IsUnknown, ActiveVersionReturnsSix, KnownVersionsContainsV6,
      # CheckReadAllowed_V6, CheckReadAllowed_UnknownVersion,
      # CheckWriteAllowed_V6, CheckWriteAllowed_UnknownVersion,
      # VersionState_StringRendersAllStates)

  go test ./... 2>&1 | tail -20
      # expected: ok across every package

Then commit:

  git add tests/version_policy_test.go
  git commit -m "Update version_policy tests from v5 to v6

v6 is the active protocol version; v5 is gone per the hard-cut
migration. Tests asserting v5 semantics now assert v6 semantics.
Version-independent tests (V4IsUnknown, UnknownVersion errors,
VersionState.String rendering) remain unchanged.

No new tests, no removed tests, no changed assertions beyond the
version number literal. The test file's design (parallel markers,
symmetric read/write, table-driven state rendering) is preserved."
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())