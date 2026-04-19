#!/usr/bin/env python3
"""
Apply v6 VerifyEntry migration to tests/destination_binding_test.go.

Does exactly two edits, each idempotent (safe to re-run):

  1. In TestVerifyEntry_CrossDestination_Rejected: insert the signature
     attachment block after the SignEntry block, and change the
     VerifyEntry call from three-arg to one-arg.

  2. Same edits in TestVerifyEntry_SameDestination_Accepted.

Uses literal string replacement — no regex, no hunk math, no diff parsing.
If the expected source isn't found (file already migrated, or the tests
have drifted from my assumptions), the script reports what it couldn't
find and exits non-zero without touching the file.

Run from the repo root:
    python3 apply_dest_binding_v6.py
"""

import sys
from pathlib import Path


# Path relative to cwd. Run from ~/workspace/ortholog-sdk.
FILE = Path("tests/destination_binding_test.go")


# ----------------------------------------------------------------------------
# Edit 1 — TestVerifyEntry_CrossDestination_Rejected
# ----------------------------------------------------------------------------
# Anchor: the three-arg VerifyEntry call that must become one-arg.
CROSS_OLD_CALL = '\terr = registryForB.VerifyEntry(entry, sig, envelope.SigAlgoECDSA)\n'
CROSS_NEW_CALL = '\terr = registryForB.VerifyEntry(entry)\n'

# Anchor: the line where we insert the signature-attachment block.
# We insert BEFORE the registry construction line.
CROSS_REGISTRY_LINE = '\tregistryForB := did.DefaultVerifierRegistry(destB, panicResolver{})\n'

# The block to insert before the registry line.
CROSS_ATTACH_BLOCK = (
    '\t// Attach the signature to the entry under v6 semantics (signatures\n'
    '\t// live inside entry.Signatures; the registry reads them from there).\n'
    '\tentry.Signatures = []envelope.Signature{{\n'
    '\t\tSignerDID: kp.DID,\n'
    '\t\tAlgoID:    envelope.SigAlgoECDSA,\n'
    '\t\tBytes:     sig,\n'
    '\t}}\n'
    '\tif err := entry.Validate(); err != nil {\n'
    '\t\tt.Fatalf("Validate signed entry: %v", err)\n'
    '\t}\n'
    '\n'
)


# ----------------------------------------------------------------------------
# Edit 2 — TestVerifyEntry_SameDestination_Accepted
# ----------------------------------------------------------------------------
SAME_OLD_CALL = '\tif err := registry.VerifyEntry(entry, sig, envelope.SigAlgoECDSA); err != nil {\n'
SAME_NEW_CALL = '\tif err := registry.VerifyEntry(entry); err != nil {\n'

SAME_REGISTRY_LINE = '\tregistry := did.DefaultVerifierRegistry(dest, panicResolver{})\n'

SAME_ATTACH_BLOCK = (
    '\t// Attach the signature to the entry under v6 semantics.\n'
    '\tentry.Signatures = []envelope.Signature{{\n'
    '\t\tSignerDID: kp.DID,\n'
    '\t\tAlgoID:    envelope.SigAlgoECDSA,\n'
    '\t\tBytes:     sig,\n'
    '\t}}\n'
    '\tif err := entry.Validate(); err != nil {\n'
    '\t\tt.Fatalf("Validate signed entry: %v", err)\n'
    '\t}\n'
    '\n'
)


def main() -> int:
    if not FILE.exists():
        print(f"ERROR: {FILE} not found. Run from repo root (~/workspace/ortholog-sdk).",
              file=sys.stderr)
        return 1

    original = FILE.read_text()
    updated = original

    # Count occurrences before any edit to distinguish
    # "already-migrated" from "source drifted."
    cross_calls = updated.count(CROSS_OLD_CALL)
    same_calls = updated.count(SAME_OLD_CALL)
    cross_registries = updated.count(CROSS_REGISTRY_LINE)
    same_registries = updated.count(SAME_REGISTRY_LINE)

    # Sanity: each anchor should appear exactly once in the original file.
    # If zero, the edit is probably already applied. If more than one, the
    # file has drifted and a literal replace would be ambiguous.
    issues = []
    if cross_registries == 0:
        issues.append(f"CROSS_REGISTRY_LINE not found (expected 1 occurrence)")
    elif cross_registries > 1:
        issues.append(
            f"CROSS_REGISTRY_LINE found {cross_registries} times (expected 1) — "
            f"ambiguous, refusing to edit")

    if same_registries == 0:
        issues.append(f"SAME_REGISTRY_LINE not found (expected 1 occurrence)")
    elif same_registries > 1:
        issues.append(
            f"SAME_REGISTRY_LINE found {same_registries} times (expected 1) — "
            f"ambiguous, refusing to edit")

    if issues:
        print("Cannot safely apply edits:", file=sys.stderr)
        for msg in issues:
            print(f"  - {msg}", file=sys.stderr)
        return 2

    # Edit 1: Cross-destination test.
    if cross_calls == 1:
        # Insert attachment block before the registry line, then rewrite the
        # VerifyEntry call.
        updated = updated.replace(
            CROSS_REGISTRY_LINE,
            CROSS_ATTACH_BLOCK + CROSS_REGISTRY_LINE,
            1,
        )
        updated = updated.replace(CROSS_OLD_CALL, CROSS_NEW_CALL, 1)
        print("Edit 1 (CrossDestination): applied.")
    elif cross_calls == 0:
        print("Edit 1 (CrossDestination): already migrated, skipping.")
    else:
        print(f"ERROR: CROSS_OLD_CALL found {cross_calls} times (expected 0 or 1).",
              file=sys.stderr)
        return 3

    # Edit 2: Same-destination test.
    if same_calls == 1:
        updated = updated.replace(
            SAME_REGISTRY_LINE,
            SAME_ATTACH_BLOCK + SAME_REGISTRY_LINE,
            1,
        )
        updated = updated.replace(SAME_OLD_CALL, SAME_NEW_CALL, 1)
        print("Edit 2 (SameDestination): applied.")
    elif same_calls == 0:
        print("Edit 2 (SameDestination): already migrated, skipping.")
    else:
        print(f"ERROR: SAME_OLD_CALL found {same_calls} times (expected 0 or 1).",
              file=sys.stderr)
        return 3

    if updated == original:
        print("No changes needed.")
        return 0

    # Backup, then write.
    backup = FILE.with_suffix(FILE.suffix + ".bak")
    backup.write_text(original)
    FILE.write_text(updated)
    print(f"Wrote {FILE}. Backup at {backup}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())