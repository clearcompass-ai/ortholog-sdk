#!/bin/bash
# apply-path-b.sh
# Applies Path B — commits fully to the strict-forever Reserve(ctx, nonce)
# NonceStore interface. Deletes the old CheckAndStore interface, fixes the
# one call site, routes EventTime access through entry.Header, and disables
# forward-looking tests that depend on patches not yet applied.

set -euo pipefail

SDK="${SDK:-$HOME/workspace/ortholog-sdk}"
cd "$SDK"

echo "=== 1. Fix freshness.go: entry.EventTime -> entry.Header.EventTime ==="
sed -i '' 's/entry\.EventTime/entry.Header.EventTime/g' exchange/policy/freshness.go

echo "=== 2. Delete old NonceStore interface + update call site ==="

python3 <<'PYEOF'
import re
import sys

path = 'exchange/auth/signed_request.go'
with open(path) as f:
    src = f.read()

# Match the old NonceStore section: separator, header, separator, blank,
# doc comments, type declaration, method, closing brace, optional blank.
pattern = re.compile(
    r'// -{20,}\n'
    r'// 5\) NonceStore interface\n'
    r'// -{20,}\n'
    r'\n'
    r'(?://[^\n]*\n)+'
    r'type NonceStore interface \{\n'
    r'\tCheckAndStore\([^)]*\) error\n'
    r'\}\n'
    r'\n?',
    re.MULTILINE
)
new_src, n_del = pattern.subn('', src)
if n_del != 1:
    print(f"ERROR: expected 1 NonceStore-block deletion, got {n_del}", file=sys.stderr)
    print("Manual cleanup required. The block is identified by:", file=sys.stderr)
    print("  - Comment header: '// 5) NonceStore interface'", file=sys.stderr)
    print("  - Interface: 'type NonceStore interface { CheckAndStore(...) error }'", file=sys.stderr)
    sys.exit(1)
print(f"  - Deleted old NonceStore interface block ({n_del} match)")

# Replace the call site.
old_call = 'nonces.CheckAndStore(env.DID, env.Nonce, env.ExpiresAt.Add(skew))'
new_call = 'nonces.Reserve(context.Background(), env.Nonce)'
if old_call not in new_src:
    print(f"ERROR: could not find call site '{old_call}'", file=sys.stderr)
    print("Manual cleanup required. Find the CheckAndStore call and rewrite.", file=sys.stderr)
    sys.exit(1)
new_src = new_src.replace(old_call, new_call)
print("  - Rewrote CheckAndStore call site to Reserve(context.Background(), ...)")

# Ensure 'context' is imported. If there's an import block, add inside it.
if '"context"' not in new_src:
    if 'import (' in new_src:
        new_src = re.sub(
            r'^import \(\n',
            'import (\n\t"context"\n',
            new_src,
            count=1,
            flags=re.MULTILINE,
        )
        print("  - Added \"context\" to import block")
    else:
        print("WARNING: 'context' not imported and no import block found.", file=sys.stderr)
        print("  Add 'import \"context\"' manually.", file=sys.stderr)

with open(path, 'w') as f:
    f.write(new_src)
print("  - Wrote updated signed_request.go")
PYEOF

echo ""
echo "=== 3. Disable forward-looking tests that require unapplied patches ==="
# destination_binding_test.go references Entry.Destination — not added yet.
# exchange_auth_test.go references VerifyRequestOptions.Nonces/ValidityWindow — not added yet.
# Renaming to .pending removes them from the go test set without deleting them.

for f in destination_binding_test.go exchange_auth_test.go; do
    if [ -f "tests/$f" ]; then
        mv "tests/$f" "tests/$f.pending"
        echo "  - Parked tests/$f as tests/$f.pending"
    fi
done

echo ""
echo "=== 4. Overwrite freshness_policy_test.go with correct struct shape ==="
# The freshness_policy_test.go we shipped used flat envelope.Entry literals.
# The real Entry wraps everything in Header. Replace with the rewritten file.
# Before running this script, the rewritten file is expected at:
#   $HOME/Downloads/files/freshness_policy_test.go
# (You download it from the outputs in this conversation.)

REWRITE_SRC="$HOME/Downloads/files/freshness_policy_test.go"
if [ -f "$REWRITE_SRC" ]; then
    cp "$REWRITE_SRC" tests/freshness_policy_test.go
    echo "  - Replaced tests/freshness_policy_test.go with Header-aware version"
else
    echo "  - SKIPPING freshness_policy_test.go replace (missing $REWRITE_SRC)"
    echo "    Download the new freshness_policy_test.go and re-run, or copy manually."
fi

echo ""
echo "=== 5. Build check ==="
go build ./core/envelope/ ./exchange/policy/ ./exchange/auth/ 2>&1 | head -20 || true

echo ""
echo "=== 6. Test build check (freshness tests only) ==="
go test -count=1 -run=TestFreshness ./tests/ 2>&1 | tail -20 || true

echo ""
echo "=== Done. ==="
echo ""
echo "If the build and the TestFreshness run are green, Path B is fully applied."
echo ""
echo "When you're ready to apply the destination-binding patches:"
echo "  1. Apply PATCHES-destination-binding.md to entry.go / serialize.go /"
echo "     entry_builders.go / verifier_registry.go / signed_request.go"
echo "  2. Re-enable the parked tests:"
echo "       mv tests/destination_binding_test.go.pending tests/destination_binding_test.go"
echo "       mv tests/exchange_auth_test.go.pending      tests/exchange_auth_test.go"
echo "  3. Fix Entry struct literals in those tests to use Header{...} shape"
echo "  4. go test ./tests/..."