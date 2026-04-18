#!/bin/bash
# apply-phase2.sh
# Applies the destination-binding refactor: replaces four SDK files with
# their destination-aware versions, renames verifier-registry callers
# flagged by the build, and runs verification.

set -euo pipefail

SDK="${SDK:-$HOME/workspace/ortholog-sdk}"
SRC="${SRC:-$HOME/Downloads/files/phase2}"

echo "=== 0. Sanity check source tree ==="
for f in \
    "$SRC/core/envelope/serialize.go" \
    "$SRC/builder/entry_builders.go" \
    "$SRC/did/verifier_registry.go" \
    "$SRC/exchange/auth/signed_request.go" ; do
    if [ ! -f "$f" ]; then
        echo "MISSING: $f"
        echo "Download the phase2/ tree and place at $SRC before running."
        exit 1
    fi
done
echo "  - All four files present."

echo ""
echo "=== 1. Back up existing files ==="
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="$SDK/.phase2-backup-$STAMP"
mkdir -p "$BACKUP"/{core/envelope,builder,did,exchange/auth}
cp "$SDK/core/envelope/serialize.go"       "$BACKUP/core/envelope/"
cp "$SDK/builder/entry_builders.go"        "$BACKUP/builder/"
cp "$SDK/did/verifier_registry.go"         "$BACKUP/did/"
cp "$SDK/exchange/auth/signed_request.go"  "$BACKUP/exchange/auth/"
echo "  - Backed up to $BACKUP"

echo ""
echo "=== 2. Replace the four files ==="
cp "$SRC/core/envelope/serialize.go"       "$SDK/core/envelope/serialize.go"
cp "$SRC/builder/entry_builders.go"        "$SDK/builder/entry_builders.go"
cp "$SRC/did/verifier_registry.go"         "$SDK/did/verifier_registry.go"
cp "$SRC/exchange/auth/signed_request.go"  "$SDK/exchange/auth/signed_request.go"
echo "  - Installed new serialize.go, entry_builders.go, verifier_registry.go, signed_request.go"

echo ""
echo "=== 3. Build the envelope package first (schema layer) ==="
cd "$SDK"
if ! go build ./core/envelope/ 2>&1 ; then
    echo ""
    echo "FAIL: core/envelope/ build broke. Restoring from backup."
    cp "$BACKUP/core/envelope/serialize.go" "$SDK/core/envelope/serialize.go"
    exit 1
fi
echo "  - core/envelope/ OK"

echo ""
echo "=== 4. Build builder + did + exchange/auth ==="
go build ./builder/ ./did/ ./exchange/auth/ 2>&1 | head -50 || true

echo ""
echo "=== 5. Full module build ==="
go build ./... 2>&1 | head -60 || true

echo ""
echo "=== 6. Run tests (expect canonical-hash-fixture failures) ==="
go test -count=1 ./... 2>&1 | tail -40 || true

echo ""
echo "=== Done. ==="
echo ""
echo "Expected outcomes:"
echo "  ✓ core/envelope/ builds clean"
echo "  ✗ Callers of NewVerifierRegistry() and DefaultVerifierRegistry(resolver)"
echo "    fail to compile — they now require a destinationDID as first arg."
echo "    These are in the SDK's own tests and in judicial-network."
echo "  ✗ Tests with frozen canonical-hash fixtures fail — the hash now"
echo "    commits to Destination, so old hex values are stale."
echo "    These are expected breakages that lock the new scheme."
echo ""
echo "Next actions:"
echo "  A. Thread destinationDID through every registry construction in tests/"
echo "     (search: grep -rn 'NewVerifierRegistry\\|DefaultVerifierRegistry' tests/)"
echo "  B. Regenerate canonical-hash fixtures:"
echo "       go test -run=TestEntrySerialize_KnownVector ./tests/ -v"
echo "       -> paste the 'got' hex back into the test's 'want' constant"
echo "  C. Update the parked tests:"
echo "       mv tests/destination_binding_test.go.pending tests/destination_binding_test.go"
echo "       mv tests/exchange_auth_test.go.pending      tests/exchange_auth_test.go"
echo "       -> fix Entry struct literals to use Header{Destination: ...} shape"
echo "  D. Thread Destination through every Build* call site in judicial-network"
echo "       cd /tmp/consumer && grep -rn 'builder\\.Build' --include='*.go'"
echo ""
echo "Rollback if needed:"
echo "  cp $BACKUP/core/envelope/serialize.go $SDK/core/envelope/"
echo "  cp $BACKUP/builder/entry_builders.go  $SDK/builder/"
echo "  cp $BACKUP/did/verifier_registry.go   $SDK/did/"
echo "  cp $BACKUP/exchange/auth/signed_request.go $SDK/exchange/auth/"
