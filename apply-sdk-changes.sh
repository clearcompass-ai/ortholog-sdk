#!/usr/bin/env bash
set -euo pipefail

# Paths
SRC="/Users/anil/Downloads/ortholog-sdk-v5-wave1"
DST="/Users/anil/workspace/ortholog-sdk"

# Preflight
if [ ! -d "$SRC" ]; then
  echo "ERROR: source not found: $SRC" >&2
  exit 1
fi
if [ ! -d "$DST" ]; then
  echo "ERROR: destination not found: $DST" >&2
  exit 1
fi
if [ ! -f "$DST/go.mod" ]; then
  echo "ERROR: $DST does not look like the SDK repo (no go.mod)" >&2
  exit 1
fi

echo "==> Backing up files that will be replaced"
BACKUP="$DST/.wave1-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP/core/envelope" "$BACKUP"
for f in core/envelope/api.go core/envelope/control_header.go core/envelope/serialize.go CHANGES.md; do
  if [ -f "$DST/$f" ]; then
    cp "$DST/$f" "$BACKUP/$f"
    echo "    backed up: $f"
  fi
done

echo "==> Overlaying core/envelope/ (4 replaced, 1 new)"
cp "$SRC/core/envelope/api.go"             "$DST/core/envelope/api.go"
cp "$SRC/core/envelope/control_header.go"  "$DST/core/envelope/control_header.go"
cp "$SRC/core/envelope/serialize.go"       "$DST/core/envelope/serialize.go"
cp "$SRC/core/envelope/canonical_hash.go"  "$DST/core/envelope/canonical_hash.go"   # NEW
cp "$SRC/core/envelope/version_policy.go"  "$DST/core/envelope/version_policy.go"   # NEW

echo "==> Adding Wave 1 tests"
cp "$SRC/tests/version_policy_test.go"     "$DST/tests/version_policy_test.go"
cp "$SRC/tests/envelope_serialize_test.go" "$DST/tests/envelope_serialize_test.go"

echo "==> Updating CHANGES.md"
cp "$SRC/CHANGES.md" "$DST/CHANGES.md"

echo "==> Verifying"
cd "$DST"
go vet ./core/envelope/... ./tests/ || { echo "vet failed"; exit 1; }
go build ./... || { echo "build failed — downstream callers likely need updates"; exit 1; }

echo ""
echo "✓ Wave 1 files in place"
echo "  Backup at: $BACKUP"
echo ""
echo "Next: run tests"
echo "  go test ./tests/ -run 'TestVersion|TestV5|TestV4|TestPreamble|TestCanonicalHash_Covers|TestCanonicalHash_Deterministic|TestAuthoritySkipUnaffected|TestMaxCanonicalBytes_Rejected|TestDeserialize_Rejects|TestCheckReadAllowed|TestCheckWriteAllowed|TestOverride_|TestErrorDispatch' -race -count=1"