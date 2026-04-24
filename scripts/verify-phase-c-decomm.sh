#!/bin/bash
# verify-phase-c-decomm.sh — end-to-end verification of the Phase C
# test decommission. Runs five gates in order; any failure aborts.
#
# Usage:
#   chmod +x scripts/verify-phase-c-decomm.sh
#   ./scripts/verify-phase-c-decomm.sh

set -euo pipefail

# Default to the directory this script lives in's parent (repo root).
# Allows running from any working directory without hard-coding an
# author-specific absolute path.
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO"

say() { printf '\n\033[1;36m══ %s ══\033[0m\n' "$1"; }
ok()  { printf '\033[1;32m  ✓ %s\033[0m\n' "$1"; }
die() { printf '\033[1;31m  ✗ %s\033[0m\n' "$1"; exit 1; }

# ═════════════════════════════════════════════════════════════════
say "Gate 1: structure check"
# ═════════════════════════════════════════════════════════════════

# Migrated file must exist.
[[ -f lifecycle/delegation_key_test.go ]] \
    || die "lifecycle/delegation_key_test.go missing — create File 1"
ok "lifecycle/delegation_key_test.go present"

# Integration file must exist.
[[ -f tests/integration/pre_lifecycle_integration_test.go ]] \
    || die "tests/integration/pre_lifecycle_integration_test.go missing — create File 2"
ok "tests/integration/pre_lifecycle_integration_test.go present"

# Legacy files must be gone.
for legacy in \
    tests/pre_test.go \
    tests/phase6_delegation_key_test.go \
    tests/phase6_part_a_test.go; do
    if [[ -f "$legacy" ]]; then
        die "$legacy still exists — delete with: rm $legacy"
    fi
done
ok "all legacy test files deleted"

# ═════════════════════════════════════════════════════════════════
say "Gate 2: mutation-audit constants locked to production"
# ═════════════════════════════════════════════════════════════════

# Gate 2a (legacy): PRE gates true.
PRE_GO="crypto/artifact/pre.go"
if grep -E 'muEnable[A-Za-z]+\s*=\s*false' "$PRE_GO" > /dev/null; then
    grep -nE 'muEnable[A-Za-z]+\s*=\s*false' "$PRE_GO"
    die "mutation audit constant set to false in $PRE_GO — restore before shipping"
fi
ok "all muEnable* constants are true in $PRE_GO"

# Gate 2b (new): every muEnable* in the tree is true.
if grep -rnE 'muEnable[A-Za-z]+\s*=\s*false' --include='*.go' \
       --exclude-dir=cmd . > /dev/null 2>&1; then
    grep -rnE 'muEnable[A-Za-z]+\s*=\s*false' --include='*.go' \
         --exclude-dir=cmd .
    die "mutation audit constant set to false somewhere in the tree"
fi
ok "no muEnable*=false anywhere in the production tree"

# Gate 2c (Group 4): mutation-audit registries validate clean.
# Reads every *.mutation-audit.yaml and verifies that each declared
# gate constant exists in the named source file and every declared
# binding test function exists in the named package's test files.
# Catches drift in either direction: a registry pointing at a
# deleted constant, or a gate declared in source without a registry
# entry.
if ! go run ./cmd/audit-v775 mutation --validate-registries 2>&1; then
    die "mutation-audit registry drift — run 'make audit-v775-list' to diagnose"
fi
ok "all *.mutation-audit.yaml registries validate clean"

# ═════════════════════════════════════════════════════════════════
say "Gate 3: compile-clean across the whole tree"
# ═════════════════════════════════════════════════════════════════

go clean -cache >/dev/null 2>&1 || true
if ! go build ./... 2>&1; then
    die "go build failed — see output above"
fi
ok "go build ./... clean"

if ! go vet ./... 2>&1; then
    die "go vet failed — see output above"
fi
ok "go vet ./... clean"

# ═════════════════════════════════════════════════════════════════
say "Gate 4: per-package test gates (phase preservation)"
# ═════════════════════════════════════════════════════════════════

# Phase A: VSS primitive.
if ! go test ./core/vss/... -race -count=1 >/dev/null; then
    die "core/vss tests FAILED — Phase A regression"
fi
ok "core/vss (Phase A) green"

# Phase B: escrow.
if ! go test ./crypto/escrow/... -race -count=1 >/dev/null; then
    die "crypto/escrow tests FAILED — Phase B regression"
fi
ok "crypto/escrow (Phase B) green"

# Phase C: artifact.
if ! go test ./crypto/artifact/... -race -count=1 >/dev/null; then
    die "crypto/artifact tests FAILED — Phase C regression"
fi
ok "crypto/artifact (Phase C core) green"

# Phase C: lifecycle (including the migrated delegation-key test).
if ! go test ./lifecycle/... -race -count=1 >/dev/null; then
    die "lifecycle tests FAILED — migrated delegation test may have API issue"
fi
ok "lifecycle (incl. migrated TestUnwrapDelegationKey_Roundtrip) green"

# Integration: cross-package.
if ! go test ./tests/integration/... -race -count=1 >/dev/null; then
    die "tests/integration FAILED — migrated integration tests have API issue"
fi
ok "tests/integration green"

# ═════════════════════════════════════════════════════════════════
say "Gate 5: full-tree test green"
# ═════════════════════════════════════════════════════════════════

if ! go test ./... -race -count=1 >/dev/null; then
    printf '\n\033[1;31mFull-tree test output:\033[0m\n'
    go test ./... -race -count=1
    die "full tree FAILED"
fi
ok "go test ./... -race -count=1  all green"

# ═════════════════════════════════════════════════════════════════
say "Phase C decommission verification complete"
# ═════════════════════════════════════════════════════════════════

printf '\n'
ok "Files moved:"
printf '    lifecycle/delegation_key_test.go               (was: tests/phase6_delegation_key_test.go)\n'
printf '    tests/integration/pre_lifecycle_integration_test.go\n'
printf '                                                   (was: tests/phase6_*.go — consolidated)\n'
ok "Files deleted:"
printf '    tests/pre_test.go\n'
printf '    tests/phase6_delegation_key_test.go\n'
printf '    tests/phase6_part_a_test.go\n'
ok "Ready for Phase C closure — run Mutation 4 (DST) next."