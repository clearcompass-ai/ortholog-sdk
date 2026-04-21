#!/usr/bin/env bash
#
# coverage_audit.sh v2 — evidence-based coverage audit
#
# FIXES FROM v1:
#   1. Workspace with multiple modules: `go list -m` returns >1 line.
#      Now we parse go.mod directly for THIS module's path.
#   2. sed substitution with newlined variable produced malformed
#      patterns. Now we use pure shell string ops (${var#prefix}).
#   3. Awk dedup emitted trailing whitespace that `go tool cover`
#      rejected. Now the merge step uses Python with strict format.
#
# USAGE:
#   cd ~/workspace/ortholog-sdk
#   bash /path/to/coverage_audit.sh

set -eu

# ---------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------

if [ ! -f go.mod ]; then
  echo "ERROR: run from repo root (go.mod not found)" >&2
  exit 1
fi

OUT_DIR="coverage"
RAW_DIR="$OUT_DIR/raw"
REPORT_DIR="$OUT_DIR/report"

rm -rf "$OUT_DIR"
mkdir -p "$RAW_DIR" "$REPORT_DIR"

# Extract THIS module's path from go.mod directly. Bypasses workspace
# weirdness where `go list -m` may return multiple modules.
MODULE=$(awk '/^module / { print $2; exit }' go.mod)
echo "Module: $MODULE"
echo

# Production packages for THIS module only.
PROD_PACKAGES=$(go list ./... 2>/dev/null \
  | grep "^$MODULE" \
  | grep -v "^$MODULE/tests$" \
  | grep -v "^$MODULE/cmd/" \
  | sort)

TEST_PACKAGES=$(go list ./... 2>/dev/null | grep "^$MODULE/tests$" || true)

PROD_COUNT=$(printf '%s\n' "$PROD_PACKAGES" | grep -c . || echo 0)

echo "=== Production packages ($PROD_COUNT) ==="
printf '%s\n' "$PROD_PACKAGES"
echo

echo "=== Test packages ==="
printf '%s\n' "$TEST_PACKAGES"
echo

# ---------------------------------------------------------------------
# Method (a): per-package self-tests
# ---------------------------------------------------------------------

echo "=== Method (a): per-package self-tests ==="

PER_PKG_FILES=""
while IFS= read -r pkg; do
  [ -z "$pkg" ] && continue
  # Slug via pure shell: strip module prefix, replace / with -
  pkg_rel="${pkg#$MODULE/}"
  [ "$pkg_rel" = "$pkg" ] && pkg_rel="root"
  pkg_slug=$(printf '%s' "$pkg_rel" | tr '/' '-')
  out="$RAW_DIR/self-$pkg_slug.cov"
  if go test -count=1 -coverprofile="$out" -covermode=atomic "$pkg" >/dev/null 2>&1; then
    if [ -s "$out" ] && [ "$(wc -l < "$out" | tr -d ' ')" -gt 1 ]; then
      lines=$(wc -l < "$out" | tr -d ' ')
      printf "  %-60s %6s lines\n" "$pkg" "$lines"
      PER_PKG_FILES="$PER_PKG_FILES $out"
    else
      rm -f "$out"
    fi
  fi
done <<< "$PROD_PACKAGES"
echo

# ---------------------------------------------------------------------
# Method (b): tests/ driving all production packages
# ---------------------------------------------------------------------

echo "=== Method (b): tests/ driving all production packages ==="

COVERPKG=$(printf '%s' "$PROD_PACKAGES" | tr '\n' ',' | sed 's/,$//')

TESTS_DRIVING="$RAW_DIR/tests-driving.cov"
if go test -count=1 -coverprofile="$TESTS_DRIVING" -covermode=atomic \
    -coverpkg="$COVERPKG" ./tests/ >/dev/null 2>&1; then
  if [ -s "$TESTS_DRIVING" ]; then
    lines=$(wc -l < "$TESTS_DRIVING" | tr -d ' ')
    printf "  %-60s %6s lines\n" "tests/ driving production" "$lines"
  fi
else
  echo "  WARNING: tests/ run failed — run 'go test ./tests/' separately"
fi
echo

# ---------------------------------------------------------------------
# Method (c): merged coverage
# ---------------------------------------------------------------------

echo "=== Method (c): merged coverage ==="

MERGED="$RAW_DIR/merged.cov"

python3 - "$MERGED" $PER_PKG_FILES "$TESTS_DRIVING" <<'PY'
import sys, os

out_path = sys.argv[1]
in_paths = sys.argv[2:]

mode = None
blocks = {}  # (loc, stmts) -> max count

for p in in_paths:
    if not os.path.isfile(p) or os.path.getsize(p) == 0:
        continue
    with open(p) as f:
        for line in f:
            line = line.rstrip('\n').rstrip()
            if not line:
                continue
            if line.startswith('mode:'):
                if mode is None:
                    mode = line
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            loc, stmts, count = parts
            try:
                stmts_i = int(stmts)
                count_i = int(count)
            except ValueError:
                continue
            key = (loc, stmts_i)
            if key not in blocks or blocks[key] < count_i:
                blocks[key] = count_i

with open(out_path, 'w') as out:
    out.write((mode or 'mode: atomic') + '\n')
    for (loc, stmts), count in sorted(blocks.items()):
        out.write(f'{loc} {stmts} {count}\n')

print(f'  merged: {len(blocks)} unique coverage blocks')
PY
echo

# ---------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------

echo "=== Analyzing merged coverage ==="

FUNC_REPORT="$REPORT_DIR/per-function.txt"
if ! go tool cover -func="$MERGED" > "$FUNC_REPORT" 2>"$REPORT_DIR/cover-errors.log"; then
  echo "  ERROR: go tool cover -func failed"
  echo "  see $REPORT_DIR/cover-errors.log"
  cat "$REPORT_DIR/cover-errors.log"
  exit 1
fi

UNTESTED="$REPORT_DIR/untested-functions.txt"
awk '$NF == "0.0%" && !/^total:/ { print }' "$FUNC_REPORT" > "$UNTESTED"

UNTESTED_COUNT=$(wc -l < "$UNTESTED" | tr -d ' ')
TOTAL_FUNCS=$(grep -v '^total:' "$FUNC_REPORT" | wc -l | tr -d ' ')

echo "  total functions: $TOTAL_FUNCS"
echo "  untested (0%):   $UNTESTED_COUNT"
echo

# ---------------------------------------------------------------------
# Per-package roll-up
# ---------------------------------------------------------------------

PER_PKG_TSV="$REPORT_DIR/per-package.tsv"
python3 - "$MERGED" "$UNTESTED" "$PER_PKG_TSV" "$MODULE" <<'PY'
import sys
from collections import defaultdict

merged_path, untested_path, out_path, module = sys.argv[1:5]

total_stmts = defaultdict(int)
covered_stmts = defaultdict(int)

with open(merged_path) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('mode:'):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        loc, stmts, count = parts
        stmts, count = int(stmts), int(count)
        file_path = loc.split(':')[0]
        dir_path = '/'.join(file_path.split('/')[:-1])
        pkg = dir_path.replace(module + '/', '') if dir_path.startswith(module) else dir_path
        total_stmts[pkg] += stmts
        if count > 0:
            covered_stmts[pkg] += stmts

untested_by_pkg = defaultdict(int)
with open(untested_path) as f:
    for line in f:
        parts = line.split()
        if not parts:
            continue
        file_path = parts[0].split(':')[0]
        dir_path = '/'.join(file_path.split('/')[:-1])
        pkg = dir_path.replace(module + '/', '') if dir_path.startswith(module) else dir_path
        untested_by_pkg[pkg] += 1

rows = []
for pkg in sorted(total_stmts):
    tot = total_stmts[pkg]
    cov = covered_stmts.get(pkg, 0)
    pct = 100.0 * cov / tot if tot > 0 else 0.0
    untested = untested_by_pkg.get(pkg, 0)
    rows.append((pkg, cov, tot, pct, untested))

rows.sort(key=lambda r: r[3])

with open(out_path, 'w') as out:
    out.write('package\tcovered\ttotal\tpct\tuntested_fns\n')
    for pkg, cov, tot, pct, untested in rows:
        out.write(f'{pkg}\t{cov}\t{tot}\t{pct:.1f}\t{untested}\n')

print()
print('=== Per-package coverage (worst first) ===')
print(f'{"package":<45} {"cov":>7} {"tot":>7} {"pct":>7} {"untested":>9}')
print('─' * 80)
for pkg, cov, tot, pct, untested in rows:
    print(f'{pkg:<45} {cov:>7} {tot:>7} {pct:>6.1f}% {untested:>9}')
PY
echo

# ---------------------------------------------------------------------
# Call-site audit
# ---------------------------------------------------------------------

echo "=== Call-site audit (grepping each 0% function) ==="

CALL_AUDIT="$REPORT_DIR/call-site-audit.txt"
{
  echo "# Call-site audit for 0% functions"
  echo "# ZERO refs = dead code; non-zero = unexercised path"
  echo ""
  printf "%-60s %-32s %10s %10s %10s\n" "LOCATION" "FUNCTION" "PROD_REFS" "TEST_REFS" "TOTAL"
  echo "────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    loc=$(printf '%s' "$line" | awk '{print $1}')
    fn=$(printf '%s' "$line" | awk '{print $2}')
    total_refs=$(grep -rE "\\b$fn\\b" --include='*.go' . 2>/dev/null | wc -l | tr -d ' ')
    test_refs=$(grep -rE "\\b$fn\\b" --include='*_test.go' . 2>/dev/null | wc -l | tr -d ' ')
    prod_refs=$((total_refs - test_refs))
    printf "%-60s %-32s %10d %10d %10d\n" "$loc" "$fn" "$prod_refs" "$test_refs" "$total_refs"
  done < "$UNTESTED"
} > "$CALL_AUDIT"

echo "  wrote $CALL_AUDIT"
echo

# ---------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------

PRIO_MD="$REPORT_DIR/gaps-by-priority.md"
python3 - "$UNTESTED" "$CALL_AUDIT" "$PRIO_MD" <<'PY'
import sys, re

untested_path, audit_path, out_path = sys.argv[1:4]

refs = {}
with open(audit_path) as f:
    for line in f:
        if not line.strip() or line.startswith('#') or line.startswith('─') or line.startswith('LOCATION'):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            fn, prod, test = parts[1], int(parts[2]), int(parts[3])
            refs[fn] = (prod, test)
        except (ValueError, IndexError):
            pass

def func_loc(file_path, func_name):
    try:
        lines = open(file_path).read().splitlines()
    except FileNotFoundError:
        return 1
    pat = re.compile(r'^\s*func\s+(\([^)]*\)\s+)?' + re.escape(func_name) + r'\b')
    start = None
    for i, line in enumerate(lines):
        if pat.match(line):
            start = i
            break
    if start is None:
        return 1
    depth, opened = 0, False
    for i in range(start, len(lines)):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                opened = True
            elif ch == '}':
                depth -= 1
                if opened and depth == 0:
                    return i - start + 1
    return max(1, len(lines) - start)

entries = []
with open(untested_path) as f:
    for line in f:
        parts = line.split()
        if len(parts) < 2:
            continue
        loc, fn = parts[0], parts[1]
        path = loc.split(':')[0]
        loc_count = func_loc(path, fn)
        prod, test = refs.get(fn, (0, 0))
        priority = loc_count * (1 + prod)
        entries.append({'path': path, 'fn': fn, 'loc': loc_count,
                        'prod': prod, 'test': test, 'priority': priority})

entries.sort(key=lambda e: -e['priority'])

with open(out_path, 'w') as out:
    out.write("# Coverage Gaps — Prioritized\n\n")
    out.write("Priority = function LOC × (1 + production caller count)\n\n")
    out.write("| Rank | Path | Function | LOC | Prod | Test | Priority |\n")
    out.write("|-----:|------|----------|----:|-----:|-----:|---------:|\n")
    for i, e in enumerate(entries[:50], 1):
        out.write(f"| {i} | `{e['path']}` | `{e['fn']}` | {e['loc']} | {e['prod']} | {e['test']} | {e['priority']} |\n")

print()
print('=== Top 20 gaps by priority ===')
print(f'{"rank":>4} {"path":<55} {"function":<32} {"LOC":>4} {"prio":>6}')
print('─' * 110)
for i, e in enumerate(entries[:20], 1):
    p = e['path']
    if len(p) > 54:
        p = '...' + p[-51:]
    print(f'{i:>4} {p:<55} {e["fn"]:<32} {e["loc"]:>4} {e["priority"]:>6}')
PY
echo

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------

SUMMARY="$REPORT_DIR/summary.md"
{
  echo "# Coverage Audit — $(date +%Y-%m-%d)"
  echo
  echo "Module: \`$MODULE\`"
  echo
  total_line=$(grep '^total:' "$FUNC_REPORT" || echo 'total: unknown 0.0%')
  echo "- Overall: \`$total_line\`"
  echo "- Untested functions: $UNTESTED_COUNT / $TOTAL_FUNCS"
  echo
  echo "## Per-package"
  echo
  echo '```'
  column -t -s$'\t' "$PER_PKG_TSV" 2>/dev/null || cat "$PER_PKG_TSV"
  echo '```'
  echo
  echo "## Top 20 priority gaps"
  echo
  head -24 "$PRIO_MD" | tail -22 2>/dev/null || true
  echo
  echo "## Reports"
  echo
  echo "- \`per-function.txt\` — all functions with coverage"
  echo "- \`untested-functions.txt\` — 0% list"
  echo "- \`per-package.tsv\` — package roll-up"
  echo "- \`call-site-audit.txt\` — references per 0% function"
  echo "- \`gaps-by-priority.md\` — ranked gaps"
  echo "- \`../coverage.html\` — HTML coverage map"
} > "$SUMMARY"

go tool cover -html="$MERGED" -o "$OUT_DIR/coverage.html" 2>/dev/null || true

echo "=== Audit complete ==="
echo
echo "Reports in: $REPORT_DIR/"
echo "Start with: cat $SUMMARY"