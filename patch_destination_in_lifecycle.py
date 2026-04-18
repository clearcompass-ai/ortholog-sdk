#!/usr/bin/env python3
"""
patch_destination_in_lifecycle.py

Mirrors patch_destination_in_params.py but targets lifecycle.*Params /
lifecycle.*Config literals. Adds `Destination: testDestinationDID,` as the
first field inside every matched literal. Idempotent.

Also rewrites lifecycle.BuildApprovalCosignature(signerDID, pos, time)
calls to lifecycle.BuildApprovalCosignature(signerDID, testDestinationDID,
pos, time) — the signature now takes a destination as its second argument.

The patcher is Go-aware of strings / runes / comments.
"""

import os
import re
import sys
from pathlib import Path

SDK_ROOT = Path(os.path.expanduser("~/workspace/ortholog-sdk"))
TESTS_DIR = SDK_ROOT / "tests"

CONST_NAME = "testDestinationDID"

# Lifecycle structs we added Destination to. Every *Params / *Config that
# feeds a public function producing an entry.
LIFECYCLE_STRUCTS = [
    # recovery.go
    "InitiateRecoveryParams",
    "ExecuteRecoveryParams",
    # artifact_access.go
    "GrantArtifactAccessParams",
    # scope_governance.go
    "AmendmentProposalParams",
    "ExecuteAmendmentParams",
    "RemovalParams",
    "ActivateRemovalParams",
    # provision.go
    "SingleLogConfig",
]

# Match both `lifecycle.Xxx{` and bare `Xxx{` (in case a test file has a
# dot-import or alias).
PATTERNS = []
for s in LIFECYCLE_STRUCTS:
    PATTERNS.append(re.compile(r'\blifecycle\.' + s + r'\{'))
    PATTERNS.append(re.compile(r'(?<!\.)\b' + s + r'\{'))

TARGET_FILES = sorted(TESTS_DIR.glob("*_test.go"))

# -----------------------------------------------------------------------------
# Go tokenizer — brace match respecting strings / runes / comments
# -----------------------------------------------------------------------------

def find_matching_brace(src: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            nl = src.find('\n', i)
            i = nl if nl != -1 else n
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            end = src.find('*/', i + 2)
            i = end + 2 if end != -1 else n
            continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '`':
            end = src.find('`', i + 1)
            i = end + 1 if end != -1 else n
            continue
        if c == "'":
            i += 1
            while i < n and src[i] != "'":
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_next_literal(src: str, start: int):
    best = None
    for p in PATTERNS:
        m = p.search(src, start)
        if m is None:
            continue
        if best is None or m.start() < best.start():
            best = m
    return best


def patch_literals(src: str) -> tuple[str, int]:
    out = []
    i = 0
    count = 0
    n = len(src)
    while i < n:
        m = find_next_literal(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        open_brace_idx = m.end() - 1
        close_brace_idx = find_matching_brace(src, open_brace_idx)
        if close_brace_idx == -1:
            out.append(src[m.start():])
            break

        literal = src[m.start():close_brace_idx + 1]
        body = src[open_brace_idx + 1:close_brace_idx]

        if body.strip() == "":
            out.append(literal)
            i = close_brace_idx + 1
            continue

        if re.search(r'\bDestination\s*:', body):
            out.append(literal)
            i = close_brace_idx + 1
            continue

        first_nl = body.find('\n')
        if first_nl == -1:
            prefix = src[m.start():open_brace_idx + 1]
            new_body = f'Destination: {CONST_NAME}, {body.lstrip()}'
            new_literal = f'{prefix}{new_body}}}'
        else:
            after_nl = body[first_nl + 1:]
            indent_match = re.match(r'([ \t]*)', after_nl)
            indent = indent_match.group(1) if indent_match else '\t'
            inserted = f'\n{indent}Destination: {CONST_NAME},'
            prefix = src[m.start():open_brace_idx + 1]
            new_literal = f'{prefix}{inserted}{body}}}'

        out.append(new_literal)
        count += 1
        i = close_brace_idx + 1

    return ''.join(out), count


# -----------------------------------------------------------------------------
# BuildApprovalCosignature signature patcher
# -----------------------------------------------------------------------------
#
# The old signature: lifecycle.BuildApprovalCosignature(signerDID, pos, time)
# The new signature: lifecycle.BuildApprovalCosignature(signerDID, destination, pos, time)
#
# We insert testDestinationDID as the second argument. Identify old 3-arg
# calls by matching lifecycle.BuildApprovalCosignature( ... with exactly
# two commas inside the balanced paren group.

BACOS_PATTERN = re.compile(r'\blifecycle\.BuildApprovalCosignature\s*\(')

def find_matching_paren(src: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            nl = src.find('\n', i)
            i = nl if nl != -1 else n
            continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '`':
            end = src.find('`', i + 1)
            i = end + 1 if end != -1 else n
            continue
        if c == "'":
            i += 1
            while i < n and src[i] != "'":
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def count_top_level_commas(args: str) -> int:
    """Count commas at the top nesting level within an argument list."""
    depth = 0
    count = 0
    i = 0
    n = len(args)
    while i < n:
        c = args[i]
        if c == '"':
            i += 1
            while i < n:
                if args[i] == '\\':
                    i += 2
                    continue
                if args[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == '`':
            end = args.find('`', i + 1)
            i = end + 1 if end != -1 else n
            continue
        if c == "'":
            i += 1
            while i < n and args[i] != "'":
                if args[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c in '({[':
            depth += 1
        elif c in ')}]':
            depth -= 1
        elif c == ',' and depth == 0:
            count += 1
        i += 1
    return count


def patch_bacos_calls(src: str) -> tuple[str, int]:
    out = []
    i = 0
    count = 0
    n = len(src)
    while i < n:
        m = BACOS_PATTERN.search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        open_paren = m.end() - 1
        close_paren = find_matching_paren(src, open_paren)
        if close_paren == -1:
            out.append(src[m.start():])
            break

        args = src[open_paren + 1:close_paren]
        # Old signature had 2 top-level commas (3 args). Skip if this call
        # is already 3 commas (4 args).
        if count_top_level_commas(args) != 2:
            out.append(src[m.start():close_paren + 1])
            i = close_paren + 1
            continue

        # Insert testDestinationDID as the second argument.
        # Find the first top-level comma.
        depth = 0
        j = 0
        first_comma = -1
        while j < len(args):
            c = args[j]
            if c == '"':
                j += 1
                while j < len(args):
                    if args[j] == '\\':
                        j += 2
                        continue
                    if args[j] == '"':
                        j += 1
                        break
                    j += 1
                continue
            if c in '({[':
                depth += 1
            elif c in ')}]':
                depth -= 1
            elif c == ',' and depth == 0:
                first_comma = j
                break
            j += 1
        if first_comma == -1:
            out.append(src[m.start():close_paren + 1])
            i = close_paren + 1
            continue

        new_args = (
            args[:first_comma + 1] +
            f' {CONST_NAME},' +
            args[first_comma + 1:]
        )
        new_call = f'{src[m.start():open_paren + 1]}{new_args}{src[close_paren]}'
        out.append(new_call)
        count += 1
        i = close_paren + 1

    return ''.join(out), count


def main():
    if not TESTS_DIR.is_dir():
        print(f"ERROR: tests dir not found at {TESTS_DIR}", file=sys.stderr)
        sys.exit(1)

    total_lits = 0
    total_calls = 0
    for path in TARGET_FILES:
        orig = path.read_text()
        patched, n_lits = patch_literals(orig)
        patched, n_calls = patch_bacos_calls(patched)
        if n_lits == 0 and n_calls == 0:
            continue
        path.write_text(patched)
        parts = []
        if n_lits > 0:
            parts.append(f"{n_lits} literal(s)")
        if n_calls > 0:
            parts.append(f"{n_calls} BuildApprovalCosignature call(s)")
        print(f"  {path.name}: patched {', '.join(parts)}")
        total_lits += n_lits
        total_calls += n_calls

    print()
    print(f"Total lifecycle literals: {total_lits}")
    print(f"Total BuildApprovalCosignature call-site rewrites: {total_calls}")
    print()
    print("Next: go vet ./tests/... && go test -count=1 ./tests/...")


if __name__ == "__main__":
    main()