#!/usr/bin/env python3
"""
patch_destination_in_params.py

Adds `Destination: testDestinationDID,` as the first field inside every
`builder.*Params{` literal in the target test files. Idempotent: any literal
that already declares `Destination:` is left alone.

Uses the same brace-matching approach as patch_destination_in_tests.py —
Go-aware of strings, runes, and comments.

Covers the 18 *Params structs defined in builder/entry_builders.go.
"""

import os
import re
import sys
from pathlib import Path

SDK_ROOT = Path(os.path.expanduser("~/workspace/ortholog-sdk"))
TESTS_DIR = SDK_ROOT / "tests"

CONST_NAME = "testDestinationDID"

# All 18 *Params struct type names the builder package exposes.
PARAMS_STRUCTS = [
    "RootEntityParams",
    "AmendmentParams",
    "DelegationParams",
    "SuccessionParams",
    "RevocationParams",
    "ScopeCreationParams",
    "ScopeAmendmentParams",
    "ScopeRemovalParams",
    "EnforcementParams",
    "CommentaryParams",
    "CosignatureParams",
    "RecoveryRequestParams",
    "AnchorParams",
    "KeyRotationParams",
    "KeyPrecommitParams",
    "SchemaEntryParams",
    "PathBParams",
    "MirrorParams",
]

# Pattern matches builder.XxxParams{ with optional whitespace.
# We also accept the bare name without the 'builder.' prefix because some
# test files use dot-imports or local aliases — safer to catch both.
PATTERNS = [re.compile(r'\bbuilder\.' + s + r'\{') for s in PARAMS_STRUCTS]
PATTERNS += [re.compile(r'(?<!\.)\b' + s + r'\{') for s in PARAMS_STRUCTS]

# Scan every Go test file.
TARGET_FILES = sorted(TESTS_DIR.glob("*_test.go"))

# -----------------------------------------------------------------------------
# Go tokenizer — brace matching that respects strings / runes / comments
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


def find_next_match(src: str, start: int):
    """Find the earliest match of any pattern starting at or after `start`.
    Returns (match, pattern_idx) or (None, -1)."""
    best = None
    for p in PATTERNS:
        m = p.search(src, start)
        if m is None:
            continue
        if best is None or m.start() < best.start():
            best = m
    return best


def patch_source(src: str) -> tuple[str, int]:
    out = []
    i = 0
    count = 0
    n = len(src)
    while i < n:
        m = find_next_match(src, i)
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

        # Skip empty literals
        if body.strip() == "":
            out.append(literal)
            i = close_brace_idx + 1
            continue

        # Skip if Destination already present
        if re.search(r'\bDestination\s*:', body):
            out.append(literal)
            i = close_brace_idx + 1
            continue

        first_nl = body.find('\n')
        if first_nl == -1:
            # Single-line literal
            prefix = src[m.start():open_brace_idx + 1]  # e.g. "builder.AmendmentParams{"
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


def main():
    if not TESTS_DIR.is_dir():
        print(f"ERROR: tests dir not found at {TESTS_DIR}", file=sys.stderr)
        sys.exit(1)

    total = 0
    for path in TARGET_FILES:
        orig = path.read_text()
        new, n = patch_source(orig)
        if n == 0:
            continue
        path.write_text(new)
        print(f"  {path.name}: patched {n} Params literal(s)")
        total += n

    print()
    print(f"Total Params literals patched: {total}")
    print()
    print("Next:")
    print("  go vet ./tests/... 2>&1 | head -20")
    print("  go test -count=1 ./tests/... 2>&1 | tail -60")


if __name__ == "__main__":
    main()