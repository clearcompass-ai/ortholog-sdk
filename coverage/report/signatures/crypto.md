# Package signature: `github.com/clearcompass-ai/ortholog-sdk/crypto`

## Overview

- **Package name:** `crypto`
- **Production files:** 1 (23 lines)
- **Test files:** 0 (0 lines)
- **Exported symbols:** 1
- **Unexported symbols:** 0
- **Exported but undocumented:** 0

### Files

- `crypto/hash.go` — 23 lines (prod)

### Test inventory

**No test files in this package.**

## Imports

- `crypto/sha256`

## Exported API surface

### Functions (1)

#### `HashBytes`

- Signature: `func HashBytes(data []byte) [32]byte`
- Location: `crypto/hash.go:20:1`
- Line count: 3
- Cyclomatic complexity: 1
- Returns error: false
- Callers: 0 external / 0 internal / 0 tests

> HashBytes returns SHA-256 of arbitrary bytes.  For Entry canonical hashes, do NOT use this function. Use the Tessera-aligned primitives in the envelope package:    - envelope.EntryIdentity(entry)      — dedup key (SHA-256 of canonical bytes)   - envelope.EntryLeafHash(entry)      — RFC 6962 Merk…

## Risk summary

- ✅ All exported symbols are documented
- ⚠️  No test files in this package
