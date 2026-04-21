# Package signature: `github.com/clearcompass-ai/ortholog-sdk/crypto`

- Packages loaded (for callsite resolution): 33
- Exported functions: 1
- Unexported functions: 0
- Exported with zero callers: 1
- Unexported with zero callers (possible dead code): 0

## Exported functions

### `HashBytes`

- Signature: `func crypto.HashBytes(data []byte) [32]byte`
- Location: `/Users/anil/workspace/ortholog-sdk/crypto/hash.go:20`
- Lines: 3
- Callers: 0 total (0 internal, 0 external, 0 test)
- ⚠️ Zero callers detected anywhere (unused export)

> HashBytes returns SHA-256 of arbitrary bytes. For Entry canonical hashes, do NOT use this function. Use the Tessera-aligned primitives in the envelope package: - envelope.EntryIdentity(entry) — dedup key (SHA-256 of canonical bytes) - envelope.EntryLeafHash(entry) — RFC 6962 Merkle leaf hash for…

## Unexported functions

