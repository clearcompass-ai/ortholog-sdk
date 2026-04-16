# Ortholog SDK v5.0 — Wave 1: Wire Format & Version Policy

This is Wave 1 of three waves that land the SDK v5.0 release. Wave 1
establishes the v4→v5 wire format bump and the generational version
policy. Waves 2 and 3 build on these foundations.

## What Wave 1 delivers

### Protocol version bump: v4 → v5

The `ControlHeader` struct gains one new field:

```go
DomainManifestVersion *[3]uint16  // [major, minor, patch]; nil for legacy entries
```

This pins every entry to a specific domain manifest version (Option 1 —
pinned per-entry versioning). Cross-version verification becomes
deterministic at scale: a verifier reading entries spanning decades
resolves each entry's governance semantics against the exact manifest
version it was issued under.

### Wire format changes

- **Preamble**: bytes 0–5 unchanged (`uint16 Protocol_Version`,
  `uint32 Header_Body_Length`). Version field now reads `5`.
- **Header body**: `DomainManifestVersion` added at the end of v5
  header bodies. 1 presence byte + 6-byte fixed-width slot (zero-filled
  when absent). v4 header bodies stop at `AuthoritySkip` as before.
- **Forward compatibility**: the Header_Body_Length preamble field
  continues to delimit the header body, so v6+ additive fields will
  not break v5 readers.

### Generational version policy

A new state machine governs read/write acceptance per protocol version:

| State | Readers | Writers | Duration |
|-------|---------|---------|----------|
| ACTIVE | Accept | Emit | Current |
| DEPRECATED | Accept | Reject | 12 months |
| FROZEN | Accept | Reject | Forever |
| REVOKED | Reject | Reject | Post-catastrophe only |

At v5.0 ship: **v4 is DEPRECATED, v5 is ACTIVE**. Legacy v4 entries
read normally (archive invariant). New v4 writes are blocked with
`ErrVersionDeprecated`.

At a future v6.0 ship: v4 moves to FROZEN, v5 moves to DEPRECATED,
v6 becomes ACTIVE. The policy table in `version_policy.go` is the
single source of truth — SDK releases update this table.

### Migration override (narrow escape hatch)

For domain migrations that must resubmit historical entries in their
original wire format (county reorganization, court splits), the SDK
exposes `NewEntryWithOverride` taking a `MigrationOverrideToken`:

```go
token := &envelope.MigrationOverrideToken{
    Reason:         "Davidson→Metro North bulk case migration",
    AuthorizingDID: "did:web:courts.tn.gov:migration-coordinator",
}
entry, err := envelope.NewEntryWithOverride(header, payload, 4, token)
```

The override unblocks DEPRECATED versions only. FROZEN and REVOKED
remain blocked. Token with empty Reason or AuthorizingDID is invalid.

### Error taxonomy for HTTP dispatch

Named errors enable the operator admission pipeline to map version
violations to HTTP status codes:

| Error | HTTP | Meaning |
|-------|------|---------|
| `ErrVersionDeprecated` | 400 Bad Request | v4 writes after v5 ship |
| `ErrVersionFrozen` | 410 Gone | v4 writes after v6 ship |
| `ErrVersionRevoked` | 451 Unavailable | Cryptographic break |
| `ErrUnknownVersion` | 400 Bad Request | Stale reader or corrupt entry |

## Files delivered

| File | Size | Role |
|------|------|------|
| `core/envelope/version_policy.go` | New | Version state machine, enforcement, override |
| `core/envelope/api.go` | New | Version constants, wire format limits |
| `core/envelope/control_header.go` | Rewritten | Adds `DomainManifestVersion` field |
| `core/envelope/serialize.go` | Rewritten | v5 wire format, policy enforcement at read/write |
| `core/envelope/canonical_hash.go` | New | SHA-256 over canonical bytes (v5-aware) |
| `tests/version_policy_test.go` | New | 23 test cases covering state machine |
| `tests/envelope_serialize_test.go` | New | 12 test cases covering wire format + v4 compat |

## Tests

All 32 test cases pass under `go test` and `go test -race`:

```
ok  github.com/clearcompass-ai/ortholog-sdk/tests  0.007s
ok  github.com/clearcompass-ai/ortholog-sdk/tests  1.045s  (race)
```

## What Wave 1 does NOT include

Deliberately deferred to Waves 2 and 3:

- `DomainManifest` struct, validation, registry (Wave 2)
- Judicial/beautician/physician manifests (Wave 2)
- `lifecycle.Provision` / `ProposeAmendment` manifest refactor (Wave 2)
- `did/resolver.go` custody-transition helpers (Wave 3)
- `verifier/contest_override.go` manifest integration (Wave 3)
- Deletion of `ProvisionThreeLogs` / `CourtMapping` etc. (Wave 3)

## Post-Wave-1 invariants

After Wave 1 is merged:

1. New entries emit at v5 with optional `DomainManifestVersion`.
2. Legacy v4 entries continue to deserialize indefinitely.
3. v4 writes are blocked by default; migration tooling can override.
4. Canonical hashes over v5 entries cover `DomainManifestVersion` —
   changing the version changes the hash.
5. The `Authority_Skip` field is unaffected by any admission proof
   corruption (SDK-3 length-prefix guarantee preserved).
6. All existing test suites must continue to pass after
   the `currentProtocolVersion` constant update — if any break, they
   reveal downstream code that hardcodes v4 semantics and must be
   updated before Wave 2.
