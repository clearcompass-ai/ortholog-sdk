# Destination-Binding + Freshness + Narrow-NonceStore — APPLY

## What this ships

Three architectural additions that together close replay-attack surface without
growing a storage-forever NonceStore:

| Defense          | Against                           | Mechanism                          |
| ---------------- | --------------------------------- | ---------------------------------- |
| **Destination binding** | Cross-exchange replay       | Field on `Entry`, in canonical hash |
| **Log dedup**    | Same-exchange resubmission        | Already present (canonical-hash uniqueness per log) |
| **Freshness policy** | Stale entries ingested fresh  | `exchange/policy/freshness.go` helper |
| **NonceStore**   | Replay of non-log-entry traffic   | Strict-forever, narrow-scoped ref impl |

## Zero-backcompat

Entries signed under the pre-destination canonical hash no longer verify.
Every consumer (including `judicial-network`) regenerates fixtures and updates
every `Build*` call site with a `Destination` field. This is the right moment
to do it — before any real court entry is committed under the old hash.

## Delivery

### NEW files (drop in whole)

1. `core/envelope/destination.go` — destination commitment helper
2. `exchange/policy/freshness.go` — ingestion freshness window
3. `exchange/auth/nonce_store.go` — interface + strict-forever contract
4. `exchange/auth/nonce_memory.go` — reference in-memory impl
5. `tests/destination_binding_test.go` — cross-destination replay rejection
6. `tests/freshness_policy_test.go` — freshness window boundaries
7. `tests/exchange_auth_test.go` — SIWE + NonceStore replay/validity tests

### MODIFIED files (patches below)

8. `core/envelope/entry.go` — add `Destination` field
9. `core/envelope/serialize.go` — serialize destination; hash includes it
10. `builder/entry_builders.go` — every `Build*Config` gets `Destination`; validated non-empty
11. `did/verifier_registry.go` — destination-scoped; add `VerifyEntry`
12. `exchange/auth/signed_request.go` — `VerifyRequestOptions`, validity constants

## Order of operations

1. Apply `core/envelope/` changes (schema + hash)
2. Apply `builder/` changes (every `Build*Config` adds `Destination`)
3. Apply `did/verifier_registry.go` (destination-scoped registry)
4. Drop in the three `exchange/` new files
5. Drop in the three new test files
6. Regenerate fixtures: `cd ~/workspace/ortholog-sdk && go test ./tests/...`
7. Update consumer: every `Build*` call site in `judicial-network` takes a new `Destination` field

## Consumer migration

In `judicial-network`, the destination DID is always known at the call site
(it's the exchange the entry is being submitted to). Mechanical update:

```go
// BEFORE
entry, err := builder.BuildAmendment(builder.AmendmentConfig{
    SignerDID:    "did:web:courts.tn.gov:appellate:judge-chen",
    TargetRoot:   targetPos,
    // ...
})

// AFTER
entry, err := builder.BuildAmendment(builder.AmendmentConfig{
    Destination:  "did:web:courts.tn.gov:appellate",  // ← NEW, required
    SignerDID:    "did:web:courts.tn.gov:appellate:judge-chen",
    TargetRoot:   targetPos,
    // ...
})
```

Then every verifier construction:

```go
// BEFORE
registry := did.DefaultVerifierRegistry(resolver)

// AFTER
registry := did.DefaultVerifierRegistry("did:web:courts.tn.gov:appellate", resolver)
```

## What NonceStore does and doesn't cover

**Use NonceStore for** endpoints that:
- Return sensitive data not public by default (sealed-record reads)
- Trigger side effects outside the log (certified-copy delivery, notifications)
- Manipulate control-plane state (key rotation, webhook registration)

**DO NOT use NonceStore for** log-entry submissions. The log's canonical-hash
dedup + destination binding + freshness window already cover that path without
maintaining forever-growing nonce state.

## Freshness window constants

```go
ValidityAutomated = 60 * time.Second   // machine-to-machine, witnesses, anchors
ValidityInteractive   = 5 * time.Minute    // clerks, administrators
ValidityDeliberative   = 30 * time.Minute   // deliberative judicial signings
MaxValidityWindow = 1 * time.Hour    // hard ceiling — SDK rejects above
```

Consumer picks per endpoint. SDK enforces the ceiling unconditionally.
