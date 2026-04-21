# Coverage Audit — 2026-04-21

Module: `github.com/clearcompass-ai/ortholog-sdk`

- Overall: `total:											(statements)			73.8%`
- Untested functions: 68 / 491

## Per-package

```
package            covered  total  pct    untested_fns
crypto             0        1      0.0    1
schema             44       93     47.3   5
exchange/auth      57       106    53.8   2
types              20       36     55.6   5
lifecycle          293      480    61.0   8
core/smt           296      452    65.5   16
did                341      506    67.4   17
core/envelope      394      579    68.0   4
builder            441      617    71.5   6
crypto/escrow      160      203    78.8   1
log                23       28     82.1   0
crypto/signatures  172      204    84.3   0
verifier           597      708    84.3   0
crypto/artifact    259      304    85.2   3
storage            160      186    86.0   0
exchange/identity  62       71     87.3   0
crypto/admission   95       107    88.8   0
witness            159      167    95.2   0
exchange/policy    16       16     100.0  0
```

## Top 20 priority gaps

Priority = function LOC × (1 + production caller count)

| Rank | Path | Function | LOC | Prod | Test | Priority |
|-----:|------|----------|----:|-----:|-----:|---------:|
| 1 | `core/envelope/serialize.go` | `NewEntry` | 43 | 41 | 10 | 1806 |
| 2 | `did/resolver.go` | `Resolve` | 37 | 38 | 39 | 1443 |
| 3 | `did/pkh.go` | `Resolve` | 26 | 38 | 39 | 1014 |
| 4 | `core/smt/overlay.go` | `Get` | 19 | 49 | 19 | 950 |
| 5 | `did/key_resolver.go` | `Resolve` | 22 | 38 | 39 | 858 |
| 6 | `core/smt/overlay.go` | `Count` | 41 | 17 | 0 | 738 |
| 7 | `exchange/auth/signed_request.go` | `VerifyRequest` | 89 | 7 | 15 | 712 |
| 8 | `schema/resolver.go` | `Resolve` | 17 | 38 | 39 | 663 |
| 9 | `did/method_router.go` | `Resolve` | 13 | 38 | 39 | 507 |
| 10 | `core/smt/tree.go` | `Get` | 9 | 49 | 19 | 450 |
| 11 | `did/method_router.go` | `Register` | 15 | 14 | 1 | 225 |
| 12 | `core/smt/tree.go` | `SetLeaves` | 48 | 3 | 0 | 192 |
| 13 | `core/smt/overlay.go` | `SetBatch` | 12 | 13 | 0 | 168 |
| 14 | `core/smt/overlay.go` | `Delete` | 7 | 22 | 6 | 161 |
| 15 | `lifecycle/scope_governance.go` | `ExecuteAmendment` | 32 | 4 | 1 | 160 |
| 16 | `core/smt/tree.go` | `SetBatch` | 11 | 13 | 0 | 154 |
| 17 | `schema/shard_genesis.go` | `BuildShardGenesisPayload` | 24 | 5 | 0 | 144 |
| 18 | `core/smt/tree.go` | `Delete` | 6 | 22 | 6 | 138 |

## Reports

- `per-function.txt` — all functions with coverage
- `untested-functions.txt` — 0% list
- `per-package.tsv` — package roll-up
- `call-site-audit.txt` — references per 0% function
- `gaps-by-priority.md` — ranked gaps (with real LOC)
- `../coverage.html` — HTML coverage map
