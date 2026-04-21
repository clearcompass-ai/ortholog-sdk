# Coverage Audit — 2026-04-21

Module: `github.com/clearcompass-ai/ortholog-sdk`

- Overall: `total:											(statements)			69.6%`
- Untested functions: 93 / 516

## Per-package

```
package                                  covered  total  pct    untested_fns
crypto                                   0        1      0.0    1
github.com/clearcompass-ai/ortholog-sdk  0        299    0.0    25
schema                                   44       93     47.3   5
exchange/auth                            57       106    53.8   2
types                                    20       36     55.6   5
lifecycle                                293      480    61.0   8
core/smt                                 296      452    65.5   16
did                                      341      506    67.4   17
core/envelope                            394      579    68.0   4
builder                                  441      617    71.5   6
crypto/escrow                            166      203    81.8   1
log                                      23       28     82.1   0
crypto/signatures                        172      204    84.3   0
verifier                                 597      708    84.3   0
crypto/artifact                          259      304    85.2   3
storage                                  160      186    86.0   0
exchange/identity                        62       71     87.3   0
crypto/admission                         95       107    88.8   0
witness                                  159      167    95.2   0
exchange/policy                          16       16     100.0  0
```

## Top 20 priority gaps

Priority = function LOC × (1 + production caller count)

| Rank | Path | Function | LOC | Prod | Test | Priority |
|-----:|------|----------|----:|-----:|-----:|---------:|
| 1 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `Get` | 1 | 49 | 19 | 50 |
| 2 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/tree.go` | `Get` | 1 | 49 | 19 | 50 |
| 3 | `github.com/clearcompass-ai/ortholog-sdk/core/envelope/serialize.go` | `NewEntry` | 1 | 41 | 10 | 42 |
| 4 | `github.com/clearcompass-ai/ortholog-sdk/did/key_resolver.go` | `Resolve` | 1 | 38 | 39 | 39 |
| 5 | `github.com/clearcompass-ai/ortholog-sdk/did/method_router.go` | `Resolve` | 1 | 38 | 39 | 39 |
| 6 | `github.com/clearcompass-ai/ortholog-sdk/did/pkh.go` | `Resolve` | 1 | 38 | 39 | 39 |
| 7 | `github.com/clearcompass-ai/ortholog-sdk/did/resolver.go` | `Resolve` | 1 | 38 | 39 | 39 |
| 8 | `github.com/clearcompass-ai/ortholog-sdk/schema/resolver.go` | `Resolve` | 1 | 38 | 39 | 39 |
| 9 | `github.com/clearcompass-ai/ortholog-sdk/check_sdk_usage.go` | `record` | 1 | 27 | 10 | 28 |
| 10 | `github.com/clearcompass-ai/ortholog-sdk/core/envelope/serialize.go` | `wrapField` | 1 | 22 | 0 | 23 |
| 11 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `Delete` | 1 | 22 | 6 | 23 |
| 12 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/tree.go` | `Delete` | 1 | 22 | 6 | 23 |
| 13 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `Set` | 1 | 17 | 16 | 18 |
| 14 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `Count` | 1 | 17 | 0 | 18 |
| 15 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/tree.go` | `Set` | 1 | 17 | 16 | 18 |
| 16 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `Mutations` | 1 | 16 | 8 | 17 |
| 17 | `github.com/clearcompass-ai/ortholog-sdk/did/method_router.go` | `MustRegister` | 1 | 16 | 0 | 17 |
| 18 | `github.com/clearcompass-ai/ortholog-sdk/did/method_router.go` | `Register` | 1 | 14 | 1 | 15 |

## Reports

- `per-function.txt` — all functions with coverage
- `untested-functions.txt` — 0% list
- `per-package.tsv` — package roll-up
- `call-site-audit.txt` — references per 0% function
- `gaps-by-priority.md` — ranked gaps
- `../coverage.html` — HTML coverage map
