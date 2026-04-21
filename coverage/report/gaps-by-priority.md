# Coverage Gaps — Prioritized

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
| 19 | `github.com/clearcompass-ai/ortholog-sdk/check_sdk_usage.go` | `main` | 1 | 13 | 0 | 14 |
| 20 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `SetBatch` | 1 | 13 | 0 | 14 |
| 21 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/tree.go` | `SetBatch` | 1 | 13 | 0 | 14 |
| 22 | `github.com/clearcompass-ai/ortholog-sdk/did/verifier_registry.go` | `NewVerifierRegistry` | 1 | 8 | 0 | 9 |
| 23 | `github.com/clearcompass-ai/ortholog-sdk/lifecycle/recovery.go` | `Store` | 1 | 8 | 57 | 9 |
| 24 | `github.com/clearcompass-ai/ortholog-sdk/check_sdk_usage.go` | `isSelectorFromPkg` | 1 | 7 | 0 | 8 |
| 25 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/derivation_commitment.go` | `Error` | 1 | 7 | 8 | 8 |
| 26 | `github.com/clearcompass-ai/ortholog-sdk/crypto/artifact/api.go` | `Error` | 1 | 7 | 8 | 8 |
| 27 | `github.com/clearcompass-ai/ortholog-sdk/exchange/auth/signed_request.go` | `VerifyRequest` | 1 | 7 | 15 | 8 |
| 28 | `github.com/clearcompass-ai/ortholog-sdk/builder/concurrency.go` | `Len` | 1 | 6 | 0 | 7 |
| 29 | `github.com/clearcompass-ai/ortholog-sdk/check_sdk_usage.go` | `pkgAlias` | 1 | 6 | 0 | 7 |
| 30 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/overlay.go` | `NewOverlayLeafStore` | 1 | 5 | 0 | 6 |
| 31 | `github.com/clearcompass-ai/ortholog-sdk/schema/shard_genesis.go` | `BuildShardGenesisPayload` | 1 | 5 | 0 | 6 |
| 32 | `github.com/clearcompass-ai/ortholog-sdk/builder/path_compression.go` | `computeIntermediateAuthorityTip` | 1 | 4 | 0 | 5 |
| 33 | `github.com/clearcompass-ai/ortholog-sdk/check_sdk_usage.go` | `checkCallExpr` | 1 | 4 | 0 | 5 |
| 34 | `github.com/clearcompass-ai/ortholog-sdk/core/envelope/api.go` | `CurrentProtocolVersion` | 1 | 4 | 0 | 5 |
| 35 | `github.com/clearcompass-ai/ortholog-sdk/lifecycle/scope_governance.go` | `ExecuteAmendment` | 1 | 4 | 1 | 5 |
| 36 | `github.com/clearcompass-ai/ortholog-sdk/schema/resolver.go` | `NewCachingResolver` | 1 | 4 | 6 | 5 |
| 37 | `github.com/clearcompass-ai/ortholog-sdk/core/envelope/destination.go` | `MustDestinationCommitment` | 1 | 3 | 0 | 4 |
| 38 | `github.com/clearcompass-ai/ortholog-sdk/core/smt/tree.go` | `SetLeaves` | 1 | 3 | 0 | 4 |
| 39 | `github.com/clearcompass-ai/ortholog-sdk/crypto/escrow/blind_routing.go` | `Platform` | 1 | 3 | 1 | 4 |
| 40 | `github.com/clearcompass-ai/ortholog-sdk/crypto/hash.go` | `HashBytes` | 1 | 3 | 0 | 4 |
| 41 | `github.com/clearcompass-ai/ortholog-sdk/did/key_resolver.go` | `NewKeyResolver` | 1 | 3 | 0 | 4 |
| 42 | `github.com/clearcompass-ai/ortholog-sdk/did/method_router.go` | `NewMethodRouter` | 1 | 3 | 0 | 4 |
| 43 | `github.com/clearcompass-ai/ortholog-sdk/did/method_router.go` | `Unregister` | 1 | 3 | 0 | 4 |
| 44 | `github.com/clearcompass-ai/ortholog-sdk/did/pkh.go` | `NewPKHResolver` | 1 | 3 | 0 | 4 |
| 45 | `github.com/clearcompass-ai/ortholog-sdk/did/pkh.go` | `NewPKHResolverWithNamespaces` | 1 | 3 | 0 | 4 |
| 46 | `github.com/clearcompass-ai/ortholog-sdk/did/pkh.go` | `NewPKHDIDEthereum` | 1 | 3 | 0 | 4 |
| 47 | `github.com/clearcompass-ai/ortholog-sdk/lifecycle/artifact_access.go` | `grantUmbralPRE` | 1 | 3 | 0 | 4 |
| 48 | `github.com/clearcompass-ai/ortholog-sdk/schema/resolver.go` | `cacheResult` | 1 | 3 | 0 | 4 |
| 49 | `github.com/clearcompass-ai/ortholog-sdk/schema/shard_genesis.go` | `ShardGenesisSchemaParams` | 1 | 3 | 0 | 4 |
| 50 | `github.com/clearcompass-ai/ortholog-sdk/builder/algorithm.go` | `verifyApprovalPointers` | 1 | 2 | 0 | 3 |
