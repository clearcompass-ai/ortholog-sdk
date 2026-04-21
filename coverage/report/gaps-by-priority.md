# Coverage Gaps — Prioritized

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
| 19 | `lifecycle/artifact_access.go` | `grantUmbralPRE` | 34 | 3 | 0 | 136 |
| 20 | `core/smt/overlay.go` | `Set` | 7 | 17 | 16 | 126 |
| 21 | `core/smt/tree.go` | `Set` | 6 | 17 | 16 | 108 |
| 22 | `builder/path_compression.go` | `computeIntermediateAuthorityTip` | 18 | 4 | 0 | 90 |
| 23 | `did/method_router.go` | `MustRegister` | 5 | 16 | 0 | 85 |
| 24 | `lifecycle/scope_governance.go` | `ActivateRemoval` | 28 | 2 | 0 | 84 |
| 25 | `builder/algorithm.go` | `verifyApprovalPointers` | 24 | 2 | 0 | 72 |
| 26 | `core/smt/overlay.go` | `NewOverlayLeafStore` | 12 | 5 | 0 | 72 |
| 27 | `core/envelope/serialize.go` | `wrapField` | 3 | 22 | 0 | 69 |
| 28 | `lifecycle/scope_governance.go` | `BuildApprovalCosignature` | 19 | 2 | 0 | 57 |
| 29 | `did/pkh.go` | `NewPKHResolverWithNamespaces` | 13 | 3 | 0 | 52 |
| 30 | `did/method_router.go` | `Methods` | 16 | 2 | 0 | 48 |
| 31 | `did/verifier_registry.go` | `NewVerifierRegistry` | 5 | 8 | 0 | 45 |
| 32 | `builder/entry_classification.go` | `pathName` | 20 | 1 | 0 | 40 |
| 33 | `did/pkh.go` | `NewPKHDIDEthereum` | 10 | 3 | 0 | 40 |
| 34 | `schema/shard_genesis.go` | `ShardGenesisSchemaParams` | 9 | 3 | 0 | 36 |
| 35 | `core/envelope/destination.go` | `MustDestinationCommitment` | 7 | 3 | 0 | 28 |
| 36 | `did/method_router.go` | `Unregister` | 7 | 3 | 0 | 28 |
| 37 | `did/pkh.go` | `NewPKHResolver` | 7 | 3 | 0 | 28 |
| 38 | `did/verifier_registry.go` | `RegisteredMethods` | 9 | 2 | 0 | 27 |
| 39 | `lifecycle/provision.go` | `AllEntries` | 9 | 2 | 0 | 27 |
| 40 | `did/resolver.go` | `FindVerificationMethod` | 8 | 2 | 0 | 24 |
| 41 | `builder/concurrency.go` | `AllKeys` | 7 | 2 | 0 | 21 |
| 42 | `builder/concurrency.go` | `Len` | 3 | 6 | 0 | 21 |
| 43 | `core/smt/derivation_commitment.go` | `VerifyCommitmentTransition` | 9 | 1 | 0 | 18 |
| 44 | `core/smt/overlay.go` | `Reset` | 6 | 2 | 0 | 18 |
| 45 | `exchange/auth/nonce_memory.go` | `ReservedAt` | 6 | 2 | 0 | 18 |
| 46 | `core/smt/overlay.go` | `Mutations` | 1 | 16 | 8 | 17 |
| 47 | `crypto/artifact/api.go` | `ZeroKey` | 8 | 1 | 0 | 16 |
| 48 | `core/envelope/api.go` | `CurrentProtocolVersion` | 3 | 4 | 0 | 15 |
| 49 | `schema/resolver.go` | `NewCachingResolver` | 3 | 4 | 6 | 15 |
| 50 | `crypto/hash.go` | `HashBytes` | 3 | 3 | 0 | 12 |
