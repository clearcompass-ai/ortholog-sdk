# The evidence confirms it — and gives us a cleaner picture than I expected

## What this measurement tells us (critical reading)

Look closely at the coverage output:

```
core/smt/tree.go:94:  GetLeaf           100.0%
core/smt/tree.go:103: SetLeaf           100.0%
core/smt/tree.go:271: Get               100.0%   ← Tree.Get covered
core/smt/tree.go:281: Set               100.0%   ← Tree.Set covered
core/smt/tree.go:296: SetBatch          0.0%
core/smt/tree.go:330: Get               0.0%     ← different Get, actually untested
core/smt/tree.go:337: Set               0.0%     ← different Set, actually untested
```

**Two functions named `Get` in the same file.** One at line 271 (100%), one at line 330 (0%). Go allows this because they're methods on different receiver types. **So the audit was right: there IS an untested `Get` method. It's just not the one heavily used by the test suite.**

This changes the interpretation significantly:
- `Tree.GetLeaf` / `Tree.SetLeaf` (lines 94, 103): 100% covered. These are what the test suite uses.
- `Tree.Get` / `Tree.Set` at lines 271, 281: 100% covered. Probably the core read/write for leaves.
- `Tree.Get` / `Tree.Set` at lines 330, 337: **0% covered.** Different methods entirely — different receiver, different purpose. **Legitimate gap.**
- `Tree.SetLeaves`, `Tree.SetBatch`: **0% covered.** Legitimate gaps.

I need to see those specific lines to know what receiver types these are. But the broader point stands: **the audit correctly identified real gaps, not artifacts.**

Also confirmed: `check_sdk_usage.go` is a **helper script, not SDK code**. All 25 of those "uncovered functions" are out of scope.

## Adjusted picture

Removing `check_sdk_usage.go` from the denominator:

- **Real untested functions: 68** (93 minus 25 helper-script functions)
- **Real total: 491** (516 minus 25)
- **Effective coverage: approximately 71% of SDK statements**

Still not Certificate Transparency rugged. CT-grade implementations aim for 90%+ with mutation testing on critical paths. Let me structure the three waves around getting there.

## The Three-Wave Plan

The goal: **ortholog-sdk at CT-grade reliability.** CT (per RFC 6962 and its operators) is the closest real-world analog — append-only Merkle logs serving legal-grade trust. Google's CT client is ~85% line coverage, with comprehensive fuzzing and property tests on wire format, Merkle proofs, and signature verification. That's the bar.

### Wave 1 — Foundation: Fix measurement, eliminate gap inventory

**Purpose:** We can't build robust testing on fragile measurement. Also, clean up the gap inventory so every remaining 0% is a real decision, not noise.

**Deliverables:**

1. **Exclude helper scripts from coverage measurement.** Add `//go:build !coverage` or relocate `check_sdk_usage.go` under `cmd/`. Either way, it stops polluting the metrics.

2. **Fix the audit script's LOC counter.** Currently reports LOC=1 for every function; priority is therefore driven only by caller count. Fix so we actually see function size.

3. **Dead-code pass.** For every 0% function with ≤2 references anywhere, decide: delete or test. Low-ref functions in `types/`, `crypto/hash.go`, `core/smt/derivation_commitment.go` are the candidates. Either cut them or keep them with a one-line test.

4. **Two-name-collision resolution.** For every case where Go coverage shows two methods with the same name (the `Get`/`Set` situation): determine which receiver each belongs to, which is actually used in production, which is legitimately uncovered. Likely identifies 3-5 more "real" gaps hiding behind name collisions.

5. **Document what IS covered.** Produce a reverse map: which critical invariants are exercised by which tests. A one-page "test inventory" that future contributors can trust. Not a coverage report — a behavior inventory.

**Success criteria:**
- `check_sdk_usage.go` no longer appears in coverage reports.
- Audit shows accurate LOC for every function.
- Every 0% function on the list is confirmed legitimate (not name collision, not dead code).
- A `docs/testing.md` or similar exists, explaining what the test suite actually verifies.

**Key architectural choice:** no new tests written in Wave 1. This is purely measurement + housekeeping. We need a trustworthy floor before building on it.

---

### Wave 2 — Protocol core: test every wire-format, SMT, and path-routing invariant

**Purpose:** The protocol-critical code. Bug here = wrong tree root = every proof against the log is false. CT-equivalent concern.

**Target packages, in priority order:**

#### 2a. `core/envelope` (wire format)

Current coverage: 68%. Targets:
- **`NewEntry`** (currently 0%): The signed-entry constructor used by production. Test should sign, then construct, then round-trip, then verify identity invariance. This is the production constructor — if no test uses it, we've never verified production's primary code path.
- **`wrapField`** (currently 0%): Internal wire helper with 22 callers. Test indirectly by ensuring every field type serializes to spec.
- **Frozen-format tests extended**: Take every `core/envelope/*.go` public function, and for each, add at least one test that verifies its contract AND one test that verifies it rejects malformed input. Target: envelope at 95%+.

**New fuzz targets:**
- `FuzzSerialize_Roundtrip`: Serialize then Deserialize any valid entry; identity should hold.
- `FuzzDeserialize_NeverPanics`: Any byte stream; Deserialize must return error, never panic.
- `FuzzValidate_StrictInvariants`: Any Entry with random field values; Validate must return error for any invariant violation.

#### 2b. `core/smt` (Merkle tree)

Current: 65.5%. Targets:
- Resolve the name-collision `Get`/`Set` at lines 330/337. Test whichever is the real untested code.
- `SetBatch`, `SetLeaves`: Batch operations. Test that `SetBatch([(k1,v1), (k2,v2)])` produces the same root as `Set(k1,v1); Set(k2,v2)`.
- `VerifyBatchProof`: Currently 0%. This is proof verification — CRITICAL. Every CT verifier goes through this kind of function. Test against known-good fixtures, then property-test.
- `overlay.go`: 0% on `Get`, `Set`, `Delete`, `Count`, `Mutations`, `NewOverlayLeafStore`, `Reset`. The overlay is how proofs are constructed before commit. Full coverage required.

**New property tests:**
- `Prop_SetThenGet`: ∀ k, v: Set(k, v); Get(k) == v
- `Prop_DeleteThenGet`: ∀ k: Delete(k); Get(k) == absent
- `Prop_ProofRoundtrip`: ∀ k, v: after Set, proof for k verifies against current root
- `Prop_BatchEquivalence`: SetBatch == sequence of Sets, same final root

**This is the section most similar to CT.** Model the tests on `github.com/google/trillian/storage/testonly` and `github.com/transparency-dev/merkle/compact`.

#### 2c. `builder` path routing

Current: 71.5%. Targets:
- **Every rejection path**: Currently untested. `PathResultRejected` fires in specific conditions; each needs a test proving rejection happens with a test-constructed entry.
- `verifyApprovalPointers`: Scope amendment approval. Tests: foreign-log approval rejected, missing-approver rejected, non-signer-in-authority-set rejected, happy path accepted.
- `computeIntermediateAuthorityTip` (0%): Path compression for authority tips. Test with and without intermediate positions.
- **Delegation loop detection** (Path B): The `visited[dh.SignerDID]` check that returns `PathResultRejected`. Must have a test with a cycle.
- **Delegation depth limit**: The `usedCount >= maxDelegationDepth` check. Test with a 4-deep chain proves it rejects.

#### 2d. `did` resolvers

Current: 67.4%. Targets:
- The `Resolve` methods on key_resolver, method_router, pkh, resolver, schema resolver. Likely a name-collision artifact per wave 1 analysis — but if they're genuinely untested, that's a critical gap since every signature verification goes through these.

**Success criteria:**
- `core/envelope`: 95%+ line coverage, all 0% functions eliminated.
- `core/smt`: 90%+ line coverage, batch and overlay operations tested, proof verification tested against fixtures.
- `builder`: 85%+ line coverage, every rejection path tested.
- `did`: 85%+ line coverage, at minimum every public `Resolve` implementation tested against both success and failure paths.
- Three fuzz targets green for 5+ minutes each in CI.

---

### Wave 3 — Legal-grade robustness: adversarial tests, differential testing, and CI gates

**Purpose:** CT-grade trust isn't just "tests pass"; it's "no adversarial input can cause wrong behavior." This wave establishes that invariant.

#### 3a. Cross-implementation differential testing

For the two truly adversary-sensitive operations — **signature verification** and **SMT proof verification** — add differential tests:

- Use `tessera_compat.go` as ground truth: your `EntryLeafHash` should produce byte-identical output to Tessera's `Entry.LeafHash()`. A go-test fixture should fail if any divergence.
- For signature verification: generate ECDSA signatures with a well-known library (crypto/ecdsa standard library), verify with your verifier, then flip arbitrary bits; ensure every bit-flip is rejected.
- For wire format: cross-check `Serialize(entry)` against an alternative reference implementation (even if you write a minimal one in-test just for this purpose).

#### 3b. Long-horizon fuzzing

Beyond Wave 2's smoke-test fuzzing, run fuzz targets for hours via CI on a schedule. CT operators run fuzzers continuously. Minimum:

- `FuzzProcessBatch`: Random entry sequences; invariant = tree root is deterministic regardless of batching boundaries.
- `FuzzVerifierRegistry_RejectsUnauthorized`: Random entries with random signatures; verifier must reject unless signature is genuinely valid.
- `FuzzDeserialize_AllVersions`: Random bytes interpreted as v6; must never produce an entry that fails `Validate()` post-deserialize.

#### 3c. Mutation testing on critical packages

Run `gremlins` (or equivalent) on `core/envelope`, `core/smt`, `crypto/signatures`, `builder/algorithm.go`, `did/verifier_registry.go`. Any surviving mutation is a test gap. Rule: **zero surviving mutations on these packages for release.**

Example: if `gremlins` changes `if h.SignerDID != target.Header.SignerDID` to `if h.SignerDID == target.Header.SignerDID` in `processPathA` and tests still pass, that's a critical test gap. Path A doesn't verify signer equality in tests.

#### 3d. Adversarial test corpus

Build a permanent corpus of pathological inputs that have caused bugs (past or hypothetical) and keep them in tests. Organized by:

- **Malformed wire**: truncated headers, oversized payloads, mismatched length prefixes, duplicate sections, zero-signature entries.
- **Malicious authority**: delegation cycles, depth overflow, scope-amendment with non-signer approval, evidence pointer overflows.
- **Merkle tree adversarial**: empty tree queries, max-depth insertions, concurrent modifications (the `concurrency_test.go` you already have is a start).
- **Signature edge cases**: zero-byte signatures, wrong-length signatures, signatures with wrong algorithm ID, signatures over modified payloads.

This corpus lives in `tests/adversarial/` and is run on every CI build. When a production bug is found, it's added here first so it never returns.

#### 3e. CI coverage policy

At this point, set hard floors:

- `core/envelope`: 95% lines, 0 surviving mutations on critical functions
- `core/smt`: 90% lines, proof verification fuzzed ≥30 minutes per CI run
- `builder`: 90% lines, every rejection path tested
- `crypto/signatures`: 95% lines, 0 surviving mutations
- `did`: 85% lines
- `verifier`: 90% lines (currently 84%)
- `lifecycle/scope_governance`: 85% lines (currently has 5 untested functions)
- `witness`: maintain 95%+
- Everything else: 75% lines minimum

CI fails a PR if coverage drops below these floors. CI fails a release if any mutation survives on the protocol-critical packages.

**Success criteria:**
- Differential tests pass for all signature algorithms and wire format.
- Fuzz targets run for 30+ minutes per CI run without finding issues.
- Zero surviving mutations on protocol-critical packages.
- Adversarial test corpus covers every known bug class.
- CI policy enforces all of the above.

---

## Summary table

| Wave | Focus | Deliverable | Coverage outcome |
|------|-------|-------------|-----------------|
| **1** | Measurement integrity | Clean audit, name-collision resolved, dead code pruned, helper code excluded | Measurement is trustworthy |
| **2** | Protocol core | Every 0% function in `core/envelope`, `core/smt`, `builder`, `did` decided (tested or deleted); fuzz targets added | envelope 95%, smt 90%, builder 85%, did 85% |
| **3** | Adversarial hardening | Differential tests, long-horizon fuzzing, mutation testing, adversarial corpus, CI enforcement | CT-grade trust |

## What this does NOT include

- Performance/load testing. Different concern; separate plan.
- Documentation beyond the `testing.md` inventory. Good docs are a separate effort.
- API stability tests. Important for SDK users, but orthogonal to correctness.
- Security audit by an external firm. Testing is necessary but not sufficient for legal-grade deployment.

## What I need from you to start

**Single decision: which wave do we start with?**

My recommendation: **Wave 1.** The measurement-integrity work is small (hours, not days) but makes everything else trustworthy. Jumping to Wave 2 without it means we write tests for what might already be tested, or miss what genuinely isn't.

**But if you prefer to act on visible problems now**: start Wave 2 with `core/envelope:NewEntry` specifically. That one is confirmed a real gap — your test suite uses `buildTestEntry` → `NewUnsignedEntry`, so production's `NewEntry` (the signed-entry constructor) is genuinely untested. Writing its test is high-value, independent of measurement cleanup.

Either way, the plan is committed. Tell me: **Wave 1 first, or jump directly to testing `NewEntry` and the scope-governance gap?**