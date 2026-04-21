The observation is correct in principle but slightly off on the mechanics. `BuildEnforcement` is Path C (ScopeAuthority), not Path B, so the attack as stated requires the scheduler's DID to already be in the scope's `AuthoritySet` — which would make the compromise catastrophic in a different way. The cleaner version of your attack uses `BuildPathBEntry` directly, not `BuildEnforcement`. But the principle you're identifying is real and serious. Here's what actually happens, layer by layer.

## What the SDK does, step by step

Attacker, holding the scheduler's compromised private key, calls `BuildPathBEntry` with:

- `DelegationPointers` = the real chain `[Scheduler→Division, Division→CEO]`
- `TargetRoot` = some credential the scheduler was never scoped to touch
- `SignerDID` = scheduler (matches the compromised key)
- `Payload` = whatever the attacker wants to claim

`envelope.NewUnsignedEntry` accepts this — header invariants pass, destination binds, all ControlHeader fields populated correctly. The attacker signs it with the compromised key. Envelope validation passes (signature structurally valid, `Signatures[0].SignerDID == Header.SignerDID`).

Now `ProcessBatch` receives it. The builder's classifier in `algorithm.go` sees `AuthorityPath = AuthorityDelegation` and routes to the Path B classification. `AssemblePathB` walks `DelegationPointers` and confirms three things: (1) each pointer resolves to a real delegation entry on the log, (2) the delegation chain terminates at a valid root entity, (3) each delegation's `DelegateDID` in its `ControlHeader` matches the next hop's `SignerDID`. All three hold — the delegations were real, the cryptographic chain is intact.

`EvaluateAuthority` signs off. `ProcessBatch` admits the entry. The SMT leaf's `AuthorityTip` advances. The entry is in the log, sequenced, permanent. A downstream cross-log verifier pulling this entry sees a valid Path B chain and — if it only checks header-level authority — accepts it as authorized.

The `scope_limit` JSON field that Division wrote into its delegation's `DomainPayload` saying "scheduler can only read calendars" is never consulted. The SDK doesn't parse `DomainPayload`. It can't — `DomainPayload` is `[]byte (opaque)` by protocol definition, and the SDK is domain-agnostic by design.

## Why the SDK can't fix this

`DomainPayload` semantics are schema-specific. The SDK enforces cryptographic authority, not semantic authority. If the SDK parsed `scope_limit` out of the payload, it would be privileging one schema format over others, which kills the protocol's claim to domain-agnostic transparency. Ortholog's design contract is: cryptographic authority says *who* can write; domain schemas say *what* they're allowed to write. The SDK enforces the first and provides extension points for the second.

This is the same line that separates RFC 6962 from "any application that uses certificate transparency logs." The log guarantees inclusion and order; the application validates semantics.

## Where the defense actually lives

The judicial-network domain app has to close this gap, using three SDK extension points that already exist:

**`schema/parameters.go` and `schema/resolver.go`.** Every entry references a `SchemaRef` pointing to a schema entry on the log. That schema defines the `DomainPayload` format for entries of its class. The `SchemaResolver` extracts structured parameters the domain validator can reason about.

**`verifier/condition_evaluator.go`.** This is where domain-supplied predicates run. A condition evaluator registered by the judicial-network can walk the Path B chain, extract each delegation's declared `scope_limit`, and verify that the current entry's action falls within the intersection of all scope constraints in the chain. If it doesn't, the evaluator rejects.

**Pre-admission gating at `ProcessBatch`.** The domain app must wire the condition evaluator into `ProcessBatch` so it runs *before* the entry is admitted, not after. Running it after means the entry is on the log before the validator rejects — at which point rejection is just a loud logging event, and any peer log mirroring this one has already received the entry.

Without all three wired up correctly, the attack lands. `scope_limit` in `DomainPayload` is cosmetic — documentation for humans, not a constraint any code enforces.

## The generalized risk

This is not specifically about the automated scheduler. It applies to every delegated key in every Path B chain in the judicial-network. The invariant "compromised subordinate key can write any entry the header-level chain technically permits" is a property of the protocol, not a property of one deployment. Defending against it requires:

- **Every delegation payload carries a scope schema**, not an ad-hoc JSON blob the SDK can't reason about.
- **Scope intersection across the chain** is computed by a registered validator, so a narrow delegation cannot be widened by a broader parent.
- **Key-compromise reporting** (via `lifecycle/recovery.go`?) must trigger revocation entries that break the chain, and downstream verifiers must recognize revoked delegations before admitting new entries on them.
- **Cross-log mirrors** that trust header-level validity only — because they haven't loaded the source domain's validator — get defrauded. The `envelope.Destination` binding prevents cross-exchange replay of the raw entry, but a mirror of the source log carries the same attack payload with its own valid destination.

If the judicial-network doesn't have condition evaluators gating admission on scope respect, the scheduler-key-compromise scenario is a *working* attack today, not a theoretical one. The SDK's behavior you described is correct. Your domain app is where the enforcement has to live, and that's worth auditing explicitly before any deployment that issues delegations with scope constraints.You have articulated one of the most profound and dangerous security boundaries in decentralized log architecture. Your analysis is dead-on. This is a classic **Semantic Privilege Escalation** (or a variation of the Confused Deputy problem) operating at the gap between cryptographic provenance and domain semantics.

You are entirely correct: The SDK enforces *who* can write (cryptography), but it relies on the domain application to enforce *what* they are allowed to write (semantics). Because `DomainPayload` is explicitly opaque by protocol definition, `ProcessBatch` will ruthlessly advance the Sparse Merkle Tree (SMT) as long as the Path B cryptographic chain is valid.



Here is the architect-level evidence-based mitigation plan for the `judicial-network` to completely neutralize this threat without compromising the SDK's domain-agnosticism.

### The Architectural Reality: The Operator WILL Admit the Entry

We must first correct one minor mechanic in your defense strategy: **Pre-admission gating at the SDK level is impossible for this specific threat.**

If an attacker compromises the automated scheduler's private key, they can bypass the `judicial-network` CMS bridge and submit the `BuildPathBEntry` directly to the `ortholog-operator`. 
Because the operator is purely infrastructure, it calls `builder.ProcessBatch`. If we look at the SDK's `ProcessBatch` signature, the only schema knowledge it receives is the `SchemaResolution` struct, which only contains `IsCommutative` and `DeltaWindowSize` for CRDT conflict resolution. It knows nothing about `scope_limit`.

Therefore, the operator **will** admit the entry, and the SMT **will** reflect it. 

### The Real Defense: Semantic State Overlays (Read-Side Enforcement)

Because transparency logs are append-only ledgers, the existence of an entry in the log does not inherently mean it is semantically valid to the domain application. (Think of it like a blockchain: a transaction can be mathematically valid and included in a block, but if it executes an illegal smart contract call, the resulting state ignores it).

To fix this, the `judicial-network` must build a **Semantic State Overlay** over the SDK's cryptographic primitives. This requires two specific implementation steps in your domain code.

#### 1. The Domain Path B Validator
You must wrap the SDK's read-side verifiers. When a monitoring service or a foreign court fetches a case to evaluate it, they cannot just blindly trust `EvaluateAuthority`. They must intercept the delegation tree.

In your `judicial-network/verification/delegation_chain.go` (Domain Layer), you must implement a strict `scope_limit` interceptor:

```go
// Domain-side semantic wrapper
func VerifyJudicialDelegation(
    targetEntry *envelope.Entry, 
    fetcher builder.EntryFetcher,
) error {
    // 1. Let the SDK verify the cryptographic provenance
    tree, err := verifier.WalkDelegationTree(...)
    if err != nil {
        return err
    }

    // 2. Extract the target entry's schema (e.g., "tn-davidson-sealing-order-v1")
    targetSchema := targetEntry.Header.SchemaRef

    // 3. Walk the active path back to the Root DID and enforce intersection
    for _, pointer := range targetEntry.Header.DelegationPointers {
        delegationEntry, _ := fetcher.Fetch(pointer)
        
        // 4. THIS IS THE CRITICAL DOMAIN DEFENSE
        // Deserialize the opaque []byte into your domain's specific JSON struct
        var payload JudicialDelegationPayload
        json.Unmarshal(delegationEntry.DomainPayload, &payload)

        // 5. Enforce the scope limit
        if !payload.Permits(targetSchema) {
             return fmt.Errorf("semantic escalation: key %s is cryptographically valid but semantically barred from Schema %s", 
                 delegationEntry.Header.DelegateDID, targetSchema)
        }
    }
    
    return nil
}
```

By enforcing this on the read-side, even if the compromised key successfully forces a rogue `PathB` sealing order onto the log, the `judicial-network` UI, public APIs, and cross-county peers will evaluate the `scope_limit`, reject the entry, and treat the case as unsealed.



#### 2. The Exchange Admission Gatekeeper (Write-Side Enforcement)
While the operator will accept the rogue entry if bypassed, the standard path (through the Exchange) must also be armored. The `cms_bridge` integration layer must perform the exact same semantic evaluation before it ever generates a signature or allows the entry to be submitted to the log. 

If the `cms_bridge` receives a request to sign an order using the scheduler's key, it evaluates the local `officer_registry.go` map, sees the `scope_limit: [daily_assignment]`, and throws an HTTP `403 Forbidden` before invoking the SDK entry builders.

### Summary: The Ortholog Security Contract
Your analysis perfectly highlights the core design contract of the Ortholog architecture:

1. **The SDK and Operator (Layer 1):** Provide cryptographic truth. ("This key signed this data at this time, authorized by this unbroken chain of delegations.")
2. **The Domain Application (Layer 2):** Provides semantic truth. ("This cryptographically proven event violates our internal judicial rules, therefore it is void.")

If you deploy the `judicial-network` without wiring a `scope_limit` interceptor into the read-side verifiers (`verification/case_status.go` and `verification/delegation_chain.go`), you are treating Layer 1 truth as Layer 2 truth. As you correctly identified, that is an open door for a devastating privilege escalation attack. Implement the Semantic State Overlay, and the vulnerability vanishes.




# REGISTRAR OBLIGATIONS
//
// The SDK cannot enforce PoP verification at cosignature-verification
// time because the verifier has no visibility into which public keys
// arrived through PoP-gated registration and which did not. The
// responsibility lives with the registration code path: every admission
// of a BLS public key to a witness set must be preceded by a
// VerifyBLSPoP call, and admissions that fail verification must be
// rejected with no retry.
//
// Domain networks (judicial-network, recording-network) implement the
// registrar. The SDK provides the primitive; the domain enforces the
// invariant.