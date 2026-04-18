# Patches to apply to existing files

Each section below shows the exact old→new change for one existing file.
Apply in order. All patches are mechanical — no design decisions in the diff.

---

## 1. `core/envelope/entry.go`

**Add** a `Destination` field to the `Entry` struct. Position it immediately
after `SignerDID` so the struct literal order in builder/test code is
obvious.

```go
type Entry struct {
    Version      uint16
    SignerDID    string
    Destination  string   // ← ADD THIS. DID of the target exchange. Required.
    // ... all other existing fields unchanged ...
}
```

Add a validation method (or update the existing one):

```go
// Validate returns a non-nil error if any invariant on the Entry is violated.
// Called by the serializer before producing a canonical hash, and by the
// ingestion policy layer before append-to-log.
func (e *Entry) Validate() error {
    if err := ValidateDestination(e.Destination); err != nil {
        return err
    }
    if e.SignerDID == "" {
        return errors.New("envelope: SignerDID must not be empty")
    }
    // ... any existing validation ...
    return nil
}
```

---

## 2. `core/envelope/serialize.go`

**Include** `Destination` in the serialized form immediately after `SignerDID`.
The canonical hash is computed over the serialized bytes, so this change
automatically binds the hash to the destination.

Inside the `Serialize` function, after the block that writes `SignerDID`:

```go
// BEFORE (existing SignerDID write block):
binary.Write(&buf, binary.BigEndian, uint16(len(entry.SignerDID)))
buf.WriteString(entry.SignerDID)

// AFTER: add these lines immediately after the SignerDID block:
binary.Write(&buf, binary.BigEndian, uint16(len(entry.Destination)))
buf.WriteString(entry.Destination)
```

And the matching `Deserialize` addition, in the same relative position:

```go
// Read Destination (new, after SignerDID):
var destLen uint16
if err := binary.Read(r, binary.BigEndian, &destLen); err != nil {
    return nil, fmt.Errorf("read destination len: %w", err)
}
destBuf := make([]byte, destLen)
if _, err := io.ReadFull(r, destBuf); err != nil {
    return nil, fmt.Errorf("read destination: %w", err)
}
entry.Destination = string(destBuf)
```

Add to `Serialize`'s preamble (before writing any bytes):

```go
if err := entry.Validate(); err != nil {
    return nil, fmt.Errorf("serialize: entry invalid: %w", err)
}
```

This ensures every serialized entry has a non-empty destination. Fail-loud.

---

## 3. `builder/entry_builders.go`

Every `*Config` struct gets a `Destination` field at the top. Every `Build*`
function validates it non-empty and copies it into the `Entry`.

Mechanical pattern — apply to ALL 18 builders:

```go
// BEFORE:
type AmendmentConfig struct {
    SignerDID  string
    TargetRoot types.LogPosition
    // ... other fields ...
}

func BuildAmendment(cfg AmendmentConfig) (*envelope.Entry, error) {
    if cfg.SignerDID == "" {
        return nil, errors.New("builder: SignerDID required")
    }
    // ...

// AFTER:
type AmendmentConfig struct {
    Destination string                // ← ADD. Required — DID of target exchange.
    SignerDID   string
    TargetRoot  types.LogPosition
    // ... other fields ...
}

func BuildAmendment(cfg AmendmentConfig) (*envelope.Entry, error) {
    if err := envelope.ValidateDestination(cfg.Destination); err != nil {
        return nil, fmt.Errorf("builder: %w", err)
    }
    if cfg.SignerDID == "" {
        return nil, errors.New("builder: SignerDID required")
    }
    // ...
    entry := &envelope.Entry{
        // ... existing field init ...
        Destination: cfg.Destination,          // ← ADD to every Entry construction
        SignerDID:   cfg.SignerDID,
        // ...
    }
    // ...
```

Do this for every `Build*` function. The pattern is identical:

- Add `Destination string` as the first field of every `*Config`
- Validate with `envelope.ValidateDestination` as the first check in `Build*`
- Copy `cfg.Destination` into every constructed `Entry`

Apply to: `BuildRootEntity`, `BuildAmendment`, `BuildDelegation`,
`BuildSuccession`, `BuildEnforcement`, `BuildScopeCreation`,
`BuildScopeAmendment`, `BuildCommentary`, `BuildCosignature`,
`BuildKeyRotation`, `BuildKeyPrecommit`, `BuildPathBEntry`,
`BuildRevocation`, `BuildScopeRemoval`, `BuildRecoveryRequest`,
`BuildAnchorEntry`, `BuildMirrorEntry`, `BuildSchemaEntry`.

---

## 4. `did/verifier_registry.go`

The registry is destination-scoped. Constructor takes a destination DID.
Add a new high-level method `VerifyEntry` that checks destination before
verifying signature.

```go
// BEFORE:
type VerifierRegistry struct {
    verifiers map[string]SignatureVerifier
}

func NewVerifierRegistry() *VerifierRegistry { /* ... */ }

func DefaultVerifierRegistry(resolver DIDResolver) *VerifierRegistry { /* ... */ }

func (r *VerifierRegistry) Verify(did string, hash []byte, sig []byte, algoID uint16) error {
    // ...
}

// AFTER:
type VerifierRegistry struct {
    destination string                              // ← ADD
    verifiers   map[string]SignatureVerifier
}

// NewVerifierRegistry constructs a destination-scoped registry. The
// destination DID identifies this exchange and is checked against
// entry.Destination during VerifyEntry. A registry cannot verify entries
// bound to a different destination.
func NewVerifierRegistry(destinationDID string) (*VerifierRegistry, error) {
    if err := envelope.ValidateDestination(destinationDID); err != nil {
        return nil, fmt.Errorf("did/registry: %w", err)
    }
    return &VerifierRegistry{
        destination: destinationDID,
        verifiers:   map[string]SignatureVerifier{},
    }, nil
}

// DefaultVerifierRegistry wires did:key, did:pkh, did:web verifiers into a
// destination-scoped registry.
func DefaultVerifierRegistry(destinationDID string, resolver DIDResolver) *VerifierRegistry {
    r, err := NewVerifierRegistry(destinationDID)
    if err != nil {
        panic(fmt.Sprintf("did/registry: DefaultVerifierRegistry: %v", err))
    }
    r.MustRegister("pkh", &PKHVerifier{})
    r.MustRegister("key", NewKeyVerifier())
    r.MustRegister("web", NewWebVerifier(resolver))
    return r
}

// Destination returns the DID this registry is scoped to.
func (r *VerifierRegistry) Destination() string {
    return r.destination
}

// Verify is the low-level primitive: verifies a signature against a
// canonical hash (which, by construction, already includes destination
// binding if the caller used envelope.CanonicalHash correctly). Callers
// that have an *envelope.Entry in hand should use VerifyEntry instead.
func (r *VerifierRegistry) Verify(did string, hash []byte, sig []byte, algoID uint16) error {
    // ... existing body unchanged ...
}

// VerifyEntry is the high-level method: asserts that entry.Destination
// matches this registry's destination, then computes the canonical hash
// and verifies the signature. The destination check is what prevents
// cross-exchange replay: an entry bound to Exchange A will not verify
// against Exchange B's registry, even if the signature is cryptographically
// valid.
func (r *VerifierRegistry) VerifyEntry(entry *envelope.Entry) error {
    if entry == nil {
        return errors.New("did/registry: entry is nil")
    }
    if entry.Destination != r.destination {
        return fmt.Errorf(
            "did/registry: destination mismatch: entry bound to %q, registry is for %q",
            entry.Destination, r.destination,
        )
    }
    if err := entry.Validate(); err != nil {
        return fmt.Errorf("did/registry: %w", err)
    }
    hash, err := envelope.CanonicalHash(entry)
    if err != nil {
        return fmt.Errorf("did/registry: canonical hash: %w", err)
    }
    sig, algoID, err := envelope.ExtractSignature(entry)
    if err != nil {
        return fmt.Errorf("did/registry: extract signature: %w", err)
    }
    return r.Verify(entry.SignerDID, hash[:], sig, algoID)
}
```

The method names `ExtractSignature` and `CanonicalHash` reflect whatever
the existing helpers are called in your envelope package; adjust if they
differ.

---

## 5. `exchange/auth/signed_request.go`

Add `VerifyRequestOptions` and validity-window constants at the top of the
file (or in a new section near the existing `NonceStore` interface).

```go
// ADD these constants and types. Position them near the top of the file
// after the existing envelope type.

// -------------------------------------------------------------------------
// Validity window constants
// -------------------------------------------------------------------------

// Validity windows are operator policy, not protocol rules. Choose per
// endpoint category based on who signs and how quickly they're expected to.
// Pass the chosen value as VerifyRequestOptions.ValidityWindow.

const (
    // ValidityAutomated is for automated machine-to-machine signed requests
    // (operator ingestion, witness cosignatures, cross-log anchoring).
    // Replays must be detected within seconds.
    ValidityAutomated = 60 * time.Second

    // ValidityInteractive is for human-operator signed actions (clerk filings,
    // administrative signings). Accommodates UI latency and brief human
    // reaction time.
    ValidityInteractive = 5 * time.Minute

    // ValidityDeliberative is for deliberative judicial signings (orders,
    // opinions, rulings). Accommodates the normal review-and-decide
    // cadence of judicial review.
    ValidityDeliberative = 30 * time.Minute

    // MaxValidityWindow is the hard ceiling VerifyRequest accepts.
    // Requests declaring a longer window are rejected unconditionally.
    // Longer windows indicate either a configuration mistake or a design
    // that needs revisiting (pre-signed durable actions should use a
    // different mechanism).
    MaxValidityWindow = 1 * time.Hour

    // MaxClockSkew is the asymmetric tolerance for "issued in the future"
    // — clocks on signer and verifier may differ by this much without
    // rejection.
    MaxClockSkew = 30 * time.Second
)

// -------------------------------------------------------------------------
// VerifyRequestOptions
// -------------------------------------------------------------------------

// VerifyRequestOptions carries per-endpoint policy for VerifyRequest.
// The caller chooses ValidityWindow (Machine/Staff/Judge or a custom
// duration <= MaxValidityWindow) and supplies a NonceStore IF the endpoint
// requires replay protection.
//
// NonceStore is optional but its absence is an explicit decision: the
// caller must set AllowNoReplayCheck=true to confirm they've chosen not to
// enforce replay protection at this endpoint. Log-entry endpoints (where
// the log's canonical-hash dedup provides replay protection) are the
// intended use case. For any endpoint whose signed request does NOT
// become a log entry, set a NonceStore.
type VerifyRequestOptions struct {
    // Nonces, if non-nil, enforces strict-forever single-use of every
    // signed request nonce. See exchange/auth/nonce_store.go for the
    // interface contract.
    Nonces NonceStore

    // AllowNoReplayCheck must be set to true if Nonces is nil. This is a
    // deliberate opt-in preventing accidental omission.
    AllowNoReplayCheck bool

    // ValidityWindow is the maximum (ExpiresAt - IssuedAt). If zero,
    // defaults to ValidityInteractive. Values greater than MaxValidityWindow
    // are rejected.
    ValidityWindow time.Duration

    // Now, if non-nil, overrides the verifier's current time. For tests.
    Now func() time.Time
}

// MODIFY VerifyRequest to accept VerifyRequestOptions instead of a bare
// NonceStore parameter. The signature becomes:
//
//     func VerifyRequest(
//         ctx context.Context,
//         req *SignedRequest,
//         registry *did.VerifierRegistry,
//         opts VerifyRequestOptions,
//     ) error
//
// Inside VerifyRequest:
//
//   1. Validate options
//   2. Check destination in the envelope matches registry.Destination()
//   3. Check clock skew: IssuedAt must be within MaxClockSkew of now
//   4. Check expiry: ExpiresAt must be in the future
//   5. Check validity window: ExpiresAt - IssuedAt <= opts.ValidityWindow
//      (or default), and <= MaxValidityWindow unconditionally
//   6. Verify signature via registry
//   7. IF opts.Nonces != nil: Reserve the nonce (strict-forever)
//      ELSE IF !opts.AllowNoReplayCheck: return error
//      ELSE: skip replay check
```

The exact body edits depend on the existing function structure — apply the
seven checks in the listed order.
