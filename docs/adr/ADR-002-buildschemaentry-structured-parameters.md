# ADR-002: BuildSchemaEntry Structured Parameters + Round-Trip Invariant

**Status:** Accepted (v7.5 "Option B")
**Related:** ADR-001 (legitimacy test)

## Context

Pre-v7.5 `BuildSchemaEntry` accepted `Payload []byte` — the caller
was responsible for producing JSON bytes that
`JSONParameterExtractor` could later read. The two sides — builder
serialises bytes, extractor deserialises bytes — shared no schema.
A typo in a caller's JSON key name silently produced a schema entry
whose parameters extracted as defaults. Weeks or months later, the
corrupted schema would quietly govern live operations with the wrong
activation delay, the wrong cosignature threshold, the wrong grant
authorization mode. No test surface existed to catch the drift.

## Decision

`BuildSchemaEntry` accepts a structured `types.SchemaParameters`.
Internally it calls `schema.MarshalParameters` to produce canonical
JSON bytes, which become the entry's `DomainPayload`. Every
downstream reader goes through `JSONParameterExtractor.Extract`, the
inverse of `MarshalParameters`.

**Round-trip invariant (permanent regression gate):** for every
valid `p *types.SchemaParameters`,
`Extract(Marshal(p))` must `reflect.DeepEqual(p)`.
Enforced by `schema/parameters_json_roundtrip_test.go` — an
exhaustive combinatorial table covering every enum value, every
optional-field shape, the all-defaults case, and the all-non-default
case. Every new parameter added to `SchemaParameters` MUST extend
the table. Failure there blocks the change until symmetry is
restored.

**Marshal shape (Option A):**

- Value-type marshal struct, not pointer.
- Every scalar field emitted unconditionally (eliminates "absent" vs
  "zero" ambiguity).
- `CredentialValidityPeriod` nil sentinel: `-1` (documented at
  `credentialValidityPeriodNilSentinel`; a real schema never sets
  negative validity).
- `MigrationPolicy` zero-value sentinel: empty string (the enum
  starts at 1; zero means "unset").
- `PredecessorSchema`, `ReEncryptionThreshold` keep pointer-to-
  struct; JSON null is their natural empty form.
- `CommutativeOperations` emits `[]` when empty (never `null`).

## Benefits

1. **Build-time validation.** Enum values checked against typed
   constants. A typo ceases to be a run-time surprise.
2. **Canonical bytes across callers.** Every caller producing
   identical `SchemaParameters` produces byte-identical wire output.
   Eliminates "my schema extracts as defaults but I know I set the
   field" bugs.
3. **Single source of truth.** The marshal/extract pair lives in
   `schema/parameters_json.go`. A new parameter touches one file
   twice (add field, update round-trip test), not a scatter of
   callers and docs.
4. **Clean landing for schema-scope fields.** `CommutativeOperations`
   (v7.5 move from `ControlHeader` to `SchemaParameters`) flows
   through the builder automatically. No caller touches raw JSON.

## Cost

Every caller of `BuildSchemaEntry` changes — once, at v7.5.
Callers update from hand-rolled JSON to structured parameters. In
v7.5's clean-slate posture that cost is paid once; deferring pays
it again on the next wire-breaking migration.

## Scope boundary

Option B applies **only** to `BuildSchemaEntry`. The other 17
builders keep `Payload []byte`: for non-schema entries the payload
shape is genuinely domain-opaque, and the SDK has nothing to marshal.
Structured parameters make sense exactly because schema payloads
are the one entry type whose shape the SDK knows.
