# crypto/admission

## Purpose
Implements **Ortholog Mode B admission stamps** — a proof-of-work cryptographic gate that submitters attach to entry headers, allowing log operators to autonomously throttle write pressure without managing centralized write credits.

## Functional Surface
| Export | Role |
| --- | --- |
| `GenerateStamp` | Submitter side. Iterates nonces upward, returning the first nonce whose stamp hash meets the required leading-zero difficulty bits. |
| `VerifyStamp` | Operator side. Validates the stamp mode, target-log match, difficulty floor, epoch window, and the recomputed cryptographic hash. |

## Hash Input Layout & Canonicalization
The stamp hash generation MUST adhere to the universal `LengthPrefixed` TupleHash discipline to prevent variable-length boundary-shifting collisions.

The hash inputs consist of:
`EntryHash (32) || Nonce (8) || SubmitterDID (Variable) || Epoch (8) || SubmitterCommit (32)`

Because `SubmitterDID` is variable-length, the hash buffer MUST route its inputs through explicit length-prefixing rather than raw concatenation.

## Domain Separation
Argon2id runs with a fixed salt: `"ortholog-admission-v1"`. The `-v1` suffix partitions outputs from this protocol from outputs of any other protocol reusing Argon2id. Any layout change MUST bump the salt (e.g., `-v2`, `-v3`).

## Dependencies
* `golang.org/x/crypto/argon2` — canonical RFC 9106 Argon2id.
* `types/admission.go` — wire types.
