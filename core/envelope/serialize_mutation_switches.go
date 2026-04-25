// Package envelope — serialize_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switches for serialize.go. Declared
// in their own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the four invariant checks the         │
//	│  envelope serializer enforces. Setting any to false         │
//	│  permanently breaks the canonical-form contract every       │
//	│  Ortholog log entry depends on: hash-chain integrity,       │
//	│  protocol-version compatibility, size-cap enforcement, and  │
//	│  destination binding. The switches exist so the audit       │
//	│  runner can flip them and observe that the binding tests    │
//	│  fire; any other use is wrong.                              │
//	│                                                             │
//	│  Binding tests (core/envelope/serialize.mutation-audit.yaml): │
//	│    muEnableCanonicalOrdering →                              │
//	│      TestDeserialize_RejectsTrailingBytes_Binding           │
//	│    muEnableSizeCap           →                              │
//	│      TestDeserialize_RejectsOversize_Binding                │
//	│    muEnableVersionReject     →                              │
//	│      TestDeserialize_RejectsUnsupportedVersion_Binding      │
//	│    muEnableDestinationBound  →                              │
//	│      TestValidateHeader_RejectsEmptyDestination_Binding     │
//	└─────────────────────────────────────────────────────────────┘
package envelope

// muEnableCanonicalOrdering gates the strict-trailing-bytes check
// that the signatures section consumes the entire suffix of the
// canonical buffer. When off, trailing bytes after the signatures
// section are silently ignored — admitting hash-chain ambiguity
// (two distinct byte sequences would deserialize to the same
// Entry, breaking the canonical-form contract that hashing the
// entry produces a unique identity).
const muEnableCanonicalOrdering = true

// muEnableSizeCap gates the MaxCanonicalBytes bound check inside
// Deserialize. When off, oversize buffers are accepted at
// deserialize; downstream consumers (Tessera bundle parser,
// admission pipeline) hit different errors at unpredictable
// boundaries.
const muEnableSizeCap = true

// muEnableVersionReject gates the CheckReadAllowed protocol-
// version check inside Deserialize. When off, entries claiming
// unsupported (past or future) protocol versions deserialize
// without error — admitting silent forward-incompatibility and
// downgrade attacks.
const muEnableVersionReject = true

// muEnableDestinationBound gates the ValidateDestination call
// inside validateHeaderForWrite. When off, entries with empty,
// whitespace-only, or oversize destinations admit at write time
// — readmitting cross-exchange replay (the canonical-hash
// destination-binding property fails the moment Destination
// validation is bypassed).
const muEnableDestinationBound = true
