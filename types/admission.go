// FILE PATH:
//
//	types/admission.go
//
// DESCRIPTION:
//
//	Defines the canonical AdmissionProof wire-type carried by Ortholog entry
//	Control Headers. The admission proof is the operator's gate against
//	denial-of-service and Sybil submission: entries arriving without a valid
//	proof (either a Mode A write credit or a Mode B hashcash stamp) are
//	rejected at the admission boundary before any SMT work occurs.
//
// KEY ARCHITECTURAL DECISIONS:
//   - One stamp mode (Mode B) carries ALL proof fields: nonce, target log,
//     difficulty, epoch, and an optional submitter commitment. A second mode
//     would duplicate logic for no semantic gain — one correct mode beats
//     two partially-correct modes.
//   - SubmitterCommit uses *[32]byte rather than []byte. The pointer-to-
//     fixed-array idiom encodes the invariant "if present, exactly 32 bytes"
//     in the type system, eliminating length-validation logic in every
//     downstream consumer. nil means absent; non-nil is guaranteed 32 bytes
//     by the language.
//   - Wire-byte aliases (WireByteModeA / WireByteModeB) are exported as
//     uint8 next to the typed AdmissionMode constants. External code that
//     constructs envelope.AdmissionProofBody directly (whose Mode field is
//     uint8 by wire-format constraint) references the aliases instead of
//     guessing numeric values or casting through uint8(). The aliases are
//     defined as uint8(AdmissionModeA/B) so they cannot drift from the
//     typed constants — and crypto/admission/wire_encoding_test.go locks
//     both the equality and the absolute numeric values.
//   - This package contains zero logic. It is the shared vocabulary between
//     serialization (core/envelope), verification (crypto/admission), and
//     operator policy (lifecycle/difficulty). No imports beyond stdlib are
//     permitted at this layer.
//
// OVERVIEW:
//
//	An AdmissionProof is attached to a Control Header at construction time
//	by the submitting exchange. For Mode A (write credit), the proof is nil
//	on the wire and the operator validates the submitter's credit balance
//	out-of-band. For Mode B (stamp), the submitter computes a hashcash-style
//	nonce such that H(entry_hash || nonce || log_did || epoch || commit)
//	has the required leading zero bits. The operator re-computes the same
//	hash and accepts or rejects.
//
//	Epoch binding prevents an attacker from harvesting stamps over time and
//	replaying them in a burst. SubmitterCommit binds a stamp to a specific
//	requester identity when the operator enforces per-submitter rate limits.
//
// KEY DEPENDENCIES:
//   - (none): this file is a leaf in the dependency graph.
package types

// -------------------------------------------------------------------------------------------------
// 1) Admission mode vocabulary
// -------------------------------------------------------------------------------------------------

// AdmissionMode selects the admission proof type carried in a Control Header.
// The uint8 representation is wire-format-stable: changing a constant's
// numeric value is a breaking protocol change.
type AdmissionMode uint8

const (
	// AdmissionModeA indicates a write-credit submission: no stamp is
	// required on the wire because the operator validates the submitter's
	// credit balance through a separate authenticated channel. The entry's
	// AdmissionProof field MUST be nil when this mode applies.
	AdmissionModeA AdmissionMode = 0

	// AdmissionModeB indicates a hashcash-style proof-of-work stamp bound
	// to the entry hash, target log DID, current epoch, and an optional
	// submitter commitment. All Mode B fields on AdmissionProof are
	// REQUIRED except SubmitterCommit, which MAY be nil.
	AdmissionModeB AdmissionMode = 1
)

// -------------------------------------------------------------------------------------------------
// 2) Wire-byte aliases
//
// These uint8 aliases exist because envelope.AdmissionProofBody.Mode is a
// uint8 (wire-format requirement) and external code that constructs the
// wire body directly should not have to write `uint8(types.AdmissionModeB)`
// or — worse — guess `1` from reading source.
//
// They are defined as uint8(AdmissionModeA/B) so they CANNOT drift from
// the typed constants by accident. The regression test in
// crypto/admission/wire_encoding_test.go additionally pins the absolute
// numeric values (WireByteModeA == 0, WireByteModeB == 1) so reordering
// the iota would fail the SDK build before breaking downstream consumers.
//
// History: pre-v0.2, consumers had to discover wire byte values by reading
// source. Operators routinely guessed wrong (assumed iota started at 1 →
// wire byte 2 for ModeB) and only learned via ProofFromWire-then-VerifyStamp
// integration test failures. These aliases eliminate that discovery loop.
// -------------------------------------------------------------------------------------------------

const (
	// WireByteModeA is the uint8 wire encoding of AdmissionModeA. Use this
	// when constructing envelope.AdmissionProofBody from external code:
	//   body := &envelope.AdmissionProofBody{Mode: types.WireByteModeA, ...}
	WireByteModeA uint8 = uint8(AdmissionModeA)

	// WireByteModeB is the uint8 wire encoding of AdmissionModeB. Use this
	// when constructing envelope.AdmissionProofBody from external code:
	//   body := &envelope.AdmissionProofBody{Mode: types.WireByteModeB, ...}
	WireByteModeB uint8 = uint8(AdmissionModeB)
)

// -------------------------------------------------------------------------------------------------
// 3) AdmissionProof wire type
// -------------------------------------------------------------------------------------------------

// AdmissionProof is the admission evidence carried in an entry's Control Header.
// Field semantics depend on Mode:
//
//	Mode A: the AdmissionProof field on the Control Header MUST be nil.
//	        This struct is not instantiated for Mode A entries.
//
//	Mode B: Nonce, TargetLog, Difficulty, and Epoch are REQUIRED.
//	        SubmitterCommit is OPTIONAL. If non-nil, it is exactly 32 bytes
//	        (enforced by the pointer-to-array type) and is bound into the
//	        stamp hash. If nil, the commit slot in the hash input is
//	        zero-filled and the presence byte is 0.
//
// Field descriptions:
//
//	Mode            — admission mode selector; see AdmissionMode constants.
//	Nonce           — the proof-of-work counter found by the submitter.
//	TargetLog       — the log DID this stamp is bound to. A stamp computed
//	                  for log A is invalid on log B by construction, because
//	                  the DID is part of the hash input.
//	Difficulty      — required leading zero bits in the stamp hash. Range
//	                  is 1..256 inclusive; values outside this range are
//	                  rejected by the admission package.
//	Epoch           — the current epoch index at stamp generation time.
//	                  Computed as floor(unix_seconds / epoch_window_seconds).
//	                  The operator rejects stamps whose epoch is outside
//	                  its configured acceptance window.
//	SubmitterCommit — optional 32-byte binding to the submitter's identity
//	                  or request, used when the operator enforces per-
//	                  submitter rate limits. nil when absent.
type AdmissionProof struct {
	Mode            AdmissionMode
	Nonce           uint64
	TargetLog       string
	Difficulty      uint32
	Epoch           uint64
	SubmitterCommit *[32]byte
}
