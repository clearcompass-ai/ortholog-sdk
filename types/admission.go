package types

// AdmissionMode identifies the admission proof type.
type AdmissionMode uint8

const (
	AdmissionModeA AdmissionMode = 0 // Fiat credits: null proof on entry
	AdmissionModeB AdmissionMode = 1 // Compute stamp: nonce + target_log + difficulty
)

// AdmissionProof is the admission evidence carried in the Control Header.
// Mode A: nil (fiat write credits, proof is the authenticated session).
// Mode B: compute stamp bound to target log DID.
type AdmissionProof struct {
	Mode      AdmissionMode
	Nonce     uint64 // Mode B only
	TargetLog string // Mode B only: DID of target log (stamp binding)
	Difficulty uint32 // Mode B only: difficulty target
}
