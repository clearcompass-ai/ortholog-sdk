package types

type AdmissionMode uint8

const (
	AdmissionModeA AdmissionMode = 0
	AdmissionModeB AdmissionMode = 1
)

type AdmissionProof struct {
	Mode       AdmissionMode
	Nonce      uint64
	TargetLog  string
	Difficulty uint32
}
