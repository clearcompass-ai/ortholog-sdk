// In crypto/admission/adapter.go (new file)
package admission

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ProofFromWire translates a wire-format admission proof body into the
// API form consumed by VerifyStamp. Operators receive AdmissionProofBody
// inside entry headers; VerifyStamp expects types.AdmissionProof. This
// adapter centralizes the translation so consumers don't reimplement it.
//
// The targetLog argument supplies the verification context — typically
// the operator's own LogDID. The wire format omits this because the
// binding is implicit at admission time.
func ProofFromWire(body *envelope.AdmissionProofBody, targetLog string) *types.AdmissionProof {
	if body == nil {
		return nil
	}
	return &types.AdmissionProof{
		Mode:            types.AdmissionMode(body.Mode),
		Nonce:           body.Nonce,
		TargetLog:       targetLog,
		Difficulty:      uint32(body.Difficulty),
		Epoch:           body.Epoch,
		SubmitterCommit: body.SubmitterCommit,
	}
}
