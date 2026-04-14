package envelope

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type SDKConfig struct {
	AllowNonASCII bool
	NFCNormalizer func(string) string
}

func DefaultConfig() SDKConfig { return SDKConfig{AllowNonASCII: false} }

var globalConfig = DefaultConfig()

func SetGlobalConfig(cfg SDKConfig) { globalConfig = cfg }

const currentProtocolVersion = 3
const MaxEvidencePointers = 10
const MaxDelegationPointers = 3

func NewEntry(header ControlHeader, payload []byte) (*Entry, error) {
	header.ProtocolVersion = currentProtocolVersion
	if header.SignerDID == "" {
		return nil, errors.New("Signer_DID must not be empty")
	}
	var err error
	header.SignerDID, err = normalizeDID(header.SignerDID)
	if err != nil {
		return nil, fmt.Errorf("Signer_DID: %w", err)
	}
	if header.DelegateDID != nil {
		if *header.DelegateDID == "" {
			return nil, errors.New("Delegate_DID must not be empty when set")
		}
		s, err := normalizeDID(*header.DelegateDID)
		if err != nil {
			return nil, fmt.Errorf("Delegate_DID: %w", err)
		}
		header.DelegateDID = &s
	}
	if header.AuthorityDID != nil {
		if *header.AuthorityDID == "" {
			return nil, errors.New("Authority_DID must not be empty when set")
		}
		s, err := normalizeDID(*header.AuthorityDID)
		if err != nil {
			return nil, fmt.Errorf("Authority_DID: %w", err)
		}
		header.AuthorityDID = &s
	}
	if len(header.AuthoritySet) > 0 {
		normalized := make(map[string]struct{}, len(header.AuthoritySet))
		for did := range header.AuthoritySet {
			if did == "" {
				return nil, errors.New("Authority_Set contains empty DID")
			}
			nd, err := normalizeDID(did)
			if err != nil {
				return nil, fmt.Errorf("Authority_Set DID %q: %w", did, err)
			}
			normalized[nd] = struct{}{}
		}
		header.AuthoritySet = normalized
	} else {
		header.AuthoritySet = nil
	}
	if err := normalizeOptionalPosition(&header.TargetRoot); err != nil {
		return nil, fmt.Errorf("Target_Root: %w", err)
	}
	if err := normalizeOptionalPosition(&header.TargetIntermediate); err != nil {
		return nil, fmt.Errorf("Target_Intermediate: %w", err)
	}
	if err := normalizeOptionalPosition(&header.SchemaRef); err != nil {
		return nil, fmt.Errorf("Schema_Ref: %w", err)
	}
	if err := normalizeOptionalPosition(&header.ScopePointer); err != nil {
		return nil, fmt.Errorf("Scope_Pointer: %w", err)
	}
	if err := normalizeOptionalPosition(&header.PriorAuthority); err != nil {
		return nil, fmt.Errorf("Prior_Authority: %w", err)
	}
	if err := normalizeOptionalPosition(&header.CosignatureOf); err != nil {
		return nil, fmt.Errorf("Cosignature_Of: %w", err)
	}
	if err := normalizeOptionalPosition(&header.AuthoritySkip); err != nil {
		return nil, fmt.Errorf("Authority_Skip: %w", err)
	}
	header.EvidencePointers, err = normalizePositionSlice(header.EvidencePointers)
	if err != nil {
		return nil, fmt.Errorf("Evidence_Pointers: %w", err)
	}
	header.DelegationPointers, err = normalizePositionSlice(header.DelegationPointers)
	if err != nil {
		return nil, fmt.Errorf("Delegation_Pointers: %w", err)
	}
	header.ApprovalPointers, err = normalizePositionSlice(header.ApprovalPointers)
	if err != nil {
		return nil, fmt.Errorf("Approval_Pointers: %w", err)
	}
	if len(header.CommutativeOperations) == 0 {
		header.CommutativeOperations = nil
	}
	if len(header.SubjectIdentifier) == 0 {
		header.SubjectIdentifier = nil
	}
	if len(header.DelegationPointers) > MaxDelegationPointers {
		return nil, fmt.Errorf("Delegation_Pointers length %d exceeds max %d", len(header.DelegationPointers), MaxDelegationPointers)
	}
	if len(header.EvidencePointers) > MaxEvidencePointers {
		if !isLikelyAuthoritySnapshot(&header) {
			return nil, fmt.Errorf("Evidence_Pointers length %d exceeds max %d (non-snapshot)", len(header.EvidencePointers), MaxEvidencePointers)
		}
	}
	if header.AdmissionProof != nil && header.AdmissionProof.Mode == types.AdmissionModeB {
		if header.AdmissionProof.TargetLog == "" {
			return nil, errors.New("Mode B Admission_Proof requires non-empty target_log DID")
		}
		header.AdmissionProof.TargetLog, err = normalizeDID(header.AdmissionProof.TargetLog)
		if err != nil {
			return nil, fmt.Errorf("Admission_Proof target_log: %w", err)
		}
	}
	return &Entry{Header: header, DomainPayload: payload}, nil
}

func isLikelyAuthoritySnapshot(h *ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != AuthorityScopeAuthority {
		return false
	}
	return h.TargetRoot != nil && h.PriorAuthority != nil
}

func normalizeDID(did string) (string, error) {
	if did == "" {
		return "", errors.New("DID must not be empty")
	}
	if !globalConfig.AllowNonASCII {
		for i := 0; i < len(did); i++ {
			if did[i] >= 0x80 {
				return "", fmt.Errorf("non-ASCII byte 0x%02x at position %d in ASCII-only mode", did[i], i)
			}
		}
		return did, nil
	}
	if globalConfig.NFCNormalizer == nil {
		return "", errors.New("AllowNonASCII is true but NFCNormalizer is not set")
	}
	return globalConfig.NFCNormalizer(did), nil
}

func normalizeOptionalPosition(pp **types.LogPosition) error {
	if *pp == nil {
		return nil
	}
	p := *pp
	if p.IsNull() {
		*pp = nil
		return nil
	}
	if err := types.ValidateLogPosition(*p); err != nil {
		return err
	}
	nd, err := normalizeDID(p.LogDID)
	if err != nil {
		return err
	}
	p.LogDID = nd
	return nil
}

func normalizePositionSlice(positions []types.LogPosition) ([]types.LogPosition, error) {
	if len(positions) == 0 {
		return nil, nil
	}
	for i := range positions {
		if err := types.ValidateLogPosition(positions[i]); err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		if !positions[i].IsNull() {
			nd, err := normalizeDID(positions[i].LogDID)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			positions[i].LogDID = nd
		}
	}
	return positions, nil
}
