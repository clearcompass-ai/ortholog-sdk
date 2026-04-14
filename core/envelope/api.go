package envelope

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// SDKConfig controls SDK-wide behavior set at initialization.
type SDKConfig struct {
	// AllowNonASCII enables full NFC normalization for non-ASCII DID methods (SDK-D15).
	// Default false: bytes >= 0x80 in DIDs are rejected (fail-closed).
	AllowNonASCII bool

	// NFCNormalizer performs NFC normalization on a string.
	// Required when AllowNonASCII is true. Typically set to
	// golang.org/x/text/unicode/norm.NFC.String.
	// Ignored in ASCII-only mode.
	NFCNormalizer func(string) string
}

// DefaultConfig returns the default SDK configuration (ASCII-only mode).
func DefaultConfig() SDKConfig {
	return SDKConfig{AllowNonASCII: false}
}

var globalConfig = DefaultConfig()

// SetGlobalConfig sets the SDK-wide configuration. Must be called before any
// entry construction. Not safe for concurrent use — call once at startup.
func SetGlobalConfig(cfg SDKConfig) {
	globalConfig = cfg
}

// currentProtocolVersion is the only supported version.
const currentProtocolVersion = 3

// MaxEvidencePointers is the cap for non-snapshot entries (Decision 51).
const MaxEvidencePointers = 10

// MaxDelegationPointers is the max delegation chain depth.
const MaxDelegationPointers = 3

// NewEntry constructs a validated entry. All DID strings are NFC-normalized.
// Empty DIDs are rejected. Empty arrays are normalized to nil.
// Protocol_Version is forced to 3. Evidence_Pointers cap is enforced.
func NewEntry(header ControlHeader, payload []byte) (*Entry, error) {
	header.ProtocolVersion = currentProtocolVersion

	// Normalize and validate Signer_DID (required, never empty).
	if header.SignerDID == "" {
		return nil, errors.New("Signer_DID must not be empty")
	}
	var err error
	header.SignerDID, err = normalizeDID(header.SignerDID)
	if err != nil {
		return nil, fmt.Errorf("Signer_DID: %w", err)
	}

	// Normalize optional DID fields.
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

	// Normalize Authority_Set DIDs.
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
		header.AuthoritySet = nil // empty -> nil canonical equivalence
	}

	// Normalize LogPosition DIDs in all position fields.
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

	// Normalize position slices.
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

	// Empty arrays -> nil (canonical equivalence).
	if len(header.CommutativeOperations) == 0 {
		header.CommutativeOperations = nil
	}
	if len(header.SubjectIdentifier) == 0 {
		header.SubjectIdentifier = nil
	}

	// Validate Delegation_Pointers max length.
	if len(header.DelegationPointers) > MaxDelegationPointers {
		return nil, fmt.Errorf("Delegation_Pointers length %d exceeds max %d",
			len(header.DelegationPointers), MaxDelegationPointers)
	}

	// Validate Evidence_Pointers cap (Decision 51).
	// Snapshot entries are exempt. Snapshot heuristic: Authority_Path == scope_authority
	// AND Target_Root set AND Prior_Authority set AND Evidence_Pointers > 0.
	if len(header.EvidencePointers) > MaxEvidencePointers {
		if !isLikelyAuthoritySnapshot(&header) {
			return nil, fmt.Errorf("Evidence_Pointers length %d exceeds max %d (non-snapshot)",
				len(header.EvidencePointers), MaxEvidencePointers)
		}
	}

	// Validate AdmissionProof target log DID if present.
	if header.AdmissionProof != nil && header.AdmissionProof.Mode == types.AdmissionModeB {
		if header.AdmissionProof.TargetLog == "" {
			return nil, errors.New("Mode B Admission_Proof requires non-empty target_log DID")
		}
		header.AdmissionProof.TargetLog, err = normalizeDID(header.AdmissionProof.TargetLog)
		if err != nil {
			return nil, fmt.Errorf("Admission_Proof target_log: %w", err)
		}
	}

	return &Entry{
		Header:        header,
		DomainPayload: payload,
	}, nil
}

// isLikelyAuthoritySnapshot uses the heuristic from Decision 51:
// Authority_Path == scope_authority AND Target_Root set AND Prior_Authority set.
func isLikelyAuthoritySnapshot(h *ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != AuthorityScopeAuthority {
		return false
	}
	if h.TargetRoot == nil {
		return false
	}
	if h.PriorAuthority == nil {
		return false
	}
	return true
}

// normalizeDID applies NFC normalization to a DID string per SDK-D15.
// In ASCII-only mode (default), bytes >= 0x80 cause rejection (fail-closed).
// In full-NFC mode, non-ASCII bytes are NFC-normalized.
func normalizeDID(did string) (string, error) {
	if did == "" {
		return "", errors.New("DID must not be empty")
	}

	if !globalConfig.AllowNonASCII {
		// ASCII fast path: reject any byte >= 0x80.
		for i := 0; i < len(did); i++ {
			if did[i] >= 0x80 {
				return "", fmt.Errorf("non-ASCII byte 0x%02x at position %d in ASCII-only mode", did[i], i)
			}
		}
		// ASCII strings are already NFC (identity operation).
		return did, nil
	}

	// Full NFC normalization for non-ASCII DID methods.
	if globalConfig.NFCNormalizer == nil {
		return "", errors.New("AllowNonASCII is true but NFCNormalizer is not set")
	}
	return globalConfig.NFCNormalizer(did), nil
}

// normalizeOptionalPosition normalizes the DID within an optional LogPosition.
func normalizeOptionalPosition(pp **types.LogPosition) error {
	if *pp == nil {
		return nil
	}
	p := *pp
	if p.IsNull() {
		*pp = nil // Normalize explicit null to nil pointer.
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

// normalizePositionSlice normalizes DIDs in a LogPosition slice.
// Empty slices become nil (canonical equivalence).
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
