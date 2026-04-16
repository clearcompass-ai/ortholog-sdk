// FILE PATH:
//     core/envelope/api.go
//
// DESCRIPTION:
//     Public API for constructing Ortholog Entry values from a Control Header
//     and Domain Payload. Performs normalization (DID NFC/ASCII rules, position
//     canonicalization) and structural validation (bounds on pointer-slice
//     lengths, admission proof invariants) before returning a ready-to-serialize
//     Entry. All protocol-level invariants that do NOT require cross-entry
//     context (which belongs to the builder) are enforced here.
//
// KEY ARCHITECTURAL DECISIONS:
//     - Protocol version is 4. This is the first version of the wire format
//       that carries the final admission proof shape (epoch + optional
//       submitter commit) and the length-prefixed admission proof body.
//       Earlier protocol versions are not supported; entries with other
//       versions are rejected by the serializer.
//     - Size limits are exported as package-level constants. Middleware,
//       API handlers, and storage backends reference these directly rather
//       than hardcoding numeric literals. Any change to a limit is a
//       single-point change.
//     - Admission proof validation here covers the cases that do not require
//       cryptographic verification: mode correctness, target log presence,
//       DID normalization. The stamp hash is verified at admission time by
//       the operator using crypto/admission.VerifyStamp.
//
// OVERVIEW:
//     NewEntry is the sole constructor. It accepts a raw ControlHeader and
//     payload bytes, overwrites ProtocolVersion with the current constant,
//     normalizes every DID field and every optional/list position, enforces
//     pointer-slice bounds, and validates the AdmissionProof shape. On any
//     normalization or validation failure, returns a descriptive error
//     identifying the offending field by its protocol name.
//
//     DID normalization depends on globalConfig.AllowNonASCII:
//       - false (default): reject any byte >= 0x80. DIDs are ASCII-only.
//       - true: require a registered NFCNormalizer and apply it. Non-ASCII
//         DIDs pass through after NFC normalization.
//     The default is strict ASCII because DID comparison semantics for
//     non-ASCII inputs require explicit Unicode handling that every caller
//     must opt into.
//
// KEY DEPENDENCIES:
//     - types/log_position.go: LogPosition structural validation.
//     - types/admission.go: AdmissionProof wire type.
//     - core/envelope/control_header.go: ControlHeader struct.
//     - core/envelope/entry.go: Entry struct.
package envelope

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) SDK configuration
// -------------------------------------------------------------------------------------------------

// SDKConfig controls SDK-wide normalization behavior. Currently the only
// knob is AllowNonASCII, which switches DID normalization between
// strict-ASCII (default) and NFC-with-caller-supplied-normalizer.
type SDKConfig struct {
	AllowNonASCII bool
	NFCNormalizer func(string) string
}

// DefaultConfig returns the strict default: ASCII-only DIDs, no normalizer.
func DefaultConfig() SDKConfig { return SDKConfig{AllowNonASCII: false} }

// globalConfig holds the process-wide SDK configuration. Mutated only via
// SetGlobalConfig, typically at program startup.
var globalConfig = DefaultConfig()

// SetGlobalConfig replaces the global SDK configuration. Intended for
// one-time configuration at program initialization. Concurrent mutation
// with active NewEntry calls produces undefined DID-normalization behavior
// and is the caller's responsibility to avoid.
func SetGlobalConfig(cfg SDKConfig) { globalConfig = cfg }

// -------------------------------------------------------------------------------------------------
// 2) Protocol version and size limits
// -------------------------------------------------------------------------------------------------

// currentProtocolVersion is the wire format version produced and accepted
// by this SDK. Serialize writes this value; Deserialize rejects any other.
const currentProtocolVersion = 4

// MaxEvidencePointers bounds the number of Evidence_Pointers entries a
// non-snapshot Control Header may carry. Authority snapshots are exempt
// from this bound; see isLikelyAuthoritySnapshot.
const MaxEvidencePointers = 10

// MaxDelegationPointers bounds the number of Delegation_Pointers entries
// a Control Header may carry. Corresponds to the protocol's maximum
// delegation chain depth.
const MaxDelegationPointers = 3

// MaxCanonicalBytes is the maximum serialized entry size accepted by
// the SDK and by any operator adhering to SDK-D11. Admission middleware
// and content-store interfaces reference this constant directly.
const MaxCanonicalBytes = 1 << 20 // 1 MiB

// -------------------------------------------------------------------------------------------------
// 3) Entry construction
// -------------------------------------------------------------------------------------------------

// NewEntry validates and normalizes a Control Header, then returns a fully
// constructed Entry ready for serialization. The ProtocolVersion field on
// the header is set unconditionally; any caller-supplied value is ignored.
//
// Validation covers:
//   - Signer_DID presence and normalization.
//   - Optional DID fields (Delegate_DID, Authority_DID): if present, must
//     be non-empty and normalizable.
//   - Authority_Set: every member must be non-empty and normalizable.
//     Empty sets are replaced with nil for wire-format uniformity.
//   - Every optional and repeated LogPosition: valid structure and
//     normalized DID component.
//   - Pointer-slice bounds: Delegation_Pointers ≤ MaxDelegationPointers;
//     Evidence_Pointers ≤ MaxEvidencePointers unless the entry is a
//     well-formed authority snapshot.
//   - Admission proof: Mode B stamps require a non-empty, normalizable
//     TargetLog. Further cryptographic validation is deferred to the
//     admission layer.
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
		return nil, fmt.Errorf("Delegation_Pointers length %d exceeds max %d",
			len(header.DelegationPointers), MaxDelegationPointers)
	}
	if len(header.EvidencePointers) > MaxEvidencePointers {
		if !isLikelyAuthoritySnapshot(&header) {
			return nil, fmt.Errorf("Evidence_Pointers length %d exceeds max %d (non-snapshot)",
				len(header.EvidencePointers), MaxEvidencePointers)
		}
	}

	if header.AdmissionProof != nil {
		if err := validateAdmissionProof(header.AdmissionProof); err != nil {
			return nil, fmt.Errorf("Admission_Proof: %w", err)
		}
	}

	return &Entry{Header: header, DomainPayload: payload}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Admission proof structural validation
// -------------------------------------------------------------------------------------------------

// validateAdmissionProof enforces the Mode-specific structural invariants.
// Cryptographic verification of Mode B stamps is performed at admission
// time by the operator using crypto/admission.VerifyStamp; this function
// covers only the invariants required for the proof to be serializable
// and parseable.
func validateAdmissionProof(ap *types.AdmissionProof) error {
	switch ap.Mode {
	case types.AdmissionModeA:
		// Mode A entries SHOULD have a nil AdmissionProof at the header
		// level. An explicit Mode A AdmissionProof is not malformed but
		// carries no meaningful fields; we accept it.
		return nil
	case types.AdmissionModeB:
		if ap.TargetLog == "" {
			return errors.New("Mode B Admission_Proof requires non-empty target_log DID")
		}
		nd, err := normalizeDID(ap.TargetLog)
		if err != nil {
			return fmt.Errorf("target_log: %w", err)
		}
		ap.TargetLog = nd
		// SubmitterCommit pointer-to-fixed-array is self-validating: if
		// non-nil, the language guarantees exactly 32 bytes.
		return nil
	default:
		return fmt.Errorf("unrecognized admission mode %d", ap.Mode)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Snapshot detection
// -------------------------------------------------------------------------------------------------

// isLikelyAuthoritySnapshot detects authority snapshot entries, which are
// exempt from the MaxEvidencePointers bound. A snapshot carries the full
// active constraint set via Evidence_Pointers and is structurally
// identified by the combination of ScopeAuthority path, a Target_Root,
// and a Prior_Authority pointer.
func isLikelyAuthoritySnapshot(h *ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != AuthorityScopeAuthority {
		return false
	}
	return h.TargetRoot != nil && h.PriorAuthority != nil
}

// -------------------------------------------------------------------------------------------------
// 6) DID and position normalization
// -------------------------------------------------------------------------------------------------

// normalizeDID applies the SDK-configured DID normalization rules.
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

// normalizeOptionalPosition applies LogPosition validation and DID
// normalization to an optional pointer field. Null positions are
// replaced with nil so the wire format uses a single canonical
// representation of "absent".
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

// normalizePositionSlice validates and normalizes every LogPosition in a
// slice. Empty slices return nil for wire-format uniformity.
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
