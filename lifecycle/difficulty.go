// FILE PATH:
//     lifecycle/difficulty.go
//
// DESCRIPTION:
//     High-level entry points for Mode B admission stamp generation and
//     verification. Wraps crypto/admission with a single DifficultyConfig
//     struct that carries every knob operators and exchanges need: target
//     log, minimum difficulty, hash function selection, Argon2id parameters,
//     and epoch binding parameters.
//
// KEY ARCHITECTURAL DECISIONS:
//     - DifficultyConfig is the single source of truth for stamp policy.
//       Operators populate one from their config file and pass it to
//       VerifyAdmissionStamp on every admission. Exchanges fetch it from
//       the operator's difficulty endpoint and pass it to
//       GenerateAdmissionStamp. No ambient state.
//     - Generation takes an optional submitter commit pointer. When non-nil,
//       the resulting AdmissionProof carries it. When nil, the proof carries
//       no commit and the admission hash zero-fills its commit slot.
//     - Epoch binding is OPT-IN at verification. EpochAcceptanceWindow of 0
//       disables the check. Exchanges always populate Epoch from
//       admission.CurrentEpoch so that enabling verification later does not
//       require changes to submitter code paths.
//     - Generation failures surface as wrapped errors with the "lifecycle/
//       difficulty:" prefix. Verification failures pass through the named
//       errors from crypto/admission unchanged so callers can dispatch via
//       errors.Is.
//
// OVERVIEW:
//     Generation flow:
//         1. Caller computes the entry's canonical hash via
//            envelope.EntryIdentity.
//         2. Caller invokes GenerateAdmissionStamp(hash, cfg, commit).
//         3. This function validates config, computes the current epoch,
//            invokes admission.GenerateStamp, and returns a fully
//            populated AdmissionProof ready to attach to the entry's
//            Control Header.
//
//     Verification flow:
//         1. Operator receives an entry with an admission proof.
//         2. Operator computes the entry hash and invokes
//            VerifyAdmissionStamp(hash, proof, cfg).
//         3. This function computes the current epoch from the configured
//            window and delegates to admission.VerifyStamp.
//
// KEY DEPENDENCIES:
//     - crypto/admission: stamp hash primitive, epoch helpers, named errors.
//     - types/admission.go: AdmissionProof and AdmissionMode.
package lifecycle

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) DifficultyConfig
// -------------------------------------------------------------------------------------------------

// DifficultyConfig holds the complete Mode B admission policy.
//
// Fields:
//
//	TargetLogDID          — the log this policy applies to. Stamps must
//	                        carry this DID in AdmissionProof.TargetLog.
//	                        Generation uses it to bind the stamp; verification
//	                        uses it to reject stamps targeting other logs.
//	Difficulty            — at generation: the difficulty the submitter will
//	                        satisfy. At verification: the operator's minimum
//	                        acceptable difficulty. Range 1..256.
//	HashFunc              — HashSHA256 or HashArgon2id. Both sides MUST
//	                        agree. Operators publish their choice via the
//	                        difficulty endpoint.
//	Argon2idParams        — parameters for Argon2id. nil uses
//	                        admission.DefaultArgon2idParams. Ignored for
//	                        HashSHA256.
//	EpochWindowSeconds    — epoch width in seconds. 0 disables epoch binding
//	                        (AdmissionProof.Epoch will be 0 on generation;
//	                        verification will not check it).
//	EpochAcceptanceWindow — tolerance in epochs around the current epoch.
//	                        0 disables the epoch check at verification even
//	                        if EpochWindowSeconds is non-zero. Set to 1 for
//	                        the default ±1-epoch tolerance.
type DifficultyConfig struct {
	TargetLogDID          string
	Difficulty            uint32
	HashFunc              admission.HashFunc
	Argon2idParams        *admission.Argon2idParams
	EpochWindowSeconds    uint64
	EpochAcceptanceWindow uint64
}

// DefaultDifficultyConfig returns a safe starting configuration for the
// given log DID: difficulty 16, SHA-256, default epoch width (5 minutes),
// default acceptance window (±1 epoch).
//
// Production operators MUST review and tune these values — in particular,
// Difficulty should be raised based on observed submission rates and
// attack patterns, and HashFunc should be switched to HashArgon2id when
// the operator's threat model includes commodity-hashing-capable adversaries.
func DefaultDifficultyConfig(logDID string) DifficultyConfig {
	return DifficultyConfig{
		TargetLogDID:          logDID,
		Difficulty:            16,
		HashFunc:              admission.HashSHA256,
		EpochWindowSeconds:    admission.DefaultEpochWindowSeconds,
		EpochAcceptanceWindow: admission.DefaultEpochAcceptanceWindow,
	}
}

// validate enforces invariants shared by generation and verification.
func (cfg DifficultyConfig) validate() error {
	if cfg.TargetLogDID == "" {
		return fmt.Errorf("lifecycle/difficulty: empty target log DID")
	}
	if cfg.Difficulty == 0 || cfg.Difficulty > 256 {
		return fmt.Errorf("lifecycle/difficulty: difficulty %d out of range 1..256", cfg.Difficulty)
	}
	switch cfg.HashFunc {
	case admission.HashSHA256, admission.HashArgon2id:
	default:
		return fmt.Errorf("lifecycle/difficulty: unknown hash function %d", cfg.HashFunc)
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 2) Stamp generation
// -------------------------------------------------------------------------------------------------

// GenerateAdmissionStamp computes a Mode B admission stamp for an entry
// and returns a fully populated AdmissionProof ready to attach to the
// entry's Control Header.
//
// Arguments:
//
//	entryHash       — canonical hash of the entry, from envelope.EntryIdentity.
//	cfg             — stamp policy. See DifficultyConfig.
//	submitterCommit — optional 32-byte submitter identity binding. nil
//	                  when the operator does not require per-submitter
//	                  rate limiting.
//
// The returned AdmissionProof has:
//
//	Mode            = AdmissionModeB
//	Nonce           = the winning nonce from GenerateStamp
//	TargetLog       = cfg.TargetLogDID
//	Difficulty      = cfg.Difficulty
//	Epoch           = CurrentEpoch(cfg.EpochWindowSeconds)
//	SubmitterCommit = submitterCommit
func GenerateAdmissionStamp(
	entryHash [32]byte,
	cfg DifficultyConfig,
	submitterCommit *[32]byte,
) (*types.AdmissionProof, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	epoch := admission.CurrentEpoch(cfg.EpochWindowSeconds)

	nonce, err := admission.GenerateStamp(admission.StampParams{
		EntryHash:       entryHash,
		LogDID:          cfg.TargetLogDID,
		Difficulty:      cfg.Difficulty,
		HashFunc:        cfg.HashFunc,
		Argon2idParams:  cfg.Argon2idParams,
		Epoch:           epoch,
		SubmitterCommit: submitterCommit,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle/difficulty: generate stamp: %w", err)
	}

	return &types.AdmissionProof{
		Mode:            types.AdmissionModeB,
		Nonce:           nonce,
		TargetLog:       cfg.TargetLogDID,
		Difficulty:      cfg.Difficulty,
		Epoch:           epoch,
		SubmitterCommit: submitterCommit,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 3) Stamp verification
// -------------------------------------------------------------------------------------------------

// VerifyAdmissionStamp validates an AdmissionProof against operator policy.
// Computes the current epoch from cfg.EpochWindowSeconds and delegates to
// admission.VerifyStamp. All named errors from crypto/admission pass
// through unchanged; callers dispatch on errors.Is to map failures to
// HTTP status codes or audit categories.
func VerifyAdmissionStamp(
	entryHash [32]byte,
	proof *types.AdmissionProof,
	cfg DifficultyConfig,
) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	currentEpoch := admission.CurrentEpoch(cfg.EpochWindowSeconds)
	return admission.VerifyStamp(
		proof,
		entryHash,
		cfg.TargetLogDID,
		cfg.Difficulty,
		cfg.HashFunc,
		cfg.Argon2idParams,
		currentEpoch,
		cfg.EpochAcceptanceWindow,
	)
}
