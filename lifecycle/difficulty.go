/*
Package lifecycle — difficulty.go wraps Phase 1's admission.GenerateStamp
and admission.VerifyStamp with a higher-level API for Mode B admission.

The operator exposes current difficulty via GET /v1/admission/difficulty.
The exchange reads the difficulty, generates a stamp via this wrapper,
and includes it in the entry's AdmissionProof field.

Two entry points:
  GenerateAdmissionStamp: computes a stamp for a given entry hash + config
  VerifyAdmissionStamp: validates a stamp against the operator's config

Consumed by:
  - Exchange submission pipeline (generate stamp before submit)
  - Operator admission middleware (verify stamp on receipt)
  - judicial-network/onboarding/provision.go for Mode B log setup
*/
package lifecycle

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// DifficultyConfig holds the admission difficulty parameters.
// The operator publishes these; the exchange reads them.
type DifficultyConfig struct {
	// TargetLogDID is the log this stamp is bound to. The stamp is
	// invalid on any other log (prevents stamp reuse across logs).
	TargetLogDID string

	// Difficulty is the number of leading zero bits required.
	// Range: 1-256. Higher = more work. Typical: 16-24.
	Difficulty uint32

	// HashFunc selects SHA-256 (default) or Argon2id (memory-hard).
	// Memory-hard recommended for better targeting of infrastructure
	// operators over botnets (governance doc recommendation).
	HashFunc admission.HashFunc

	// Argon2idParams are used when HashFunc is Argon2id.
	// Nil uses admission.DefaultArgon2idParams().
	Argon2idParams *admission.Argon2idParams
}

// DefaultDifficultyConfig returns safe defaults for development.
func DefaultDifficultyConfig(logDID string) DifficultyConfig {
	return DifficultyConfig{
		TargetLogDID: logDID,
		Difficulty:   16,
		HashFunc:     admission.HashSHA256,
	}
}

// ─────────────────────────────────────────────────────────────────────
// GenerateAdmissionStamp
// ─────────────────────────────────────────────────────────────────────

// GenerateAdmissionStamp computes a Mode B admission stamp for an entry.
// The caller computes the entry's canonical hash via crypto.CanonicalHash,
// then calls this with the hash and the operator's difficulty config.
//
// Returns an AdmissionProof ready to set on the entry's Control Header
// before serialization and submission.
func GenerateAdmissionStamp(entryHash [32]byte, cfg DifficultyConfig) (*types.AdmissionProof, error) {
	if cfg.TargetLogDID == "" {
		return nil, fmt.Errorf("lifecycle/difficulty: empty target log DID")
	}
	if cfg.Difficulty == 0 || cfg.Difficulty > 256 {
		return nil, fmt.Errorf("lifecycle/difficulty: difficulty %d out of range 1-256", cfg.Difficulty)
	}

	nonce, err := admission.GenerateStamp(entryHash, cfg.TargetLogDID, cfg.Difficulty, cfg.HashFunc, cfg.Argon2idParams)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/difficulty: generate stamp: %w", err)
	}

	return &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  cfg.TargetLogDID,
		Difficulty: cfg.Difficulty,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp
// ─────────────────────────────────────────────────────────────────────

// VerifyAdmissionStamp validates a Mode B admission stamp. The operator's
// admission pipeline calls this to verify stamps on incoming entries.
//
// Checks:
//  1. Proof is Mode B
//  2. TargetLog matches the operator's log DID (stamp bound to this log)
//  3. Difficulty meets the minimum (operator can accept higher)
//  4. Stamp hash meets the difficulty target
func VerifyAdmissionStamp(entryHash [32]byte, proof *types.AdmissionProof, cfg DifficultyConfig) error {
	if proof == nil {
		return fmt.Errorf("lifecycle/difficulty: nil admission proof")
	}
	if proof.Mode != types.AdmissionModeB {
		return fmt.Errorf("lifecycle/difficulty: expected Mode B, got mode %d", proof.Mode)
	}
	if proof.TargetLog != cfg.TargetLogDID {
		return fmt.Errorf("lifecycle/difficulty: stamp bound to %s, expected %s", proof.TargetLog, cfg.TargetLogDID)
	}
	if proof.Difficulty < cfg.Difficulty {
		return fmt.Errorf("lifecycle/difficulty: stamp difficulty %d below minimum %d", proof.Difficulty, cfg.Difficulty)
	}

	return admission.VerifyStamp(entryHash, proof.Nonce, cfg.TargetLogDID, proof.Difficulty, cfg.HashFunc, cfg.Argon2idParams)
}
