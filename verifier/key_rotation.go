/*
Package verifier — key_rotation.go evaluates whether a key rotation is
Tier 2 (pre-committed + matured = immediate effect) or Tier 3
(activation delay + identity witness + contest window).

Tier 2: The DID profile entry contains a next_key_hash that matches the
rotation's new key. The pre-commitment has matured (Log_Time of
pre-commitment + maturation_epoch ≤ Log_Time of rotation). Immediate
effect, no contest possible.

Tier 3: No matching pre-commitment, or pre-commitment hasn't matured.
Activation delay applies, contest window opens, identity witness required.
Delegates to EvaluateContest for contest/override status.

Consumed by:
  - Domain key rotation verification flows
  - Exchange key recovery evaluation
*/
package verifier

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// RotationTier classifies the key rotation security level.
type RotationTier int

const (
	// RotationTier2 means the rotation has a matured pre-commitment.
	// Immediate effect, no contest window.
	RotationTier2 RotationTier = 2

	// RotationTier3 means no matured pre-commitment exists.
	// Activation delay + contest window + identity witness required.
	RotationTier3 RotationTier = 3
)

// RotationEvaluation holds the result of key rotation evaluation.
type RotationEvaluation struct {
	// Tier is the rotation security tier (2 or 3).
	Tier RotationTier

	// Matured is true if a pre-commitment exists and has matured.
	// Only meaningful for Tier 2.
	Matured bool

	// ContestResult holds contest/override status for Tier 3 rotations.
	// Nil for Tier 2 (no contest window).
	ContestResult *ContestResult

	// EffectiveAt is when the rotation takes effect.
	// Tier 2: nil (immediate).
	// Tier 3: Log_Time of rotation + activation delay.
	EffectiveAt *time.Time
}

// ─────────────────────────────────────────────────────────────────────
// EvaluateKeyRotation
// ─────────────────────────────────────────────────────────────────────

// EvaluateKeyRotation determines the tier and status of a key rotation.
//
// Algorithm:
//  1. Fetch rotation entry → get TargetRoot (DID profile entity)
//  2. Fetch DID profile entry → read next_key_hash from Domain Payload
//  3. If next_key_hash matches rotation's new key:
//     a. Compute maturation: LogTime(profile) + MaturationEpoch
//     b. If LogTime(rotation) >= maturation → Tier 2
//     c. Otherwise → Tier 3
//  4. No pre-commitment → Tier 3
//  5. Tier 3: EffectiveAt = LogTime(rotation) + ActivationDelay
//  6. Tier 3: delegate to EvaluateContest
func EvaluateKeyRotation(
	rotationPos types.LogPosition,
	fetcher EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
) (*RotationEvaluation, error) {
	// 1. Fetch rotation entry.
	rotMeta, err := fetcher.Fetch(rotationPos)
	if err != nil || rotMeta == nil {
		return nil, fmt.Errorf("verifier/rotation: rotation entry not found at %s", rotationPos)
	}
	rotEntry, err := envelope.Deserialize(rotMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("verifier/rotation: deserialize rotation: %w", err)
	}

	if rotEntry.Header.TargetRoot == nil {
		return nil, fmt.Errorf("verifier/rotation: rotation entry has no TargetRoot")
	}
	profilePos := *rotEntry.Header.TargetRoot

	// 2. Fetch DID profile entry.
	profileMeta, err := fetcher.Fetch(profilePos)
	if err != nil || profileMeta == nil {
		return nil, fmt.Errorf("verifier/rotation: DID profile not found at %s", profilePos)
	}
	profileEntry, err := envelope.Deserialize(profileMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("verifier/rotation: deserialize profile: %w", err)
	}

	// 3. Read schema parameters for maturation epoch and activation delay.
	var maturationEpoch time.Duration
	var activationDelay time.Duration
	if extractor != nil && rotEntry.Header.SchemaRef != nil {
		schemaMeta, fetchErr := fetcher.Fetch(*rotEntry.Header.SchemaRef)
		if fetchErr == nil && schemaMeta != nil {
			schemaEntry, desErr := envelope.Deserialize(schemaMeta.CanonicalBytes)
			if desErr == nil {
				params, extErr := extractor.Extract(schemaEntry)
				if extErr == nil && params != nil {
					maturationEpoch = params.MaturationEpoch
					activationDelay = params.ActivationDelay
				}
			}
		}
	}

	// 4. Check for next_key_hash pre-commitment in DID profile.
	nextKeyHash := readNextKeyHash(profileEntry)
	rotationKeyHash := computeRotationKeyHash(rotEntry)

	if nextKeyHash != "" && rotationKeyHash != "" && nextKeyHash == rotationKeyHash {
		// Pre-commitment exists and matches.
		// Check maturation: LogTime(profile) + MaturationEpoch <= LogTime(rotation)
		maturationTime := profileMeta.LogTime.Add(maturationEpoch)
		if !rotMeta.LogTime.Before(maturationTime) {
			// Matured → Tier 2.
			return &RotationEvaluation{
				Tier:    RotationTier2,
				Matured: true,
			}, nil
		}
		// Pre-commitment exists but hasn't matured → Tier 3.
	}

	// 5. No matured pre-commitment → Tier 3.
	eval := &RotationEvaluation{
		Tier:    RotationTier3,
		Matured: false,
	}

	// Compute EffectiveAt.
	if activationDelay > 0 {
		effectiveAt := rotMeta.LogTime.Add(activationDelay)
		eval.EffectiveAt = &effectiveAt
	}

	// 6. Evaluate contest status.
	contestResult, contestErr := EvaluateContest(rotationPos, fetcher, leafReader, extractor)
	if contestErr == nil {
		eval.ContestResult = contestResult
	}

	return eval, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// readNextKeyHash extracts the next_key_hash field from a DID profile
// entry's Domain Payload (JSON). Returns empty string if not found.
func readNextKeyHash(profileEntry *envelope.Entry) string {
	if len(profileEntry.DomainPayload) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(profileEntry.DomainPayload, &payload); err != nil {
		return ""
	}
	v, ok := payload["next_key_hash"]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// computeRotationKeyHash computes a hash identifier for the rotation's
// new key from the rotation entry's Domain Payload. Returns empty string
// if not computable.
func computeRotationKeyHash(rotEntry *envelope.Entry) string {
	if len(rotEntry.DomainPayload) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(rotEntry.DomainPayload, &payload); err != nil {
		return ""
	}
	// Check for explicit new_key_hash field.
	if v, ok := payload["new_key_hash"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	// Fallback: hash the new_public_key field.
	if v, ok := payload["new_public_key"]; ok {
		if s, ok := v.(string); ok {
			h := sha256.Sum256([]byte(s))
			return fmt.Sprintf("%x", h[:])
		}
	}
	return ""
}
