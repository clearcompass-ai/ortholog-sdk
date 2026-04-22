/*
Package verifier — condition_evaluator.go evaluates whether all conditions
for a pending operation have been met. Used by monitoring services to
determine when an activation entry should be published.

Four conditions checked (all from SchemaParameters):
 1. Activation delay elapsed: LogTime + ActivationDelay ≤ now
 2. Cosignature threshold met: count of valid cosignatures ≥ CosignatureThreshold
 3. Maturation epoch passed: LogTime + MaturationEpoch ≤ now (for key rotation)
 4. Credential validity period not expired: LogTime + CredentialValidityPeriod > now

Two entry points:

	EvaluateConditions: full evaluation given a pending position + cosignatures
	CheckActivationReady: quick boolean check for monitoring loops

BUG-015 FIX (this revision):

	countValidCosignatures now routes cosignature-to-position binding
	through verifier.IsCosignatureOf rather than the raw
	`CosignatureOf != nil` check it previously used. The raw check
	admitted any cosignature as approval regardless of what it was for,
	enabling an attacker to replay cosignatures of unrelated approvals
	as satisfaction of this operation's CosignatureThreshold.

	Signature change: countValidCosignatures and evaluateCosignatureThreshold
	now accept the pending position explicitly as a parameter, because
	*envelope.Entry (the deserialized form) does not carry position —
	position lives on EntryWithMetadata. The caller (EvaluateConditions)
	already has p.PendingPos and threads it through.

Consumed by:
  - judicial-network/monitoring/sealing_compliance.go → EvaluateConditions
  - operator admission pipeline for activation entry validation
  - exchange lifecycle for activation entry publishing decisions
*/
package verifier

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/scope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// ConditionState classifies a single condition.
type ConditionState uint8

const (
	// ConditionMet means the condition is satisfied.
	ConditionMet ConditionState = iota
	// ConditionPending means the condition is not yet satisfied.
	ConditionPending
	// ConditionNotApplicable means the condition is not required by the schema.
	ConditionNotApplicable
	// ConditionFailed means the condition cannot be satisfied (e.g., expired).
	ConditionFailed
)

// ConditionDetail describes one evaluated condition.
type ConditionDetail struct {
	Name   string
	State  ConditionState
	Reason string
	MetAt  *time.Time // When the condition was or will be met. Nil if N/A.
}

// ConditionResult holds the full evaluation of all conditions for a
// pending operation.
type ConditionResult struct {
	// AllMet is true when every applicable condition is satisfied.
	AllMet bool

	// Conditions lists each evaluated condition with its state.
	Conditions []ConditionDetail

	// PendingPosition is the position of the entry being evaluated.
	PendingPosition types.LogPosition

	// SchemaPosition is the Schema_Ref of the pending entry. Nil if absent.
	SchemaPosition *types.LogPosition

	// CosignatureCount is the number of valid cosignatures found.
	CosignatureCount int

	// EarliestActivation is the earliest time all time-based conditions
	// will be met. Nil if all time conditions are already met or N/A.
	EarliestActivation *time.Time
}

// EvaluateConditionsParams configures condition evaluation.
type EvaluateConditionsParams struct {
	// PendingPos is the log position of the pending operation.
	PendingPos types.LogPosition

	// Fetcher reads entries by position. Satisfied by operator's
	// PostgresEntryFetcher or test MockFetcher.
	Fetcher types.EntryFetcher

	// Extractor reads schema parameters from Domain Payload.
	// Nil is safe — all conditions default to met/not-applicable.
	Extractor schema.SchemaParameterExtractor

	// Cosignatures are the pre-fetched cosignature entries for the
	// pending operation. The caller discovers these via
	// OperatorQueryAPI.QueryByCosignatureOf(pendingPos).
	Cosignatures []types.EntryWithMetadata

	// LeafReader is the read-only SMT view used to resolve the
	// governing scope's AuthoritySet via core/scope.AuthorizedSetAtPosition.
	// Decision 52: the SDK derives the authorised set from the
	// pending entry's Prior_Authority rather than trusting a
	// caller-supplied map. The set is cryptographically anchored
	// to the scope-history chain; a caller can no longer supply a
	// permissive override to bypass cosignature authority checks.
	//
	// Required when the pending entry is a Path C scope-authority
	// operation (ScopePointer + PriorAuthority both non-nil). For
	// pending entries that carry no scope context, the evaluator
	// treats the cosignature count as unfiltered by scope membership
	// (no authorised-set filter applied) — matching the pre-
	// Decision-52 behaviour for non-scope operations.
	LeafReader smt.LeafReader

	// Now is the evaluation time. Pass time.Now().UTC() for live
	// evaluation or a fixed time for deterministic testing.
	Now time.Time
}

// ─────────────────────────────────────────────────────────────────────
// EvaluateConditions
// ─────────────────────────────────────────────────────────────────────

// EvaluateConditions checks all schema-declared conditions for a pending
// operation and returns a structured result.
//
// The caller is responsible for discovering cosignatures (via
// OperatorQueryAPI.QueryByCosignatureOf) and passing them in. This keeps
// the evaluator pure — it evaluates given data, it doesn't fetch data.
//
// Steps:
//  1. Fetch the pending entry to read Schema_Ref and LogTime.
//  2. If Schema_Ref is set, fetch schema entry and extract parameters.
//  3. Evaluate each condition against the parameters and current time.
//  4. Return structured result with per-condition detail.
func EvaluateConditions(p EvaluateConditionsParams) (*ConditionResult, error) {
	// 1. Fetch pending entry.
	pendingMeta, err := p.Fetcher.Fetch(p.PendingPos)
	if err != nil || pendingMeta == nil {
		return nil, fmt.Errorf("verifier/conditions: pending entry not found at %s", p.PendingPos)
	}
	pendingEntry, err := envelope.Deserialize(pendingMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("verifier/conditions: deserialize pending: %w", err)
	}

	result := &ConditionResult{
		PendingPosition: p.PendingPos,
		SchemaPosition:  pendingEntry.Header.SchemaRef,
	}

	// 2. Extract schema parameters.
	var params *types.SchemaParameters
	if pendingEntry.Header.SchemaRef != nil && p.Extractor != nil {
		schemaMeta, fetchErr := p.Fetcher.Fetch(*pendingEntry.Header.SchemaRef)
		if fetchErr == nil && schemaMeta != nil {
			schemaEntry, desErr := envelope.Deserialize(schemaMeta.CanonicalBytes)
			if desErr == nil {
				extracted, extErr := p.Extractor.Extract(schemaEntry)
				if extErr == nil {
					params = extracted
				}
			}
		}
	}

	// 3. Evaluate each condition.
	entryTime := pendingMeta.LogTime

	// Derive the governing AuthoritySet via the shared scope-history
	// primitive (Decision 52). For Path C entries the SDK — not the
	// caller — is the trust boundary for cosignature authority
	// membership. Only resolved when the pending entry carries both
	// ScopePointer and PriorAuthority; other shapes leave the
	// authorised set nil (no filtering, same as pre-Decision-52
	// non-scope evaluation).
	//
	// Fail-closed: any non-nil error from the primitive rejects the
	// entire evaluation rather than silently falling back to an
	// unfiltered count. The caller sees the typed scope error
	// wrapped with verifier context.
	var authorizedSet map[string]struct{}
	if p.LeafReader != nil &&
		pendingEntry.Header.ScopePointer != nil &&
		pendingEntry.Header.PriorAuthority != nil {
		set, err := scope.AuthorizedSetAtPosition(
			*pendingEntry.Header.ScopePointer,
			*pendingEntry.Header.PriorAuthority,
			p.Fetcher,
			p.LeafReader,
		)
		if err != nil {
			return nil, fmt.Errorf("verifier/conditions: resolve authority set: %w", err)
		}
		authorizedSet = set
	}

	// Condition 1: Activation delay.
	result.Conditions = append(result.Conditions, evaluateActivationDelay(params, entryTime, p.Now))

	// Condition 2: Cosignature threshold.
	// BUG-015: pass p.PendingPos explicitly so countValidCosignatures
	// binds each cosignature to the correct position.
	// Decision 52: authorizedSet derived cryptographically above
	// from the pending entry's Prior_Authority observation time.
	cosigDetail := evaluateCosignatureThreshold(params, p.Cosignatures, pendingEntry, p.PendingPos, authorizedSet)
	result.CosignatureCount = countValidCosignatures(p.Cosignatures, pendingEntry, p.PendingPos, authorizedSet)
	result.Conditions = append(result.Conditions, cosigDetail)

	// Condition 3: Maturation epoch.
	result.Conditions = append(result.Conditions, evaluateMaturationEpoch(params, entryTime, p.Now))

	// Condition 4: Credential validity period.
	result.Conditions = append(result.Conditions, evaluateCredentialValidity(params, entryTime, p.Now))

	// 4. Compute aggregate.
	result.AllMet = true
	for _, c := range result.Conditions {
		if c.State == ConditionPending || c.State == ConditionFailed {
			result.AllMet = false
		}
	}
	// EarliestActivation is the LATEST of all pending "MetAt" times
	// (all must be met, so we need the last one).
	if !result.AllMet {
		var latest *time.Time
		for _, c := range result.Conditions {
			if c.State == ConditionPending && c.MetAt != nil {
				if latest == nil || c.MetAt.After(*latest) {
					t := *c.MetAt
					latest = &t
				}
			}
		}
		result.EarliestActivation = latest
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// CheckActivationReady — quick boolean for monitoring loops
// ─────────────────────────────────────────────────────────────────────

// CheckActivationReady is a convenience wrapper that returns true when
// all conditions are met. Monitoring services call this in tight loops
// to decide whether to publish an activation entry.
func CheckActivationReady(p EvaluateConditionsParams) (bool, error) {
	result, err := EvaluateConditions(p)
	if err != nil {
		return false, err
	}
	return result.AllMet, nil
}

// ─────────────────────────────────────────────────────────────────────
// Individual condition evaluators
// ─────────────────────────────────────────────────────────────────────

func evaluateActivationDelay(params *types.SchemaParameters, entryTime time.Time, now time.Time) ConditionDetail {
	if params == nil || params.ActivationDelay <= 0 {
		return ConditionDetail{
			Name:   "activation_delay",
			State:  ConditionNotApplicable,
			Reason: "no activation delay declared",
		}
	}

	effectiveAt := entryTime.Add(params.ActivationDelay)
	if !now.Before(effectiveAt) {
		return ConditionDetail{
			Name:   "activation_delay",
			State:  ConditionMet,
			Reason: fmt.Sprintf("delay %s elapsed at %s", params.ActivationDelay, effectiveAt.Format(time.RFC3339)),
			MetAt:  &effectiveAt,
		}
	}
	return ConditionDetail{
		Name:   "activation_delay",
		State:  ConditionPending,
		Reason: fmt.Sprintf("delay %s not elapsed until %s", params.ActivationDelay, effectiveAt.Format(time.RFC3339)),
		MetAt:  &effectiveAt,
	}
}

// evaluateCosignatureThreshold counts valid cosignatures and reports
// whether the schema's CosignatureThreshold is satisfied.
//
// BUG-015 fix: accepts pendingPos explicitly so the underlying count
// binds each cosignature to the pending operation's position.
// Sybil fix: accepts authorizedSet so cosignatures from signers outside
// the governing scope are discarded before counting.
func evaluateCosignatureThreshold(
	params *types.SchemaParameters,
	cosignatures []types.EntryWithMetadata,
	pendingEntry *envelope.Entry,
	pendingPos types.LogPosition,
	authorizedSet map[string]struct{},
) ConditionDetail {
	if params == nil || params.CosignatureThreshold <= 0 {
		return ConditionDetail{
			Name:   "cosignature_threshold",
			State:  ConditionNotApplicable,
			Reason: "no cosignature threshold declared",
		}
	}

	validCount := countValidCosignatures(cosignatures, pendingEntry, pendingPos, authorizedSet)
	threshold := params.CosignatureThreshold

	if validCount >= threshold {
		return ConditionDetail{
			Name:   "cosignature_threshold",
			State:  ConditionMet,
			Reason: fmt.Sprintf("%d of %d required cosignatures present", validCount, threshold),
		}
	}
	return ConditionDetail{
		Name:   "cosignature_threshold",
		State:  ConditionPending,
		Reason: fmt.Sprintf("%d of %d required cosignatures present", validCount, threshold),
	}
}

func evaluateMaturationEpoch(params *types.SchemaParameters, entryTime time.Time, now time.Time) ConditionDetail {
	if params == nil || params.MaturationEpoch <= 0 {
		return ConditionDetail{
			Name:   "maturation_epoch",
			State:  ConditionNotApplicable,
			Reason: "no maturation epoch declared",
		}
	}

	maturedAt := entryTime.Add(params.MaturationEpoch)
	if !now.Before(maturedAt) {
		return ConditionDetail{
			Name:   "maturation_epoch",
			State:  ConditionMet,
			Reason: fmt.Sprintf("maturation %s elapsed at %s", params.MaturationEpoch, maturedAt.Format(time.RFC3339)),
			MetAt:  &maturedAt,
		}
	}
	return ConditionDetail{
		Name:   "maturation_epoch",
		State:  ConditionPending,
		Reason: fmt.Sprintf("maturation %s not elapsed until %s", params.MaturationEpoch, maturedAt.Format(time.RFC3339)),
		MetAt:  &maturedAt,
	}
}

func evaluateCredentialValidity(params *types.SchemaParameters, entryTime time.Time, now time.Time) ConditionDetail {
	if params == nil || params.CredentialValidityPeriod == nil {
		return ConditionDetail{
			Name:   "credential_validity",
			State:  ConditionNotApplicable,
			Reason: "no credential validity period declared (no expiry)",
		}
	}

	expiresAt := entryTime.Add(*params.CredentialValidityPeriod)
	if now.Before(expiresAt) {
		return ConditionDetail{
			Name:   "credential_validity",
			State:  ConditionMet,
			Reason: fmt.Sprintf("valid until %s", expiresAt.Format(time.RFC3339)),
			MetAt:  &expiresAt,
		}
	}
	return ConditionDetail{
		Name:   "credential_validity",
		State:  ConditionFailed,
		Reason: fmt.Sprintf("expired at %s", expiresAt.Format(time.RFC3339)),
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// countValidCosignatures counts cosignature entries bound to the pending
// operation's position. Each unique signer counts once. The pending
// entry's own signer is excluded (self-cosignature is not approval).
//
// # BUG-015 FIX
//
// Previously this function checked only `CosignatureOf != nil`, which
// admitted any cosignature regardless of what it referenced. An
// attacker could satisfy CosignatureThreshold by replaying cosignatures
// from unrelated approvals.
//
// The fix routes the binding check through verifier.IsCosignatureOf,
// which requires the cosignature to explicitly reference pendingPos.
//
// # SYBIL FIX
//
// authorizedSet names the DIDs whose cosignatures count. Signers
// outside this set are discarded even when the cosignature entry
// binds to pendingPos — otherwise an attacker operating an unrelated
// DID could satisfy the threshold by cosigning a victim's operation.
// A nil authorizedSet preserves prior behaviour (every bound
// cosignature counts) and is intentionally legal for callers that
// have no scope to authorise against, but production callers SHOULD
// pass the governing scope's AuthoritySet.
//
// The pendingPos parameter is passed explicitly by the caller because
// *envelope.Entry does not carry position — position lives on the
// EntryWithMetadata wrapper. EvaluateConditions has p.PendingPos on
// hand and threads it through.
func countValidCosignatures(
	cosignatures []types.EntryWithMetadata,
	pendingEntry *envelope.Entry,
	pendingPos types.LogPosition,
	authorizedSet map[string]struct{},
) int {
	seen := make(map[string]bool)
	count := 0
	for _, meta := range cosignatures {
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		// BUG-015 fix: bind the cosignature to the pending position.
		// Previously this was a raw `CosignatureOf != nil` check.
		if !IsCosignatureOf(entry, pendingPos) {
			continue
		}

		// Exclude self-cosignature (signer cosigning their own entry).
		if entry.Header.SignerDID == pendingEntry.Header.SignerDID {
			continue
		}
		// Sybil defence: signer must be in the authorised set, when
		// one is provided. A nil authorizedSet disables this check.
		if authorizedSet != nil {
			if _, ok := authorizedSet[entry.Header.SignerDID]; !ok {
				continue
			}
		}
		if seen[entry.Header.SignerDID] {
			continue
		}
		seen[entry.Header.SignerDID] = true
		count++
	}
	return count
}
