/*
Package lifecycle — provision.go creates the initial entries for a
judicial network deployment. Three logs (officers, cases, parties),
each with a scope entity, initial delegations, and schema entries.

The provisioner produces entries. The caller submits them to the
operator's POST /v1/entries endpoint. The SDK does not make HTTP calls.

The operator's builder/loop.go processes these entries through
ProcessBatch, creating the initial SMT leaves. After provisioning:
  - Each log has a scope entity with the court's Authority_Set
  - Initial officers have delegation entries
  - Governing schemas are published and referenceable via Schema_Ref

Supports all three operational topology models:
  Model 1 (independent): three separate operators, three sets of entries
  Model 2 (shared AOC): single operator, three log DIDs
  Model 3 (consortium): shared operator with consortium scope

Consumed by:
  - judicial-network/onboarding/provision.go → ProvisionThreeLogs
  - Domain onboarding scripts
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// ProvisionConfig configures the initial log setup.
type ProvisionConfig struct {
	// CourtDID is the institutional DID (e.g., "did:web:courts.nashville.gov").
	CourtDID string

	// OfficersLogDID is the DID for the officers log.
	OfficersLogDID string

	// CasesLogDID is the DID for the cases log.
	CasesLogDID string

	// PartiesLogDID is the DID for the parties log.
	PartiesLogDID string

	// AuthoritySet is the initial set of authority DIDs for the scope.
	// Must include CourtDID.
	AuthoritySet map[string]struct{}

	// InitialDelegations defines the first officers to delegate to.
	InitialDelegations []DelegationSpec

	// Schemas defines the initial schema entries to publish.
	Schemas []SchemaSpec

	// EventTime is the timestamp for all provisioning entries.
	// Default: current time in Unix microseconds.
	EventTime int64
}

// DelegationSpec describes one initial delegation.
type DelegationSpec struct {
	// DelegateDID is the officer's role-scoped DID.
	DelegateDID string

	// ScopeLimit is the Domain Payload for the delegation (scope constraint).
	// The SDK does not interpret this (SDK-D6).
	ScopeLimit []byte

	// LogDIDs lists which logs this delegation should appear on.
	// Typically all three logs, but some delegations are log-specific.
	LogDIDs []string
}

// SchemaSpec describes one initial schema entry.
type SchemaSpec struct {
	// Payload is the schema's Domain Payload (JSON with 10 well-known fields).
	Payload []byte

	// CommutativeOperations is non-empty for commutative schemas.
	CommutativeOperations []uint32

	// LogDID is the log where this schema should be published.
	// Schemas are typically on the cases log.
	LogDID string
}

// ─────────────────────────────────────────────────────────────────────
// Result
// ─────────────────────────────────────────────────────────────────────

// ProvisionResult holds all entries for the three-log deployment.
// The caller submits entries for each log to the corresponding operator.
type ProvisionResult struct {
	Officers LogProvision
	Cases    LogProvision
	Parties  LogProvision
}

// LogProvision holds the entries for one log.
type LogProvision struct {
	// LogDID identifies which log these entries are for.
	LogDID string

	// ScopeEntry is the scope entity establishing the Authority_Set.
	// Submitted first — creates the scope SMT leaf.
	ScopeEntry *envelope.Entry

	// Delegations are the initial officer delegation entries.
	// Submitted after the scope entry.
	Delegations []*envelope.Entry

	// SchemaEntries are the governing schema entries.
	// Submitted after delegations.
	SchemaEntries []*envelope.Entry
}

// AllEntries returns all entries for this log in submission order.
func (lp *LogProvision) AllEntries() []*envelope.Entry {
	entries := make([]*envelope.Entry, 0, 1+len(lp.Delegations)+len(lp.SchemaEntries))
	if lp.ScopeEntry != nil {
		entries = append(entries, lp.ScopeEntry)
	}
	entries = append(entries, lp.Delegations...)
	entries = append(entries, lp.SchemaEntries...)
	return entries
}

// ─────────────────────────────────────────────────────────────────────
// ProvisionThreeLogs
// ─────────────────────────────────────────────────────────────────────

// ProvisionThreeLogs creates all initial entries for a three-log
// judicial network deployment.
//
// For each log:
//  1. BuildScopeCreation: scope entity with the court's Authority_Set
//  2. BuildDelegation: one per initial officer
//  3. BuildSchemaEntry: governing schemas
//
// The entries are returned in submission order. The caller submits
// them to the operator's API. The operator's builder processes them
// through ProcessBatch, creating the initial SMT leaves.
//
// Convention (SDK-D4): the scope entity has Authority_Path=SameSigner,
// Creator DID in Authority_Set. This creates a new SMT leaf with both
// Origin_Tip and Authority_Tip pointing to itself.
func ProvisionThreeLogs(cfg ProvisionConfig) (*ProvisionResult, error) {
	if cfg.CourtDID == "" {
		return nil, fmt.Errorf("lifecycle/provision: empty court DID")
	}
	if cfg.OfficersLogDID == "" || cfg.CasesLogDID == "" || cfg.PartiesLogDID == "" {
		return nil, fmt.Errorf("lifecycle/provision: all three log DIDs required")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("lifecycle/provision: empty authority set")
	}
	if _, ok := cfg.AuthoritySet[cfg.CourtDID]; !ok {
		return nil, fmt.Errorf("lifecycle/provision: court DID must be in authority set")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	// Build provisions for each log.
	officers, err := provisionLog(cfg.OfficersLogDID, cfg, eventTime)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/provision: officers: %w", err)
	}

	cases, err := provisionLog(cfg.CasesLogDID, cfg, eventTime)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/provision: cases: %w", err)
	}

	parties, err := provisionLog(cfg.PartiesLogDID, cfg, eventTime)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/provision: parties: %w", err)
	}

	return &ProvisionResult{
		Officers: *officers,
		Cases:    *cases,
		Parties:  *parties,
	}, nil
}

func provisionLog(logDID string, cfg ProvisionConfig, eventTime int64) (*LogProvision, error) {
	provision := &LogProvision{LogDID: logDID}

	// 1. Scope entity.
	scopeEntry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		SignerDID:    cfg.CourtDID,
		AuthoritySet: cfg.AuthoritySet,
		Payload:      mustMarshalJSON(map[string]any{"log_did": logDID, "court_did": cfg.CourtDID}),
		EventTime:    eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("scope creation: %w", err)
	}
	provision.ScopeEntry = scopeEntry

	// 2. Delegations (only those targeting this log).
	for _, d := range cfg.InitialDelegations {
		if !containsLogDID(d.LogDIDs, logDID) {
			continue
		}
		delegEntry, err := builder.BuildDelegation(builder.DelegationParams{
			SignerDID:   cfg.CourtDID,
			DelegateDID: d.DelegateDID,
			Payload:     d.ScopeLimit,
			EventTime:   eventTime,
		})
		if err != nil {
			return nil, fmt.Errorf("delegation %s: %w", d.DelegateDID, err)
		}
		provision.Delegations = append(provision.Delegations, delegEntry)
	}

	// 3. Schemas (only those targeting this log).
	for _, s := range cfg.Schemas {
		if s.LogDID != logDID {
			continue
		}
		schemaEntry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
			SignerDID:             cfg.CourtDID,
			Payload:               s.Payload,
			CommutativeOperations: s.CommutativeOperations,
			EventTime:             eventTime,
		})
		if err != nil {
			return nil, fmt.Errorf("schema: %w", err)
		}
		provision.SchemaEntries = append(provision.SchemaEntries, schemaEntry)
	}

	return provision, nil
}

func containsLogDID(logDIDs []string, target string) bool {
	if len(logDIDs) == 0 {
		return true // Empty means all logs.
	}
	for _, d := range logDIDs {
		if d == target {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────
// ProvisionSingleLog — for non-judicial deployments
// ─────────────────────────────────────────────────────────────────────

// SingleLogConfig configures a single-log provisioning.
type SingleLogConfig struct {
	SignerDID    string
	LogDID       string
	AuthoritySet map[string]struct{}
	Delegations  []DelegationSpec
	Schemas      []SchemaSpec
	EventTime    int64
}

// ProvisionSingleLog creates initial entries for a single log.
// Used by non-judicial deployments (physician credentialing, insurance).
func ProvisionSingleLog(cfg SingleLogConfig) (*LogProvision, error) {
	if cfg.SignerDID == "" || cfg.LogDID == "" {
		return nil, fmt.Errorf("lifecycle/provision: signer DID and log DID required")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("lifecycle/provision: empty authority set")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	fullCfg := ProvisionConfig{
		CourtDID:           cfg.SignerDID,
		OfficersLogDID:     cfg.LogDID,
		CasesLogDID:        cfg.LogDID,
		PartiesLogDID:      cfg.LogDID,
		AuthoritySet:       cfg.AuthoritySet,
		InitialDelegations: cfg.Delegations,
		Schemas:            cfg.Schemas,
	}

	return provisionLog(cfg.LogDID, fullCfg, eventTime)
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// ProvisionResultEntryCount returns the total number of entries across
// all three logs. Useful for write credit budgeting.
func (pr *ProvisionResult) EntryCount() int {
	return len(pr.Officers.AllEntries()) +
		len(pr.Cases.AllEntries()) +
		len(pr.Parties.AllEntries())
}

// ProvisionResultLogDIDs returns the three log DIDs.
func (pr *ProvisionResult) LogDIDs() [3]string {
	return [3]string{pr.Officers.LogDID, pr.Cases.LogDID, pr.Parties.LogDID}
}
