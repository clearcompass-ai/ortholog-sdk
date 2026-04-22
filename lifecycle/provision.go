/*
Package lifecycle — provision.go creates the initial entries for a single
Ortholog log: one scope entity, initial delegations, and schema entries.

The provisioner produces entries. The caller submits them to the
operator's POST /v1/entries endpoint. The SDK does not make HTTP calls.

The operator's builder/loop.go processes these entries through
ProcessBatch, creating the initial SMT leaves. After provisioning:
  - The log has a scope entity with the creator's Authority_Set
  - Any initial delegations are present
  - Governing schemas are published and referenceable via Schema_Ref

Domain-specific multi-log provisioning (e.g., a judicial network's
officers/cases/parties triple) composes this function — a domain
repo calls ProvisionSingleLog three times with per-log configuration
and assembles the results into a domain-specific structure.

Destination binding: SingleLogConfig carries a Destination field (DID of
the target exchange). Every entry produced (scope creation, each
delegation, each schema) is bound to this destination via the canonical
hash. Cross-exchange replay of provisioning entries is cryptographically
impossible.

Consumed by:
  - Domain onboarding scripts (single-log)
  - Domain-specific multi-log provisioners (composing this for each log)
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Specs
// ─────────────────────────────────────────────────────────────────────

// DelegationSpec describes one delegation to issue at provisioning.
// Domain-specific fields (log filters, role labels, scope constraints
// beyond the opaque ScopeLimit) live in the caller's configuration and
// are translated into this generic spec before calling ProvisionSingleLog.
type DelegationSpec struct {
	// DelegateDID is who receives delegated authority.
	DelegateDID string

	// ScopeLimit is the Domain Payload for the delegation (scope constraint).
	// The SDK does not interpret this (SDK-D6).
	ScopeLimit []byte
}

// SchemaSpec describes one schema to publish at provisioning.
// v7.5: structured parameters replace the raw Payload []byte + side
// field for CommutativeOperations. BuildSchemaEntry marshals these
// into the entry's Domain Payload via schema.MarshalParameters.
type SchemaSpec struct {
	// Parameters is the structured schema configuration. Includes
	// CommutativeOperations — non-empty selects Δ-window OCC for
	// this schema (Decision 37 / SDK-D7).
	Parameters types.SchemaParameters
}

// ─────────────────────────────────────────────────────────────────────
// LogProvision — result shape
// ─────────────────────────────────────────────────────────────────────

// LogProvision holds the entries for one log in submission order.
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
// ProvisionSingleLog
// ─────────────────────────────────────────────────────────────────────

// SingleLogConfig configures a single-log provisioning.
//
// Convention (SDK-D4): the scope entity is built with
// Authority_Path=SameSigner and SignerDID included in AuthoritySet.
// This creates a new SMT leaf with both Origin_Tip and Authority_Tip
// pointing to itself.
type SingleLogConfig struct {
	// Destination is the DID of the target exchange. Required.
	// Validated by envelope.ValidateDestination. Threaded into every
	// provisioning entry (scope creation, delegations, schemas).
	Destination string

	// SignerDID is the creator of the scope entity and (conventionally)
	// the first member of AuthoritySet.
	SignerDID string

	// LogDID identifies the log these entries target. Embedded in the
	// default scope payload as "log_did" for discovery.
	LogDID string

	// AuthoritySet is the initial set of authority DIDs for the scope.
	// Must be non-empty.
	AuthoritySet map[string]struct{}

	// Delegations defines the initial delegations to issue on this log.
	// All delegations in this list are published; there is no per-log
	// filtering. Callers provisioning multiple logs filter upstream.
	Delegations []DelegationSpec

	// Schemas defines the initial schemas to publish on this log.
	// Same no-filter contract as Delegations.
	Schemas []SchemaSpec

	// ScopePayload is an optional Domain Payload for the scope entity.
	//
	// The SDK treats this as opaque bytes (SDK-D6) — same contract as
	// DelegationSpec.ScopeLimit and SchemaSpec.Payload. Domain repos
	// building on ProvisionSingleLog inject their own structured payload
	// here (e.g., judicial networks recording the court DID, physician
	// credentialing networks recording the institution).
	//
	// nil: SDK generates a minimal default of {"log_did": cfg.LogDID}.
	// non-nil (including empty slice): passed through verbatim.
	//
	// The nil/non-nil distinction is deliberate — an explicit empty slice
	// means "caller wants no payload" and the SDK respects that, while
	// nil means "caller hasn't specified, use a sensible default."
	ScopePayload []byte

	// EventTime is the timestamp for all provisioning entries.
	// Zero value means time.Now().UTC().UnixMicro() at call time.
	EventTime int64
}

// ProvisionSingleLog creates initial entries for a single log:
//
//  1. BuildScopeCreation: scope entity with the creator's Authority_Set.
//  2. BuildDelegation: one per entry in cfg.Delegations.
//  3. BuildSchemaEntry: one per entry in cfg.Schemas.
//
// Entries are returned in submission order via LogProvision. The caller
// submits them to the operator's API. The operator's builder processes
// them through ProcessBatch, creating the initial SMT leaves.
func ProvisionSingleLog(cfg SingleLogConfig) (*LogProvision, error) {
	if err := envelope.ValidateDestination(cfg.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/provision: %w", err)
	}
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("lifecycle/provision: empty signer DID")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("lifecycle/provision: empty log DID")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("lifecycle/provision: empty authority set")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	provision := &LogProvision{LogDID: cfg.LogDID}

	// Resolve scope payload. nil → minimal default; non-nil (including
	// empty slice) → pass through verbatim. See ScopePayload docstring.
	scopePayload := cfg.ScopePayload
	if scopePayload == nil {
		scopePayload = mustMarshalJSON(map[string]any{"log_did": cfg.LogDID})
	}

	// 1. Scope entity.
	scopeEntry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination:  cfg.Destination,
		SignerDID:    cfg.SignerDID,
		AuthoritySet: cfg.AuthoritySet,
		Payload:      scopePayload,
		EventTime:    eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle/provision: scope creation: %w", err)
	}
	provision.ScopeEntry = scopeEntry

	// 2. Delegations.
	for _, d := range cfg.Delegations {
		delegEntry, err := builder.BuildDelegation(builder.DelegationParams{
			Destination: cfg.Destination,
			SignerDID:   cfg.SignerDID,
			DelegateDID: d.DelegateDID,
			Payload:     d.ScopeLimit,
			EventTime:   eventTime,
		})
		if err != nil {
			return nil, fmt.Errorf("lifecycle/provision: delegation %s: %w", d.DelegateDID, err)
		}
		provision.Delegations = append(provision.Delegations, delegEntry)
	}

	// 3. Schemas.
	for _, s := range cfg.Schemas {
		schemaEntry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
			Destination: cfg.Destination,
			SignerDID:   cfg.SignerDID,
			Parameters:  s.Parameters,
			EventTime:   eventTime,
		})
		if err != nil {
			return nil, fmt.Errorf("lifecycle/provision: schema: %w", err)
		}
		provision.SchemaEntries = append(provision.SchemaEntries, schemaEntry)
	}

	return provision, nil
}
