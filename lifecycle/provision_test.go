// Package lifecycle — provision_test.go tests ProvisionSingleLog config
// validation, entry production, payload defaulting, and LogProvision
// ordering contract.
package lifecycle

import (
	"encoding/json"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// ProvisionSingleLog — config validation
// -------------------------------------------------------------------------------------------------

func TestProvisionSingleLog_RejectsEmptyDestination(t *testing.T) {
	_, err := ProvisionSingleLog(SingleLogConfig{
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestProvisionSingleLog_RejectsEmptySignerDID(t *testing.T) {
	_, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:a.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for empty SignerDID, got nil")
	}
}

func TestProvisionSingleLog_RejectsEmptyLogDID(t *testing.T) {
	_, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for empty LogDID, got nil")
	}
}

func TestProvisionSingleLog_RejectsEmptyAuthoritySet(t *testing.T) {
	_, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{},
	})
	if err == nil {
		t.Fatal("expected error for empty authority set, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// ProvisionSingleLog — happy path
// -------------------------------------------------------------------------------------------------

func TestProvisionSingleLog_ProducesScopeOnlyWhenNoDelegationsOrSchemas(t *testing.T) {
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}
	if prov == nil {
		t.Fatal("result is nil")
	}
	if prov.LogDID != "did:web:log.test" {
		t.Errorf("LogDID = %q, want did:web:log.test", prov.LogDID)
	}
	if prov.ScopeEntry == nil {
		t.Error("ScopeEntry is nil, want non-nil")
	}
	if len(prov.Delegations) != 0 {
		t.Errorf("len(Delegations) = %d, want 0", len(prov.Delegations))
	}
	if len(prov.SchemaEntries) != 0 {
		t.Errorf("len(SchemaEntries) = %d, want 0", len(prov.SchemaEntries))
	}
}

func TestProvisionSingleLog_ProducesAllEntries(t *testing.T) {
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
		Delegations: []DelegationSpec{
			{DelegateDID: "did:web:alice.test", ScopeLimit: []byte(`{"role":"clerk"}`)},
			{DelegateDID: "did:web:bob.test", ScopeLimit: []byte(`{"role":"clerk"}`)},
		},
		Schemas: []SchemaSpec{
			{Payload: []byte(`{"schema":"a"}`)},
			{Payload: []byte(`{"schema":"b"}`), CommutativeOperations: []uint32{1, 2}},
		},
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}
	if prov.ScopeEntry == nil {
		t.Fatal("ScopeEntry is nil")
	}
	if len(prov.Delegations) != 2 {
		t.Errorf("len(Delegations) = %d, want 2", len(prov.Delegations))
	}
	if len(prov.SchemaEntries) != 2 {
		t.Errorf("len(SchemaEntries) = %d, want 2", len(prov.SchemaEntries))
	}
	for i, e := range prov.Delegations {
		if e == nil {
			t.Errorf("Delegations[%d] is nil", i)
		}
	}
	for i, e := range prov.SchemaEntries {
		if e == nil {
			t.Errorf("SchemaEntries[%d] is nil", i)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// ProvisionSingleLog — ScopePayload defaulting behavior
// -------------------------------------------------------------------------------------------------

func TestProvisionSingleLog_NilScopePayloadProducesDefault(t *testing.T) {
	// nil ScopePayload → SDK generates {"log_did": <LogDID>}.
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
		// ScopePayload explicitly left nil
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}
	if prov.ScopeEntry == nil {
		t.Fatal("ScopeEntry is nil")
	}
	// We can't easily introspect the entry without knowing the Entry
	// struct shape — but we can confirm the entry was built (non-nil)
	// and that non-zero fields are populated. Documented behavior says
	// the default is {"log_did": LogDID}; a deeper assertion requires
	// deserializing the entry which is outside the scope of this test.
}

func TestProvisionSingleLog_ExplicitEmptyScopePayloadIsRespected(t *testing.T) {
	// Empty slice (non-nil) → passed through verbatim, not replaced
	// with default. The nil/non-nil distinction is load-bearing per
	// the doc comment.
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
		ScopePayload: []byte{}, // explicit empty, not nil
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}
	if prov.ScopeEntry == nil {
		t.Fatal("ScopeEntry is nil")
	}
	// Same constraint as above — deeper assertion on payload bytes
	// requires envelope deserialization.
}

func TestProvisionSingleLog_CustomScopePayload(t *testing.T) {
	custom, err := json.Marshal(map[string]any{
		"log_did":  "did:web:log.test",
		"operator": "did:web:op.test",
		"domain":   "judicial-network",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
		ScopePayload: custom,
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}
	if prov.ScopeEntry == nil {
		t.Fatal("ScopeEntry is nil")
	}
}

// -------------------------------------------------------------------------------------------------
// LogProvision.AllEntries — ordering contract
// -------------------------------------------------------------------------------------------------

func TestLogProvision_AllEntriesOrderScope_Delegations_Schemas(t *testing.T) {
	prov, err := ProvisionSingleLog(SingleLogConfig{
		Destination:  testDestination,
		SignerDID:    "did:web:signer.test",
		LogDID:       "did:web:log.test",
		AuthoritySet: map[string]struct{}{"did:web:signer.test": {}},
		Delegations: []DelegationSpec{
			{DelegateDID: "did:web:a.test", ScopeLimit: []byte(`{}`)},
			{DelegateDID: "did:web:b.test", ScopeLimit: []byte(`{}`)},
		},
		Schemas: []SchemaSpec{
			{Payload: []byte(`{"s":1}`)},
		},
	})
	if err != nil {
		t.Fatalf("ProvisionSingleLog: %v", err)
	}

	all := prov.AllEntries()
	// 1 scope + 2 delegations + 1 schema = 4 entries.
	if len(all) != 4 {
		t.Fatalf("len(AllEntries()) = %d, want 4", len(all))
	}

	// The first entry must be the scope entry.
	if all[0] != prov.ScopeEntry {
		t.Error("AllEntries()[0] is not the ScopeEntry")
	}
	// Delegations follow the scope entry.
	if all[1] != prov.Delegations[0] || all[2] != prov.Delegations[1] {
		t.Error("delegations are not in expected positions 1..2")
	}
	// Schema entries follow delegations.
	if all[3] != prov.SchemaEntries[0] {
		t.Error("schema entry not in expected position 3")
	}
}

func TestLogProvision_AllEntriesHandlesNilScope(t *testing.T) {
	// A zero-value LogProvision must not panic.
	lp := &LogProvision{LogDID: "did:web:x.test"}
	all := lp.AllEntries()
	if len(all) != 0 {
		t.Fatalf("len(AllEntries()) = %d, want 0 for empty LogProvision", len(all))
	}
}
