package schema

import (
	"reflect"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// roundTripParams walks a canonical JSON round-trip: p → Marshal(p) →
// Extract → p'. The returned value is what the verifier would read
// back from the schema entry's Domain Payload. Callers assert
// reflect.DeepEqual(input, result).
func roundTripParams(t *testing.T, in *types.SchemaParameters) *types.SchemaParameters {
	t.Helper()
	b, err := MarshalParameters(in)
	if err != nil {
		t.Fatalf("MarshalParameters: %v", err)
	}
	entry := &envelope.Entry{DomainPayload: b}
	ext := NewJSONParameterExtractor()
	out, err := ext.Extract(entry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return out
}

// dur is a tiny helper to keep the table rows readable.
func dur(d time.Duration) *time.Duration { return &d }

// thr is a ThresholdConfig pointer helper.
func thr(m, n int) *types.ThresholdConfig { return &types.ThresholdConfig{M: m, N: n} }

// predecessor helper for the PredecessorSchema column.
func predecessor(did string, seq uint64) *types.LogPosition {
	return &types.LogPosition{LogDID: did, Sequence: seq}
}

// TestSchemaParams_RoundTrip_ExhaustiveTable is the permanent
// regression gate for the Extract(Marshal(p)) == p invariant (D4 in
// the v7.5 plan). Every combination below covers enum coverage on
// every enum-typed field, plus representative scalar and pointer
// variants. The all-defaults and all-non-default rows bracket the
// combinatorial space.
//
// Every new parameter added to SchemaParameters must extend this
// table. Failure here blocks the change until the marshal/extract
// symmetry is restored.
func TestSchemaParams_RoundTrip_ExhaustiveTable(t *testing.T) {
	cases := []struct {
		name string
		in   types.SchemaParameters
	}{
		// ── Enum coverage ────────────────────────────────────────
		{"mig_strict", types.SchemaParameters{MigrationPolicy: types.MigrationStrict}},
		{"mig_forward", types.SchemaParameters{MigrationPolicy: types.MigrationForward}},
		{"mig_amendment", types.SchemaParameters{MigrationPolicy: types.MigrationAmendment}},
		{"enc_aes", types.SchemaParameters{ArtifactEncryption: types.EncryptionAESGCM}},
		{"enc_umbral", types.SchemaParameters{ArtifactEncryption: types.EncryptionUmbralPRE}},
		{"grant_open", types.SchemaParameters{GrantAuthorizationMode: types.GrantAuthOpen}},
		{"grant_restricted", types.SchemaParameters{GrantAuthorizationMode: types.GrantAuthRestricted}},
		{"grant_sealed", types.SchemaParameters{GrantAuthorizationMode: types.GrantAuthSealed}},
		{"thr_two_thirds", types.SchemaParameters{OverrideThreshold: types.ThresholdTwoThirdsMajority}},
		{"thr_simple", types.SchemaParameters{OverrideThreshold: types.ThresholdSimpleMajority}},
		{"thr_unanimity", types.SchemaParameters{OverrideThreshold: types.ThresholdUnanimity}},

		// ── CredentialValidityPeriod variants ─────────────────────
		{"cvp_nil", types.SchemaParameters{}},
		{"cvp_24h", types.SchemaParameters{CredentialValidityPeriod: dur(24 * time.Hour)}},
		{"cvp_year", types.SchemaParameters{CredentialValidityPeriod: dur(365 * 24 * time.Hour)}},

		// ── PredecessorSchema variants ────────────────────────────
		{"pred_nil", types.SchemaParameters{}},
		{"pred_set", types.SchemaParameters{PredecessorSchema: predecessor("did:ortholog:log1", 42)}},

		// ── ReEncryptionThreshold variants ────────────────────────
		{"rek_nil", types.SchemaParameters{}},
		{"rek_3of5", types.SchemaParameters{ReEncryptionThreshold: thr(3, 5)}},
		{"rek_2of3", types.SchemaParameters{ReEncryptionThreshold: thr(2, 3)}},

		// ── Booleans ──────────────────────────────────────────────
		{"owr_false", types.SchemaParameters{OverrideRequiresIndependentWitness: false}},
		{"owr_true", types.SchemaParameters{OverrideRequiresIndependentWitness: true}},
		{"ger_false", types.SchemaParameters{GrantEntryRequired: false}},
		{"ger_true", types.SchemaParameters{GrantEntryRequired: true}},
		{"grae_false", types.SchemaParameters{GrantRequiresAuditEntry: false}},
		{"grae_true", types.SchemaParameters{GrantRequiresAuditEntry: true}},

		// ── CommutativeOperations variants ────────────────────────
		{"commut_empty", types.SchemaParameters{CommutativeOperations: []uint32{}}},
		{"commut_one", types.SchemaParameters{CommutativeOperations: []uint32{1}}},
		{"commut_three", types.SchemaParameters{CommutativeOperations: []uint32{1, 2, 3}}},
		{"commut_five", types.SchemaParameters{CommutativeOperations: []uint32{0, 1, 2, 3, 4}}},

		// ── Scalars ───────────────────────────────────────────────
		{"delay_0", types.SchemaParameters{ActivationDelay: 0}},
		{"delay_1m", types.SchemaParameters{ActivationDelay: time.Minute}},
		{"delay_1d", types.SchemaParameters{ActivationDelay: 24 * time.Hour}},
		{"cosig_0", types.SchemaParameters{CosignatureThreshold: 0}},
		{"cosig_2", types.SchemaParameters{CosignatureThreshold: 2}},
		{"cosig_12", types.SchemaParameters{CosignatureThreshold: 12}},
		{"mat_0", types.SchemaParameters{MaturationEpoch: 0}},
		{"mat_5m", types.SchemaParameters{MaturationEpoch: 5 * time.Minute}},
		{"mat_1y", types.SchemaParameters{MaturationEpoch: 365 * 24 * time.Hour}},

		// ── Bracketing rows ──────────────────────────────────────
		{"all_defaults", types.SchemaParameters{
			// Zero-value params — every enum field must set its
			// canonical default explicitly in the expected output
			// because Extract assigns the defaults for absent
			// fields, and the zero SchemaParameters has the same
			// enum values as those defaults.
		}},
		{"all_non_default", types.SchemaParameters{
			ActivationDelay:                    42 * time.Hour,
			CosignatureThreshold:               7,
			MaturationEpoch:                    3 * time.Hour,
			CredentialValidityPeriod:           dur(180 * 24 * time.Hour),
			OverrideRequiresIndependentWitness: true,
			MigrationPolicy:                    types.MigrationForward,
			PredecessorSchema:                  predecessor("did:ortholog:pred", 99),
			OverrideThreshold:                  types.ThresholdUnanimity,
			ArtifactEncryption:                 types.EncryptionUmbralPRE,
			GrantEntryRequired:                 true,
			ReEncryptionThreshold:              thr(5, 7),
			GrantAuthorizationMode:             types.GrantAuthSealed,
			GrantRequiresAuditEntry:            true,
			CommutativeOperations:              []uint32{100, 200, 300},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Normalize the input the same way Extract would (the
			// invariant is Extract(Marshal(p)) == Extract(Marshal(
			// Extract(Marshal(p)))), which is equivalent to
			// comparing against the normalized form).
			want := tc.in
			if want.CommutativeOperations == nil {
				want.CommutativeOperations = []uint32{}
			}
			got := roundTripParams(t, &tc.in)
			if !reflect.DeepEqual(&want, got) {
				t.Fatalf("round-trip mismatch\n want: %+v\n  got: %+v", &want, got)
			}
		})
	}
}
