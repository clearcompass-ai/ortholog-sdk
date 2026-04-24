package schema

import (
	"reflect"
	"strings"
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

// ─────────────────────────────────────────────────────────────────────
// Group 2.3 fail-closed regressions: Marshal side
//
// These tests pin the "refuse to emit bad enums" guarantee. Each one
// fails for a single specific reason if the corresponding default
// branch in MarshalParameters regresses (for example, if a future
// refactor replaces the explicit default with a silent fallback to a
// canonical string). The tests consume values outside the defined
// enum range, which the switch statement's default arm must reject
// with an error naming the offending value.
// ─────────────────────────────────────────────────────────────────────

// TestMarshalParameters_RejectsUnknownEnum_MigrationPolicy fails if
// MarshalParameters' MigrationPolicy switch silently accepts an
// out-of-range value.
func TestMarshalParameters_RejectsUnknownEnum_MigrationPolicy(t *testing.T) {
	in := &types.SchemaParameters{MigrationPolicy: types.MigrationPolicyType(99)}
	if _, err := MarshalParameters(in); err == nil {
		t.Fatal("Marshal: want error on MigrationPolicy=99, got nil")
	} else if !strings.Contains(err.Error(), "unknown MigrationPolicy") || !strings.Contains(err.Error(), "99") {
		t.Fatalf("Marshal: error = %v, want phrase 'unknown MigrationPolicy' and value '99'", err)
	}
}

// TestMarshalParameters_RejectsUnknownEnum_ArtifactEncryption fails
// if the ArtifactEncryption switch silently accepts an out-of-range
// value.
func TestMarshalParameters_RejectsUnknownEnum_ArtifactEncryption(t *testing.T) {
	in := &types.SchemaParameters{ArtifactEncryption: types.EncryptionScheme(99)}
	if _, err := MarshalParameters(in); err == nil {
		t.Fatal("Marshal: want error on ArtifactEncryption=99, got nil")
	} else if !strings.Contains(err.Error(), "unknown ArtifactEncryption") || !strings.Contains(err.Error(), "99") {
		t.Fatalf("Marshal: error = %v, want phrase 'unknown ArtifactEncryption' and value '99'", err)
	}
}

// TestMarshalParameters_RejectsUnknownEnum_GrantAuthorizationMode
// fails if the GrantAuthorizationMode switch silently accepts an
// out-of-range value.
func TestMarshalParameters_RejectsUnknownEnum_GrantAuthorizationMode(t *testing.T) {
	in := &types.SchemaParameters{GrantAuthorizationMode: types.GrantAuthorizationMode(99)}
	if _, err := MarshalParameters(in); err == nil {
		t.Fatal("Marshal: want error on GrantAuthorizationMode=99, got nil")
	} else if !strings.Contains(err.Error(), "unknown GrantAuthorizationMode") || !strings.Contains(err.Error(), "99") {
		t.Fatalf("Marshal: error = %v, want phrase 'unknown GrantAuthorizationMode' and value '99'", err)
	}
}

// TestMarshalParameters_RejectsUnknownEnum_OverrideThreshold fails
// if the OverrideThreshold switch silently accepts an out-of-range
// value.
func TestMarshalParameters_RejectsUnknownEnum_OverrideThreshold(t *testing.T) {
	in := &types.SchemaParameters{OverrideThreshold: types.OverrideThresholdRule(99)}
	if _, err := MarshalParameters(in); err == nil {
		t.Fatal("Marshal: want error on OverrideThreshold=99, got nil")
	} else if !strings.Contains(err.Error(), "unknown OverrideThreshold") || !strings.Contains(err.Error(), "99") {
		t.Fatalf("Marshal: error = %v, want phrase 'unknown OverrideThreshold' and value '99'", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Group 2.3 fail-closed regressions: Extract side
//
// JSON-side coverage symmetric to the Marshal-side tests above:
// Marshal tests confirm the SDK refuses to emit bad enums; Extract
// tests confirm the SDK refuses to accept bad enums on the wire.
// ─────────────────────────────────────────────────────────────────────

// extractUnknownEnumFixture builds a minimal JSON payload for a
// single enum field set to an unknown value and runs it through
// Extract. Returns the returned error for inspection.
func extractUnknownEnumFixture(t *testing.T, field, value string) error {
	t.Helper()
	// Minimal valid payload with one offending enum field. Every
	// other field is omitted; Extract fills defaults and fails only
	// on the unknown enum.
	payload := "{\"" + field + "\":\"" + value + "\"}"
	entry := &envelope.Entry{DomainPayload: []byte(payload)}
	_, err := NewJSONParameterExtractor().Extract(entry)
	return err
}

// TestExtract_RejectsUnknownEnum_MigrationPolicy fails if Extract's
// migration_policy switch silently accepts an unknown string on the
// wire.
func TestExtract_RejectsUnknownEnum_MigrationPolicy(t *testing.T) {
	err := extractUnknownEnumFixture(t, "migration_policy", "not-a-policy")
	if err == nil {
		t.Fatal("Extract: want error on migration_policy=\"not-a-policy\", got nil")
	}
	if !strings.Contains(err.Error(), "unknown migration_policy") {
		t.Fatalf("Extract: error = %v, want phrase 'unknown migration_policy'", err)
	}
}

// TestExtract_RejectsUnknownEnum_ArtifactEncryption fails if
// Extract's artifact_encryption switch silently accepts an unknown
// string on the wire.
func TestExtract_RejectsUnknownEnum_ArtifactEncryption(t *testing.T) {
	err := extractUnknownEnumFixture(t, "artifact_encryption", "not-a-scheme")
	if err == nil {
		t.Fatal("Extract: want error on artifact_encryption=\"not-a-scheme\", got nil")
	}
	if !strings.Contains(err.Error(), "unknown artifact_encryption") {
		t.Fatalf("Extract: error = %v, want phrase 'unknown artifact_encryption'", err)
	}
}

// TestExtract_RejectsUnknownEnum_GrantAuthorizationMode fails if
// Extract's grant_authorization_mode switch silently accepts an
// unknown string on the wire.
func TestExtract_RejectsUnknownEnum_GrantAuthorizationMode(t *testing.T) {
	err := extractUnknownEnumFixture(t, "grant_authorization_mode", "not-a-mode")
	if err == nil {
		t.Fatal("Extract: want error on grant_authorization_mode=\"not-a-mode\", got nil")
	}
	if !strings.Contains(err.Error(), "unknown grant_authorization_mode") {
		t.Fatalf("Extract: error = %v, want phrase 'unknown grant_authorization_mode'", err)
	}
}

// TestExtract_RejectsUnknownEnum_OverrideThreshold fails if Extract's
// override_threshold switch silently accepts an unknown string on
// the wire.
func TestExtract_RejectsUnknownEnum_OverrideThreshold(t *testing.T) {
	err := extractUnknownEnumFixture(t, "override_threshold", "not-a-rule")
	if err == nil {
		t.Fatal("Extract: want error on override_threshold=\"not-a-rule\", got nil")
	}
	if !strings.Contains(err.Error(), "unknown override_threshold") {
		t.Fatalf("Extract: error = %v, want phrase 'unknown override_threshold'", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Group 2.3 sentinel-discipline round-trip regressions
//
// Two named regressions for the sentinel semantics that
// parameters_json.go documents. Each fails if the round-trip
// contract the sentinel pins is silently changed.
// ─────────────────────────────────────────────────────────────────────

// TestRoundTrip_UnsetMigrationPolicy_EmitsEmptyStringSentinel pins
// the empty-string sentinel semantics for MigrationPolicy. A zero-
// valued MigrationPolicy (caller constructed SchemaParameters{} with
// no policy set) must emit "" on the wire and round-trip back to the
// zero value. The test fails if a future refactor drops the empty-
// string sentinel or starts emitting "strict" as a stealth default.
func TestRoundTrip_UnsetMigrationPolicy_EmitsEmptyStringSentinel(t *testing.T) {
	in := &types.SchemaParameters{}
	b, err := MarshalParameters(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), "\"migration_policy\":\"\"") {
		t.Fatalf("Marshal: wire form missing empty-string sentinel for migration_policy\n  got: %s", b)
	}

	entry := &envelope.Entry{DomainPayload: b}
	out, err := NewJSONParameterExtractor().Extract(entry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if out.MigrationPolicy != 0 {
		t.Fatalf("round-trip MigrationPolicy = %d, want 0 (zero value)", out.MigrationPolicy)
	}
}

// TestRoundTrip_NilCredentialValidityPeriod_EmitsNegativeOneSentinel
// pins the -1 sentinel semantics for CredentialValidityPeriod. A nil
// pointer must emit -1 on the wire (documented on marshalShape) and
// round-trip back to nil. The test fails if the sentinel constant
// changes, the mirrored Extract branch drops the sentinel check, or
// Marshal starts emitting 0 for nil.
func TestRoundTrip_NilCredentialValidityPeriod_EmitsNegativeOneSentinel(t *testing.T) {
	in := &types.SchemaParameters{CredentialValidityPeriod: nil}
	b, err := MarshalParameters(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), "\"credential_validity_period\":-1") {
		t.Fatalf("Marshal: wire form missing -1 sentinel for credential_validity_period\n  got: %s", b)
	}

	entry := &envelope.Entry{DomainPayload: b}
	out, err := NewJSONParameterExtractor().Extract(entry)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if out.CredentialValidityPeriod != nil {
		t.Fatalf("round-trip CredentialValidityPeriod = %v, want nil", *out.CredentialValidityPeriod)
	}

	// Cross-check: a populated value still round-trips correctly,
	// so the sentinel is not cannibalising legitimate zero-second
	// durations (it can't, because the sentinel is -1 and a real
	// duration is non-negative).
	cvp := 24 * time.Hour
	in2 := &types.SchemaParameters{CredentialValidityPeriod: &cvp}
	b2, err := MarshalParameters(in2)
	if err != nil {
		t.Fatalf("Marshal populated: %v", err)
	}
	entry2 := &envelope.Entry{DomainPayload: b2}
	out2, err := NewJSONParameterExtractor().Extract(entry2)
	if err != nil {
		t.Fatalf("Extract populated: %v", err)
	}
	if out2.CredentialValidityPeriod == nil || *out2.CredentialValidityPeriod != cvp {
		t.Fatalf("populated round-trip: got %v, want %v", out2.CredentialValidityPeriod, cvp)
	}
}
