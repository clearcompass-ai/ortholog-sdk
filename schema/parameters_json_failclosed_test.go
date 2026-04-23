package schema

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Marshal-side fail-closed tests
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
// Extract-side fail-closed tests
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
// Sentinel-discipline round-trip tests
//
// Two named regressions for the sentinel semantics that parameters_
// json.go documents. Each fails if the round-trip contract the
// sentinel pins is silently changed.
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
