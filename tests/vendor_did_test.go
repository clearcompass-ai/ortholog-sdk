/*
tests/vendor_did_test.go — VendorDIDResolver behavioral coverage.

These tests verify the generic VendorDIDResolver infrastructure using
domain-neutral fixtures. The SDK ships no domain-specific mappings —
judicial, credentialing, and other domain mappings live in their
respective downstream repos. These tests exercise the resolver using
abstract method names (alpha, beta, gamma) so the test suite is
free of any domain vocabulary.

Coverage:
  - Default colon-to-dot transform with domain suffix
  - Multi-segment specifics (did:method:a:b:c → reversed and joined)
  - Passthrough for unmapped methods
  - Custom TransformFunc (overrides the default transform)
  - Error paths: invalid DID, incomplete DID, transform error
  - Runtime mapping management: NewVendorDIDResolver, RegisterMapping,
    HasMapping
*/
package tests

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Fixture mappings
// ─────────────────────────────────────────────────────────────────────
//
// Three abstract mappings cover the relevant shape variations:
//
//   alpha  — single-segment specific:   did:alpha:foo
//   beta   — two-segment specific:      did:beta:foo:bar
//   gamma  — three-segment specific:    did:gamma:foo:bar:baz
//
// All three exercise the default colon-to-dot reversal transform.
// Custom transforms get their own dedicated fixtures inside the
// relevant test functions.

func alphaMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "alpha",
		DomainSuffix: ".alpha.example",
		TargetMethod: "web",
	}
}

func betaMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "beta",
		DomainSuffix: ".beta.example",
		TargetMethod: "web",
	}
}

func gammaMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "gamma",
		DomainSuffix: ".gamma.example",
		TargetMethod: "web",
	}
}

// ─────────────────────────────────────────────────────────────────────
// Default transform — single-segment specific
// ─────────────────────────────────────────────────────────────────────

// TestVendorDID_DefaultTransform_SingleSegment verifies the simplest
// case: a method-specific-id with no internal colons. The reversal
// is a no-op; the suffix is appended.
func TestVendorDID_DefaultTransform_SingleSegment(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{alphaMapping()})

	resolver.Resolve("did:alpha:foo")
	if resolved != "did:web:foo.alpha.example" {
		t.Fatalf("resolved: got %q, want %q", resolved, "did:web:foo.alpha.example")
	}
}

// TestVendorDID_DefaultTransform_TwoSegments verifies that a two-segment
// specific is reversed before joining: foo:bar → bar.foo.<suffix>.
func TestVendorDID_DefaultTransform_TwoSegments(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{betaMapping()})

	resolver.Resolve("did:beta:foo:bar")
	if resolved != "did:web:bar.foo.beta.example" {
		t.Fatalf("resolved: got %q, want %q", resolved, "did:web:bar.foo.beta.example")
	}
}

// TestVendorDID_DefaultTransform_ThreeSegments verifies the reversal
// continues to work for arbitrarily deep specifics: foo:bar:baz →
// baz.bar.foo.<suffix>. This is the pattern downstream domain repos
// rely on for hierarchical DIDs.
func TestVendorDID_DefaultTransform_ThreeSegments(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{gammaMapping()})

	resolver.Resolve("did:gamma:foo:bar:baz")
	if resolved != "did:web:baz.bar.foo.gamma.example" {
		t.Fatalf("resolved: got %q, want %q", resolved, "did:web:baz.bar.foo.gamma.example")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Passthrough — unmapped methods reach the base resolver unchanged
// ─────────────────────────────────────────────────────────────────────

func TestVendorDID_Passthrough(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:direct")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{alphaMapping()})

	// did:web is not a registered vendor mapping → passes through verbatim.
	resolver.Resolve("did:web:direct.example.com")
	if resolved != "did:web:direct.example.com" {
		t.Fatalf("passthrough: got %q, want %q", resolved, "did:web:direct.example.com")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error paths
// ─────────────────────────────────────────────────────────────────────

func TestVendorDID_InvalidDID_Error(t *testing.T) {
	base := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, nil)

	_, err := resolver.Resolve("not-a-did")
	if err == nil {
		t.Fatal("invalid DID should error")
	}
}

func TestVendorDID_IncompleteDID_Error(t *testing.T) {
	base := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, nil)

	_, err := resolver.Resolve("did:alpha:")
	if err == nil {
		t.Fatal("incomplete DID should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Custom TransformFunc — overrides the default transform
// ─────────────────────────────────────────────────────────────────────

// TestVendorDID_CustomTransform verifies that a non-nil TransformFunc
// short-circuits the default colon-to-dot reversal. Domain repos use
// this when their mapping rule isn't expressible as a simple suffix
// append (e.g., requires a lookup table or includes hash digests).
func TestVendorDID_CustomTransform(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}

	custom := did.VendorMapping{
		Method:       "custom",
		TargetMethod: "web",
		TransformFunc: func(specific string) (string, error) {
			return "custom-" + specific + ".example.com", nil
		},
	}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{custom})

	resolver.Resolve("did:custom:mylog")
	if resolved != "did:web:custom-mylog.example.com" {
		t.Fatalf("custom transform: got %q, want %q", resolved, "did:web:custom-mylog.example.com")
	}
}

// TestVendorDID_CustomTransform_Error verifies that an error from a
// TransformFunc propagates to the caller of Resolve, wrapped with
// context. Without this, a domain transform could silently fall back
// to a wrong DID.
func TestVendorDID_CustomTransform_Error(t *testing.T) {
	base := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	failing := did.VendorMapping{
		Method:       "fail",
		TargetMethod: "web",
		TransformFunc: func(string) (string, error) {
			return "", errors.New("transform error")
		},
	}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{failing})

	_, err := resolver.Resolve("did:fail:something")
	if err == nil {
		t.Fatal("transform error should propagate")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Runtime mapping management
// ─────────────────────────────────────────────────────────────────────

// TestVendorDID_RegisterMapping verifies that mappings can be added
// after construction. Operators register additional domain mappings
// at startup based on configuration; this test pins that behavior.
func TestVendorDID_RegisterMapping(t *testing.T) {
	base := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, nil)

	if resolver.HasMapping("alpha") {
		t.Fatal("should not have alpha mapping initially")
	}

	resolver.RegisterMapping(alphaMapping())

	if !resolver.HasMapping("alpha") {
		t.Fatal("should have alpha mapping after register")
	}
}

// TestVendorDID_HasMapping verifies positive and negative lookups.
// HasMapping is the discovery mechanism for callers that need to
// gate behavior on whether a method is supported.
func TestVendorDID_HasMapping(t *testing.T) {
	resolver := did.NewVendorDIDResolver(
		&staticDIDRes{doc: makeSampleDIDDoc("did:web:test")},
		[]did.VendorMapping{alphaMapping(), betaMapping()},
	)
	if !resolver.HasMapping("alpha") {
		t.Fatal("should have alpha")
	}
	if !resolver.HasMapping("beta") {
		t.Fatal("should have beta")
	}
	if resolver.HasMapping("unknown") {
		t.Fatal("should not have unknown")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Mock: captures the resolved DID string
// ─────────────────────────────────────────────────────────────────────

type captureDIDRes struct {
	resolved *string
	doc      did.DIDDocument
}

func (r *captureDIDRes) Resolve(didStr string) (*did.DIDDocument, error) {
	*r.resolved = didStr
	return &r.doc, nil
}
