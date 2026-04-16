package tests

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Inline mapping fixtures
// ─────────────────────────────────────────────────────────────────────
//
// Wave 3: the did package no longer ships judicial mapping helpers
// (CourtMapping, JNetMapping, CCRMapping). They moved to the
// judicial-network repo. These tests continue to exercise the generic
// VendorDIDResolver infrastructure using inline VendorMapping literals
// equivalent to the old helpers.

func courtMappingFixture() did.VendorMapping {
	return did.VendorMapping{
		Method:       "court",
		DomainSuffix: ".court.gov",
		TargetMethod: "web",
	}
}

func jnetMappingFixture() did.VendorMapping {
	return did.VendorMapping{
		Method:       "jnet",
		DomainSuffix: ".jnet.gov",
		TargetMethod: "web",
	}
}

func ccrMappingFixture() did.VendorMapping {
	return did.VendorMapping{
		Method:       "ccr",
		DomainSuffix: ".ccr.org",
		TargetMethod: "web",
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VendorDIDResolver
// ─────────────────────────────────────────────────────────────────────

func TestVendorDID_CourtMapping(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{courtMappingFixture()})

	resolver.Resolve("did:court:davidson-county")
	if resolved != "did:web:davidson-county.court.gov" {
		t.Fatalf("resolved: %s", resolved)
	}
}

func TestVendorDID_JNetMapping(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{jnetMappingFixture()})

	resolver.Resolve("did:jnet:tn:criminal")
	if resolved != "did:web:criminal.tn.jnet.gov" {
		t.Fatalf("resolved: %s", resolved)
	}
}

func TestVendorDID_CCRMapping(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{ccrMappingFixture()})

	resolver.Resolve("did:ccr:issuer:state-bar")
	if resolved != "did:web:state-bar.issuer.ccr.org" {
		t.Fatalf("resolved: %s", resolved)
	}
}

func TestVendorDID_Passthrough(t *testing.T) {
	var resolved string
	base := &captureDIDRes{resolved: &resolved, doc: makeSampleDIDDoc("did:web:direct")}
	resolver := did.NewVendorDIDResolver(base, []did.VendorMapping{courtMappingFixture()})

	// did:web is not a vendor mapping → passes through.
	resolver.Resolve("did:web:direct.example.com")
	if resolved != "did:web:direct.example.com" {
		t.Fatalf("passthrough: %s", resolved)
	}
}

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

	_, err := resolver.Resolve("did:court:")
	if err == nil {
		t.Fatal("incomplete DID should error")
	}
}

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
		t.Fatalf("custom: %s", resolved)
	}
}

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

func TestVendorDID_RegisterMapping(t *testing.T) {
	base := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	resolver := did.NewVendorDIDResolver(base, nil)

	if resolver.HasMapping("court") {
		t.Fatal("should not have court mapping initially")
	}

	resolver.RegisterMapping(courtMappingFixture())

	if !resolver.HasMapping("court") {
		t.Fatal("should have court mapping after register")
	}
}

func TestVendorDID_HasMapping(t *testing.T) {
	resolver := did.NewVendorDIDResolver(
		&staticDIDRes{doc: makeSampleDIDDoc("did:web:test")},
		[]did.VendorMapping{courtMappingFixture(), jnetMappingFixture()},
	)
	if !resolver.HasMapping("court") {
		t.Fatal("should have court")
	}
	if !resolver.HasMapping("jnet") {
		t.Fatal("should have jnet")
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
