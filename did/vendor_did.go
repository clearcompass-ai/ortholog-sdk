/*
did/vendor_did.go — Vendor-specific DID method mapping and resolution.

VendorDIDResolver transforms vendor-specific DID methods into standard
methods before delegating to a base resolver. This allows downstream
consumers (judicial networks, credentialing platforms) to support
non-standard DID methods without changes to the SDK.

Consumers register mappings via NewVendorDIDResolver or RegisterMapping.
The SDK ships no default mappings — all method-specific transforms
(did:court:*, did:jnet:*, etc.) are domain concerns and belong in
domain repos.

Example construction from a domain repo:

	resolver := did.NewVendorDIDResolver(baseResolver, []did.VendorMapping{
	    {Method: "court", DomainSuffix: ".court.gov", TargetMethod: "web"},
	})
*/
package did

import (
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────
// VendorMapping
// ─────────────────────────────────────────────────────────────────────

// VendorMapping defines a rule for transforming a vendor DID method
// to a standard DID method.
type VendorMapping struct {
	// Method is the vendor-specific DID method prefix (e.g., "court").
	Method string

	// DomainSuffix is appended to the transformed domain (e.g., ".gov").
	DomainSuffix string

	// TargetMethod is the standard method to delegate to (e.g., "web").
	TargetMethod string

	// TransformFunc optionally provides custom transformation logic.
	// If nil, the default colon-to-dot reversal is used.
	TransformFunc func(specific string) (string, error)
}

// ─────────────────────────────────────────────────────────────────────
// VendorDIDResolver
// ─────────────────────────────────────────────────────────────────────

// VendorDIDResolver wraps a base DIDResolver with vendor-specific
// method mappings. If a DID's method matches a registered mapping,
// it is transformed before delegation. Unknown methods pass through
// to the base resolver unchanged.
type VendorDIDResolver struct {
	base     DIDResolver
	mappings map[string]VendorMapping
}

// NewVendorDIDResolver creates a resolver with the given mappings.
func NewVendorDIDResolver(base DIDResolver, mappings []VendorMapping) *VendorDIDResolver {
	m := make(map[string]VendorMapping, len(mappings))
	for _, mapping := range mappings {
		m[mapping.Method] = mapping
	}
	return &VendorDIDResolver{base: base, mappings: m}
}

// Resolve transforms vendor DIDs and delegates to the base resolver.
func (v *VendorDIDResolver) Resolve(did string) (*DIDDocument, error) {
	method, specific, err := parseDID(did)
	if err != nil {
		return nil, err
	}

	mapping, ok := v.mappings[method]
	if !ok {
		// No mapping — pass through to base resolver.
		return v.base.Resolve(did)
	}

	transformedDID, err := applyMapping(method, specific, mapping)
	if err != nil {
		return nil, fmt.Errorf("did/vendor: transform %s: %w", did, err)
	}

	return v.base.Resolve(transformedDID)
}

// RegisterMapping adds or replaces a vendor mapping at runtime.
func (v *VendorDIDResolver) RegisterMapping(mapping VendorMapping) {
	v.mappings[mapping.Method] = mapping
}

// HasMapping returns true if a mapping exists for the given method.
func (v *VendorDIDResolver) HasMapping(method string) bool {
	_, ok := v.mappings[method]
	return ok
}

// ─────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────

// parseDID extracts the method and method-specific-id from a DID string.
func parseDID(did string) (method, specific string, err error) {
	if !strings.HasPrefix(did, "did:") {
		return "", "", fmt.Errorf("did/vendor: invalid DID format: %s", did)
	}

	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return "", "", fmt.Errorf("did/vendor: incomplete DID: %s", did)
	}

	return parts[1], parts[2], nil
}

// applyMapping transforms a vendor DID using the given mapping.
func applyMapping(method, specific string, mapping VendorMapping) (string, error) {
	if mapping.TransformFunc != nil {
		transformed, err := mapping.TransformFunc(specific)
		if err != nil {
			return "", err
		}
		return "did:" + mapping.TargetMethod + ":" + transformed, nil
	}

	// Default transformation: reverse colon-separated parts, join with dots,
	// append domain suffix.
	parts := strings.Split(specific, ":")
	reversed := make([]string, len(parts))
	for i, p := range parts {
		reversed[len(parts)-1-i] = p
	}
	domain := strings.Join(reversed, ".") + mapping.DomainSuffix
	return "did:" + mapping.TargetMethod + ":" + domain, nil
}
