/*
FILE PATH:
    did/resolver.go

DESCRIPTION:
    DID resolution core: the DIDDocument schema, the DIDResolver interface,
    the did:web resolver, the caching wrapper, and adapters satisfying witness
    and verifier consumer interfaces. Other DID methods (did:key, did:pkh)
    live in sibling files and satisfy DIDResolver via structural typing.

KEY ARCHITECTURAL DECISIONS:
    - DIDResolver is a single-method interface: Resolve(did) -> (*DIDDocument,
      error). Every concrete resolver (Web, Key, PKH, Method, Caching, ...)
      satisfies this interface, making composition trivial.
    - Pubkey decoding supports hex encoding, multibase 'f' (hex), and
      multibase 'z' (base58btc). The 'z' path is mandatory for interop with
      standards-compliant DID documents from other implementations.
    - WitnessKeys filters verification methods BY TYPE. It returns only keys
      that are appropriate for witness cosignatures (secp256k1 or Ed25519),
      not every verification method in the document. This prevents entry
      signing keys, DID-pkh recovery stubs, or BLS keys from being treated
      as witness keys.
    - DID-doc identity verification: if the fetched document carries an ID,
      it MUST match the requested DID. Mismatches are hard failures.
    - SDK-shipped verification method types cover all curves the SDK can
      verify against. Unknown types are filtered out of witness-key
      extraction — they cannot be silently accepted because the caller
      would have no way to verify signatures against them.

OVERVIEW:
    DIDResolver implementations in this package:
        WebDIDResolver     -> HTTP fetch per did:web spec
        CachingResolver    -> TTL cache wrapping any DIDResolver
        KeyResolver        -> pure parse (did/key_resolver.go)
        PKHResolver        -> pure parse (did/pkh.go)
        MethodRouter       -> dispatch-by-method (did/method_router.go)
        VendorDIDResolver  -> vendor-method rewriting (did/vendor_did.go)

    Adapters:
        DIDEndpointAdapter  -> satisfies witness.EndpointProvider
        DIDWitnessAdapter   -> satisfies witness.EndpointResolver

KEY DEPENDENCIES:
    - types.WitnessPublicKey: witness key representation
    - net/http: did:web HTTPS fetching
*/
package did

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/mr-tron/base58"
)

// -------------------------------------------------------------------------------------------------
// 1) Service type constants
// -------------------------------------------------------------------------------------------------

const (
	// ServiceTypeOperator is the DID Document service type for Ortholog operators.
	ServiceTypeOperator = "OrthologOperator"

	// ServiceTypeWitness is the DID Document service type for Ortholog witnesses.
	ServiceTypeWitness = "OrthologWitness"

	// ServiceTypeArtifactStore is the service type for artifact stores.
	ServiceTypeArtifactStore = "OrthologArtifactStore"
)

// -------------------------------------------------------------------------------------------------
// 2) DID Document types
// -------------------------------------------------------------------------------------------------

// DIDDocument is a W3C DID Document with Ortholog extensions.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
	Created            *time.Time           `json:"created,omitempty"`
	Updated            *time.Time           `json:"updated,omitempty"`

	// Ortholog extension: witness quorum configuration.
	WitnessQuorumK int `json:"ortholog:witnessQuorumK,omitempty"`
}

// VerificationMethod represents a public key or blockchain account in a DID
// Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyHex       string `json:"publicKeyHex,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`

	// BlockchainAccountID is populated for did:pkh verification methods
	// whose identity IS the blockchain account, with no separate pubkey.
	// Format: CAIP-10 "<namespace>:<reference>:<address>".
	BlockchainAccountID string `json:"blockchainAccountId,omitempty"`
}

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// -------------------------------------------------------------------------------------------------
// 3) DIDDocument helper methods
// -------------------------------------------------------------------------------------------------

// OperatorEndpointURL returns the first OrthologOperator service endpoint.
func (d *DIDDocument) OperatorEndpointURL() (string, error) {
	for _, s := range d.Service {
		if s.Type == ServiceTypeOperator {
			return s.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("did: no %s service in document %s", ServiceTypeOperator, d.ID)
}

// WitnessEndpointURLs returns all OrthologWitness service endpoints.
func (d *DIDDocument) WitnessEndpointURLs() []string {
	var urls []string
	for _, s := range d.Service {
		if s.Type == ServiceTypeWitness {
			urls = append(urls, s.ServiceEndpoint)
		}
	}
	return urls
}

// ArtifactStoreURL returns the first OrthologArtifactStore service endpoint.
func (d *DIDDocument) ArtifactStoreURL() (string, error) {
	for _, s := range d.Service {
		if s.Type == ServiceTypeArtifactStore {
			return s.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("did: no %s service in document %s", ServiceTypeArtifactStore, d.ID)
}

// FindVerificationMethod returns the first verification method with the given
// ID, or nil if none match.
func (d *DIDDocument) FindVerificationMethod(vmID string) *VerificationMethod {
	for i := range d.VerificationMethod {
		if d.VerificationMethod[i].ID == vmID {
			return &d.VerificationMethod[i]
		}
	}
	return nil
}

// WitnessKeys returns the subset of verification methods that are valid for
// witness cosignature verification.
//
// Only keys whose Type matches an Ortholog-supported witness curve are
// returned. Unknown types, did:pkh recovery stubs, and BLS keys are
// excluded.
func (d *DIDDocument) WitnessKeys() ([]types.WitnessPublicKey, error) {
	var keys []types.WitnessPublicKey
	for _, vm := range d.VerificationMethod {
		if !isWitnessSupportedType(vm.Type) {
			continue
		}
		pubBytes, err := decodePublicKey(vm)
		if err != nil {
			return nil, fmt.Errorf("did: verification method %s: %w", vm.ID, err)
		}
		id := sha256.Sum256(pubBytes)
		keys = append(keys, types.WitnessPublicKey{
			ID:        id,
			PublicKey: pubBytes,
		})
	}
	return keys, nil
}

// isWitnessSupportedType reports whether the given verification method type
// identifies a curve the SDK can produce witness cosignatures against.
func isWitnessSupportedType(vmType string) bool {
	switch vmType {
	case VerificationMethodSecp256k1,
		VerificationMethodEd25519,
		VerificationMethodP256:
		return true
	default:
		return false
	}
}

// decodePublicKey extracts raw public key bytes from a verification method,
// supporting hex, multibase 'f' (hex), and multibase 'z' (base58btc).
func decodePublicKey(vm VerificationMethod) ([]byte, error) {
	if vm.PublicKeyHex != "" {
		return hex.DecodeString(vm.PublicKeyHex)
	}
	if vm.PublicKeyMultibase != "" && len(vm.PublicKeyMultibase) > 1 {
		switch vm.PublicKeyMultibase[0] {
		case 'f':
			return hex.DecodeString(vm.PublicKeyMultibase[1:])
		case 'z':
			decoded, err := base58.Decode(vm.PublicKeyMultibase[1:])
			if err != nil {
				return nil, fmt.Errorf("did: base58 decode: %w", err)
			}
			return decoded, nil
		default:
			return nil, fmt.Errorf(
				"did: unsupported multibase encoding %q",
				vm.PublicKeyMultibase[0])
		}
	}
	return nil, errors.New("did: no decodable public key in verification method")
}

// -------------------------------------------------------------------------------------------------
// 4) Errors
// -------------------------------------------------------------------------------------------------

// ErrDIDNotFound is returned when a DID cannot be resolved.
var ErrDIDNotFound = errors.New("did: not found")

// ErrDIDMethodNotSupported is returned for unsupported DID methods.
var ErrDIDMethodNotSupported = errors.New("did: method not supported")

// -------------------------------------------------------------------------------------------------
// 5) DIDResolver interface
// -------------------------------------------------------------------------------------------------

// DIDResolver resolves a DID string to a DIDDocument.
type DIDResolver interface {
	Resolve(did string) (*DIDDocument, error)
}

// -------------------------------------------------------------------------------------------------
// 6) WebDIDResolver
// -------------------------------------------------------------------------------------------------

// WebDIDResolver resolves did:web identifiers by fetching DID documents over
// HTTPS per the did:web specification.
//
//	did:web:example.com           -> https://example.com/.well-known/did.json
//	did:web:example.com:path:to   -> https://example.com/path/to/did.json
type WebDIDResolver struct {
	Client *http.Client
}

// NewWebDIDResolver creates a resolver with the given HTTP client. A nil
// client yields a default client with a 15-second timeout.
func NewWebDIDResolver(client *http.Client) *WebDIDResolver {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &WebDIDResolver{Client: client}
}

// Resolve fetches and parses a did:web DID document.
func (r *WebDIDResolver) Resolve(did string) (*DIDDocument, error) {
	url, err := DIDWebToURL(did)
	if err != nil {
		return nil, err
	}

	resp, err := r.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("did/web: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrDIDNotFound, did)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did/web: HTTP %d for %s", resp.StatusCode, did)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("did/web: read body: %w", err)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did/web: parse document: %w", err)
	}

	if doc.ID != "" && doc.ID != did {
		return nil, fmt.Errorf(
			"did/web: document ID %q does not match requested %q",
			doc.ID, did)
	}

	return &doc, nil
}

// DIDWebToURL converts a did:web identifier to its HTTPS URL.
func DIDWebToURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf(
			"%w: expected did:web:, got %s",
			ErrDIDMethodNotSupported, did)
	}

	specific := strings.TrimPrefix(did, "did:web:")
	if specific == "" {
		return "", fmt.Errorf("did/web: empty domain in %s", did)
	}

	parts := strings.Split(specific, ":")
	domain := parts[0]

	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json", nil
	}
	path := strings.Join(parts[1:], "/")
	return "https://" + domain + "/" + path + "/did.json", nil
}

// -------------------------------------------------------------------------------------------------
// 7) CachingResolver
// -------------------------------------------------------------------------------------------------

// CachingResolver wraps any DIDResolver with a thread-safe TTL cache.
type CachingResolver struct {
	inner DIDResolver
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]*cachedDoc
}

type cachedDoc struct {
	doc       *DIDDocument
	fetchedAt time.Time
}

// NewCachingResolver creates a caching wrapper. A non-positive TTL defaults
// to five minutes.
func NewCachingResolver(inner DIDResolver, ttl time.Duration) *CachingResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &CachingResolver{
		inner: inner,
		ttl:   ttl,
		cache: make(map[string]*cachedDoc),
	}
}

// Resolve returns a cached document if fresh, otherwise delegates to inner.
func (c *CachingResolver) Resolve(did string) (*DIDDocument, error) {
	c.mu.RLock()
	cached, ok := c.cache[did]
	c.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) <= c.ttl {
		return cached.doc, nil
	}

	doc, err := c.inner.Resolve(did)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[did] = &cachedDoc{doc: doc, fetchedAt: time.Now().UTC()}
	c.mu.Unlock()

	return doc, nil
}

// InvalidateCache removes a cached document.
func (c *CachingResolver) InvalidateCache(did string) {
	c.mu.Lock()
	delete(c.cache, did)
	c.mu.Unlock()
}

// CacheSize returns the number of cached entries.
func (c *CachingResolver) CacheSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// -------------------------------------------------------------------------------------------------
// 8) Adapters -> witness package interfaces (structural typing)
// -------------------------------------------------------------------------------------------------

// DIDEndpointAdapter satisfies witness.EndpointProvider via structural typing.
type DIDEndpointAdapter struct {
	Resolver DIDResolver
}

// OperatorEndpoint resolves a log DID and returns the operator service URL.
func (a *DIDEndpointAdapter) OperatorEndpoint(logDID string) (string, error) {
	doc, err := a.Resolver.Resolve(logDID)
	if err != nil {
		return "", err
	}
	return doc.OperatorEndpointURL()
}

// WitnessEndpoints resolves a log DID and returns witness service URLs.
func (a *DIDEndpointAdapter) WitnessEndpoints(logDID string) ([]string, error) {
	doc, err := a.Resolver.Resolve(logDID)
	if err != nil {
		return nil, err
	}
	return doc.WitnessEndpointURLs(), nil
}

// DIDWitnessAdapter satisfies witness.EndpointResolver via structural typing.
type DIDWitnessAdapter struct {
	Resolver DIDResolver
}

// ResolveWitnessKeys resolves a log DID and extracts witness keys and quorum.
func (a *DIDWitnessAdapter) ResolveWitnessKeys(logDID string) ([]types.WitnessPublicKey, int, error) {
	doc, err := a.Resolver.Resolve(logDID)
	if err != nil {
		return nil, 0, err
	}
	keys, err := doc.WitnessKeys()
	if err != nil {
		return nil, 0, err
	}
	quorumK := doc.WitnessQuorumK
	if quorumK <= 0 {
		quorumK = len(keys)/2 + 1
	}
	return keys, quorumK, nil
}
