/*
Package did provides DID (Decentralized Identifier) resolution for the
Ortholog protocol.

resolver.go defines:
  - DIDDocument and its sub-types (W3C DID Core compatible)
  - DIDResolver interface (the central abstraction)
  - WebDIDResolver (did:web method — HTTP fetch of DID documents)
  - CachingResolver (wraps any DIDResolver with TTL cache)
  - DIDEndpointAdapter (satisfies witness.EndpointProvider via structural typing)
  - DIDWitnessAdapter (satisfies witness.EndpointResolver via structural typing)

Consumed by:
  - witness/verify.go — VerifyTreeHeadWithResolution (needs witness keys)
  - witness/tree_head_client.go — FetchLatestTreeHead (needs operator endpoint)
  - verifier/cross_log.go — ResolveCrossLogRef (needs foreign log discovery)
  - verifier/bootstrap.go — AnchorLogSync (needs anchor log endpoint)
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
)

// ─────────────────────────────────────────────────────────────────────
// DID Document types (W3C DID Core compatible)
// ─────────────────────────────────────────────────────────────────────

// ServiceTypeOperator is the DID Document service type for Ortholog operators.
const ServiceTypeOperator = "OrthologOperator"

// ServiceTypeWitness is the DID Document service type for Ortholog witnesses.
const ServiceTypeWitness = "OrthologWitness"

// ServiceTypeArtifactStore is the service type for artifact stores.
const ServiceTypeArtifactStore = "OrthologArtifactStore"

// DIDDocument represents a W3C DID Document with Ortholog extensions.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
	Created            *time.Time           `json:"created,omitempty"`
	Updated            *time.Time           `json:"updated,omitempty"`

	// Ortholog extensions: witness quorum configuration.
	WitnessQuorumK int `json:"ortholog:witnessQuorumK,omitempty"`
}

// VerificationMethod represents a public key in a DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyHex       string `json:"publicKeyHex,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// ─────────────────────────────────────────────────────────────────────
// DIDDocument helper methods
// ─────────────────────────────────────────────────────────────────────

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

// WitnessKeys extracts witness public keys from verification methods.
// Keys with type "EcdsaSecp256r1VerificationKey2019" or
// "Bls12381G2Key2020" are treated as witness keys.
func (d *DIDDocument) WitnessKeys() ([]types.WitnessPublicKey, error) {
	var keys []types.WitnessPublicKey
	for _, vm := range d.VerificationMethod {
		pubBytes, err := decodePublicKey(vm)
		if err != nil {
			continue // Skip undecodable keys.
		}
		id := sha256.Sum256(pubBytes)
		keys = append(keys, types.WitnessPublicKey{
			ID:        id,
			PublicKey: pubBytes,
		})
	}
	return keys, nil
}

func decodePublicKey(vm VerificationMethod) ([]byte, error) {
	if vm.PublicKeyHex != "" {
		return hex.DecodeString(vm.PublicKeyHex)
	}
	if vm.PublicKeyMultibase != "" && len(vm.PublicKeyMultibase) > 1 {
		// Multibase: first character is base identifier. 'f' = hex, 'z' = base58btc.
		switch vm.PublicKeyMultibase[0] {
		case 'f':
			return hex.DecodeString(vm.PublicKeyMultibase[1:])
		default:
			return nil, fmt.Errorf("did: unsupported multibase encoding: %c", vm.PublicKeyMultibase[0])
		}
	}
	return nil, errors.New("did: no decodable public key in verification method")
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrDIDNotFound is returned when a DID cannot be resolved.
var ErrDIDNotFound = errors.New("did: not found")

// ErrDIDMethodNotSupported is returned for unsupported DID methods.
var ErrDIDMethodNotSupported = errors.New("did: method not supported")

// ─────────────────────────────────────────────────────────────────────
// DIDResolver interface
// ─────────────────────────────────────────────────────────────────────

// DIDResolver resolves a DID string to a DIDDocument.
// Implementations: WebDIDResolver (did:web), CachingResolver (wrapper),
// VendorDIDResolver (vendor mapping + delegation).
type DIDResolver interface {
	Resolve(did string) (*DIDDocument, error)
}

// ─────────────────────────────────────────────────────────────────────
// WebDIDResolver — did:web method
// ─────────────────────────────────────────────────────────────────────

// WebDIDResolver resolves did:web identifiers by fetching DID documents
// over HTTPS. Per the did:web spec:
//
//	did:web:example.com           → https://example.com/.well-known/did.json
//	did:web:example.com:path:to   → https://example.com/path/to/did.json
type WebDIDResolver struct {
	Client *http.Client
}

// NewWebDIDResolver creates a resolver with the given HTTP client.
// If client is nil, a default client with 15s timeout is used.
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

	// Verify the document ID matches the requested DID.
	if doc.ID != "" && doc.ID != did {
		return nil, fmt.Errorf("did/web: document ID %q does not match requested %q", doc.ID, did)
	}

	return &doc, nil
}

// DIDWebToURL converts a did:web identifier to its HTTPS URL.
// Exported for testing.
func DIDWebToURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("%w: expected did:web:, got %s", ErrDIDMethodNotSupported, did)
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

// ─────────────────────────────────────────────────────────────────────
// CachingResolver — TTL cache around any DIDResolver
// ─────────────────────────────────────────────────────────────────────

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

// NewCachingResolver creates a caching wrapper.
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

// ─────────────────────────────────────────────────────────────────────
// Adapters: DIDResolver → witness package interfaces
// ─────────────────────────────────────────────────────────────────────

// DIDEndpointAdapter satisfies witness.EndpointProvider (structural typing).
// Methods: OperatorEndpoint(logDID) and WitnessEndpoints(logDID).
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

// DIDWitnessAdapter satisfies witness.EndpointResolver (structural typing).
// Method: ResolveWitnessKeys(logDID) → (keys, quorumK, error).
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
		// Default: majority quorum.
		quorumK = len(keys)/2 + 1
	}
	return keys, quorumK, nil
}
