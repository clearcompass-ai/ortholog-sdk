/*
FILE PATH:
    did/verifier_registry.go

DESCRIPTION:
    Signature verifier registry. Maps DID method -> SignatureVerifier and
    dispatches verification calls by DID method. This is the central entry
    point for "given a DID, a message, and a signature, is it valid?"

KEY ARCHITECTURAL DECISIONS:
    - Lives in the did/ package rather than crypto/signatures/ to avoid an
      import cycle: did/creation.go imports crypto/signatures for its key
      primitives, so crypto/signatures cannot import did/. The registry
      belongs with the other DID-aware logic.
    - Registration is fail-loud (identical pattern to MethodRouter). No
      silent overwriting.
    - SignatureVerifier is a narrow interface with one method. Concrete
      verifiers hold any state they need (e.g., WebVerifier holds a
      DIDResolver) and satisfy the interface.
    - The registry accepts both (did, message, sig, algoID) and dispatches
      on the DID method. It does NOT interpret the algoID — that is the
      verifier's job. The registry is pure routing.
    - Consumers wire DefaultVerifierRegistry() at startup for the standard
      three-method bundle (pkh, key, web) and extend with additional methods
      if their deployment needs them.

OVERVIEW:
    Wiring:
        resolver := did.NewWebDIDResolver(nil)  // for did:web lookups
        registry := did.DefaultVerifierRegistry(resolver)
        // or
        registry := did.NewVerifierRegistry()
        registry.MustRegister("pkh", did.NewPKHVerifier())
        registry.MustRegister("key", did.NewKeyVerifier())
        registry.MustRegister("web", did.NewWebVerifier(resolver))

    Verification:
        err := registry.Verify(did, message, sig, algoID)

KEY DEPENDENCIES:
    - did/method_router.go: ExtractMethod
    - SignatureVerifier implementations in did/pkh_verifier.go etc.
*/
package did

import (
	"errors"
	"fmt"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrVerifierNotRegistered is returned when no verifier is registered for the
// DID method of a given DID.
var ErrVerifierNotRegistered = errors.New("did/verifier: no verifier registered for method")

// ErrAlgorithmNotSupported is returned by a verifier when it does not support
// the requested signature algorithm ID.
var ErrAlgorithmNotSupported = errors.New("did/verifier: algorithm not supported by this DID method")

// -------------------------------------------------------------------------------------------------
// 2) SignatureVerifier interface
// -------------------------------------------------------------------------------------------------

// SignatureVerifier verifies a signature produced by the controller of a DID.
//
// Implementations are DID-method-specific. Each decides which algorithm IDs
// it supports and returns ErrAlgorithmNotSupported for any others.
type SignatureVerifier interface {
	// Verify checks that sig is a valid signature over message produced by
	// the controller of did under the given signature algorithm.
	//
	// For did:pkh the "message" is typically a 32-byte canonical entry
	// hash and the verifier performs ecrecover + address compare.
	//
	// For did:key the verifier extracts the public key from the identifier
	// and performs a pubkey verification appropriate to the key type.
	//
	// For did:web the verifier resolves the DID document and iterates
	// verification methods until one verifies (or none do).
	Verify(did string, message []byte, sig []byte, algoID uint16) error
}

// -------------------------------------------------------------------------------------------------
// 3) VerifierRegistry
// -------------------------------------------------------------------------------------------------

// VerifierRegistry dispatches verification by DID method.
type VerifierRegistry struct {
	mu        sync.RWMutex
	verifiers map[string]SignatureVerifier
}

// NewVerifierRegistry creates an empty registry.
func NewVerifierRegistry() *VerifierRegistry {
	return &VerifierRegistry{verifiers: make(map[string]SignatureVerifier)}
}

// DefaultVerifierRegistry returns a registry wired with the three built-in
// verifiers: pkh, key, and web. The web verifier requires a resolver for
// fetching remote DID documents.
func DefaultVerifierRegistry(webResolver DIDResolver) *VerifierRegistry {
	if webResolver == nil {
		panic("did/verifier: DefaultVerifierRegistry requires a non-nil web resolver")
	}
	r := NewVerifierRegistry()
	r.MustRegister("pkh", NewPKHVerifier())
	r.MustRegister("key", NewKeyVerifier())
	r.MustRegister("web", NewWebVerifier(webResolver))
	return r
}

// Register installs a verifier for the given DID method. Returns an error if
// a verifier is already registered for the method.
func (r *VerifierRegistry) Register(method string, v SignatureVerifier) error {
	if method == "" {
		return fmt.Errorf("did/verifier: cannot register empty method")
	}
	if v == nil {
		return fmt.Errorf("did/verifier: cannot register nil verifier for %q", method)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.verifiers[method]; exists {
		return fmt.Errorf("did/verifier: method %q already registered", method)
	}
	r.verifiers[method] = v
	return nil
}

// MustRegister panics if registration fails. Intended for wiring-time use.
func (r *VerifierRegistry) MustRegister(method string, v SignatureVerifier) {
	if err := r.Register(method, v); err != nil {
		panic(err)
	}
}

// Unregister removes the verifier for the given method.
func (r *VerifierRegistry) Unregister(method string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.verifiers[method]
	delete(r.verifiers, method)
	return existed
}

// Methods returns the registered DID methods for diagnostics.
func (r *VerifierRegistry) Methods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.verifiers))
	for m := range r.verifiers {
		out = append(out, m)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Verify dispatches to the verifier registered for the DID's method.
func (r *VerifierRegistry) Verify(did string, message []byte, sig []byte, algoID uint16) error {
	method, err := ExtractMethod(did)
	if err != nil {
		return err
	}
	r.mu.RLock()
	v, ok := r.verifiers[method]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %q", ErrVerifierNotRegistered, method)
	}
	return v.Verify(did, message, sig, algoID)
}
