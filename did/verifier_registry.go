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
    - Destination-scoped: every registry instance is bound to a single
      exchange DID at construction time. VerifyEntry asserts that an
      incoming entry's Destination matches this registry's destination
      before verifying the signature. This is the runtime enforcement
      of the destination-binding defense — an attacker cannot present a
      signed entry bound to exchange A to a registry scoped for exchange
      B, even though the signature is cryptographically valid.
    - Registration is fail-loud (identical pattern to MethodRouter). No
      silent overwriting.
    - SignatureVerifier is a narrow interface with one method. Concrete
      verifiers hold any state they need (e.g., WebVerifier holds a
      DIDResolver) and satisfy the interface.
    - The registry accepts both (did, message, sig, algoID) and dispatches
      on the DID method. It does NOT interpret the algoID — that is the
      verifier's job. The registry is pure routing.
    - Consumers wire DefaultVerifierRegistry(destinationDID, resolver) at
      startup for the standard three-method bundle (pkh, key, web) and
      extend with additional methods if their deployment needs them.

OVERVIEW:
    Wiring:
        resolver := did.NewWebDIDResolver(nil)
        registry := did.DefaultVerifierRegistry(
            "did:web:exchange.example.com",
            resolver,
        )

    Low-level verification (legacy callers who already have the hash):
        err := registry.Verify(signerDID, canonicalHash, sig, algoID)

    High-level verification (recommended — enforces destination binding):
        err := registry.VerifyEntry(entry, sig, algoID)

KEY DEPENDENCIES:
    - did/method_router.go: ExtractMethod
    - core/envelope: Entry, Serialize, ValidateDestination
    - SignatureVerifier implementations in did/pkh_verifier.go etc.
*/
package did

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
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

// ErrDestinationMismatch is returned by VerifyEntry when the entry's
// Destination does not match the registry's scope. This is the runtime
// signal of a cross-exchange replay attempt (or a misconfigured caller).
var ErrDestinationMismatch = errors.New("did/verifier: destination mismatch")

// ErrEntryNil is returned by VerifyEntry when passed a nil entry.
var ErrEntryNil = errors.New("did/verifier: entry is nil")

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

// VerifierRegistry dispatches verification by DID method, scoped to a
// single destination exchange identity.
type VerifierRegistry struct {
	destination string
	mu          sync.RWMutex
	verifiers   map[string]SignatureVerifier
}

// NewVerifierRegistry creates an empty registry scoped to a destination DID.
// Panics if destinationDID fails envelope.ValidateDestination — a registry
// without a valid destination cannot enforce its security contract, so
// construction with a bad destination is a programming error, not a
// runtime condition to recover from.
func NewVerifierRegistry(destinationDID string) *VerifierRegistry {
	if err := envelope.ValidateDestination(destinationDID); err != nil {
		panic(fmt.Sprintf("did/verifier: invalid destination DID: %v", err))
	}
	return &VerifierRegistry{
		destination: destinationDID,
		verifiers:   make(map[string]SignatureVerifier),
	}
}

// DefaultVerifierRegistry returns a registry scoped to destinationDID and
// wired with the three built-in verifiers: pkh, key, and web. The web
// verifier requires a resolver for fetching remote DID documents.
func DefaultVerifierRegistry(destinationDID string, webResolver DIDResolver) *VerifierRegistry {
	if webResolver == nil {
		panic("did/verifier: DefaultVerifierRegistry requires a non-nil web resolver")
	}
	r := NewVerifierRegistry(destinationDID)
	r.MustRegister("pkh", NewPKHVerifier())
	r.MustRegister("key", NewKeyVerifier())
	r.MustRegister("web", NewWebVerifier(webResolver))
	return r
}

// Destination returns the DID this registry is scoped to. Diagnostic
// accessor — production code should treat this as opaque except when
// emitting audit log entries that need to record the verifier scope.
func (r *VerifierRegistry) Destination() string {
	return r.destination
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
//
// Low-level primitive: takes a canonical hash (message) and a signature,
// and asks the method-specific verifier to check them. Does NOT check
// destination binding — that is VerifyEntry's job. Callers who already
// have a canonical hash in hand (e.g., SIWE signed-request flow, test
// harnesses that forge known hashes) use this method; callers with an
// *envelope.Entry should use VerifyEntry instead.
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

// VerifyEntry verifies an *envelope.Entry end-to-end against this
// registry's destination scope. The steps are:
//
//  1. Check entry is non-nil.
//  2. Check entry.Header.Destination matches r.destination. If not, return
//     ErrDestinationMismatch — this is the cross-exchange replay defense.
//  3. Compute the canonical hash as sha256(envelope.Serialize(entry)).
//  4. Dispatch to the DID-method-specific verifier for entry.Header.SignerDID.
//
// Callers who have an entry plus its detached signature and algorithm ID
// should use this method. It is strictly preferred over the low-level
// Verify for entry-signature verification, because it enforces the
// destination-binding contract.
func (r *VerifierRegistry) VerifyEntry(entry *envelope.Entry, sig []byte, algoID uint16) error {
	if entry == nil {
		return ErrEntryNil
	}
	if entry.Header.Destination != r.destination {
		return fmt.Errorf(
			"%w: entry bound to %q, registry is scoped to %q",
			ErrDestinationMismatch,
			entry.Header.Destination,
			r.destination,
		)
	}
	// Canonical hash: sha256 over the canonical wire bytes. By construction,
	// the canonical bytes include Destination (serialize.go writes it
	// after SignerDID), so the hash the signer signed cannot be
	// reconstructed against a different destination.
	canonical := envelope.Serialize(entry)
	hash := sha256.Sum256(canonical)
	return r.Verify(entry.Header.SignerDID, hash[:], sig, algoID)
}
