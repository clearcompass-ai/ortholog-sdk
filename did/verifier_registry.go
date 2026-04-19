/*
FILE PATH:
    did/verifier_registry.go

DESCRIPTION:
    Registry of DID-method-specific signature verifiers. The single
    dispatch point for (did, hash, sig, algoID) → verifier lookup →
    cryptographic verification.

KEY ARCHITECTURAL DECISIONS:
    - The registry pattern is the extension point for new DID methods.
      Adding did:polygonid / did:ethr / did:iden3 is:
        registry.MustRegister("polygonid", NewPolygonIDVerifier(...))
      No core code changes. No switch statements. No wire format edits.
    - Under v6 VerifyEntry has been restructured. v5's signature was
      VerifyEntry(entry, sig, algoID) — the caller passed sig and algoID
      as separate arguments because sigs lived outside the entry.
      v6 signatures live inside entry.Signatures, so VerifyEntry now
      takes only the entry and iterates its signature list.
    - The per-algorithm Verify dispatch (registry.Verify) is unchanged
      at v6 — it still takes (did, hash, sig, algoID) and routes by
      DID method. VerifyEntry is the caller-facing wrapper that hashes
      the SigningPayload and calls Verify for each signature.
    - Primary-signer invariant (Signatures[0].SignerDID ==
      Header.SignerDID) is enforced by envelope.Deserialize and
      envelope.Entry.Validate, not by this registry. Callers building
      entries by hand must call entry.Validate() before VerifyEntry.

OVERVIEW:
    Two public methods:

      Register / MustRegister — register a verifier for a DID method
        (no path prefix; e.g., "pkh", "key", "web", "polygonid").

      Verify(did, hash, sig, algoID) — dispatch one signature to its
        method-specific verifier. Used by VerifyEntry internally and
        directly by exchange/auth/signed_request.go for HTTP request
        authentication.

      VerifyEntry(entry) — verify every signature on an entry against
        its signing-payload hash. Returns nil iff every signature is
        valid; returns the first failure wrapped with context.

    The method-specific verifiers (PKHVerifier, KeyVerifier, WebVerifier)
    satisfy the SignatureVerifier interface:

      Verify(did string, message []byte, sig []byte, algoID uint16) error

    Adding a new DID method is implementing that interface and calling
    registry.Register or MustRegister.

KEY DEPENDENCIES:
    - crypto/sha256 (standard library)
    - core/envelope: SigningPayload, Entry (VerifyEntry hashes and reads)
    - method_router.go: ExtractMethod (parse DID method from DID string)
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
// 1) SignatureVerifier interface
// -------------------------------------------------------------------------------------------------

// SignatureVerifier is the contract every DID-method verifier satisfies.
// Implementations include PKHVerifier (did:pkh), KeyVerifier (did:key),
// WebVerifier (did:web), and any operator-registered verifier for
// additional methods.
//
// Verify returns nil on cryptographic success. On failure it returns a
// descriptive error; callers do NOT unwrap or switch on the error type.
// Any non-nil return is "this signature is not valid for this DID" and
// the entry MUST be rejected.
type SignatureVerifier interface {
	Verify(did string, message []byte, sig []byte, algoID uint16) error
}

// -------------------------------------------------------------------------------------------------
// 2) Registry errors
// -------------------------------------------------------------------------------------------------

var (
	// ErrMethodNotRegistered is returned by Verify when the DID's method
	// (e.g., "pkh" in "did:pkh:...") has no registered verifier.
	ErrMethodNotRegistered = errors.New("did: DID method has no registered verifier")

	// ErrDuplicateRegistration is returned by Register when the method
	// is already registered. MustRegister panics on this.
	ErrDuplicateRegistration = errors.New("did: DID method already registered")

	// ErrAlgorithmNotSupported is returned by individual verifiers when
	// the requested algoID is not supported for the given DID method
	// (e.g., asking did:pkh to verify an Ed25519 signature).
	ErrAlgorithmNotSupported = errors.New("did: algorithm not supported for DID method")
)

// -------------------------------------------------------------------------------------------------
// 3) VerifierRegistry
// -------------------------------------------------------------------------------------------------

// VerifierRegistry holds the mapping from DID method name to
// SignatureVerifier. Thread-safe for concurrent Verify calls after all
// registrations are complete; Register/MustRegister are write operations
// that must complete during startup before Verify is called.
type VerifierRegistry struct {
	mu        sync.RWMutex
	verifiers map[string]SignatureVerifier
}

// NewVerifierRegistry constructs an empty registry. Callers register
// verifiers via Register/MustRegister before the first Verify call.
func NewVerifierRegistry() *VerifierRegistry {
	return &VerifierRegistry{
		verifiers: make(map[string]SignatureVerifier),
	}
}

// Register installs a verifier for the given DID method. The method
// string is the name without the "did:" prefix (e.g., "pkh", "key",
// "web", "polygonid"). Returns ErrDuplicateRegistration if the method
// is already registered.
//
// Intended to be called once per method at process startup. The
// registry is not designed for dynamic re-registration.
func (r *VerifierRegistry) Register(method string, v SignatureVerifier) error {
	if method == "" {
		return errors.New("did: Register requires non-empty method name")
	}
	if v == nil {
		return errors.New("did: Register requires non-nil verifier")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.verifiers[method]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateRegistration, method)
	}
	r.verifiers[method] = v
	return nil
}

// MustRegister is Register's panic-on-error form. Used in startup
// wiring code where a registration failure is a programming error and
// should crash the process.
func (r *VerifierRegistry) MustRegister(method string, v SignatureVerifier) {
	if err := r.Register(method, v); err != nil {
		panic(fmt.Sprintf("did: MustRegister(%q): %v", method, err))
	}
}

// RegisteredMethods returns the list of currently registered DID method
// names. Order is not guaranteed. Intended for diagnostics and tests.
func (r *VerifierRegistry) RegisteredMethods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.verifiers))
	for m := range r.verifiers {
		out = append(out, m)
	}
	return out
}

// -------------------------------------------------------------------------------------------------
// 4) Verify — per-signature dispatch
// -------------------------------------------------------------------------------------------------

// Verify dispatches one signature to its DID-method-specific verifier.
//
// Extracts the method from the DID string (e.g., "pkh" from
// "did:pkh:eip155:1:0x..."), looks up the registered verifier, and
// invokes its Verify method with the given hash, sig, and algoID.
//
// Returns nil on cryptographic success. Returns ErrMethodNotRegistered
// if the DID method is unknown. Returns the underlying verifier's error
// on cryptographic failure.
//
// This is the direct entry point used by
// exchange/auth/signed_request.go for HTTP request authentication
// (where the "message" is the signed-request envelope hash, not an
// entry signing payload). Entry-level verification goes through
// VerifyEntry, which calls Verify once per sig.
func (r *VerifierRegistry) Verify(did string, message []byte, sig []byte, algoID uint16) error {
	method, err := ExtractMethod(did)
	if err != nil {
		return fmt.Errorf("did: %w", err)
	}

	r.mu.RLock()
	v, ok := r.verifiers[method]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("%w: %q", ErrMethodNotRegistered, method)
	}
	return v.Verify(did, message, sig, algoID)
}

// -------------------------------------------------------------------------------------------------
// 5) VerifyEntry — entry-level multi-sig verification
// -------------------------------------------------------------------------------------------------

// VerifyEntry verifies every signature on a v6 entry against its
// signing-payload hash. Returns nil iff every signature is valid;
// returns the first failure wrapped with signature index, signer DID,
// and algoID.
//
// Flow:
//  1. Reject nil entry or zero-signature entry.
//  2. Compute hash := sha256(envelope.SigningPayload(entry)).
//  3. For each sig in entry.Signatures:
//       r.Verify(sig.SignerDID, hash[:], sig.Bytes, sig.AlgoID)
//  4. Return nil if every call succeeded.
//
// Note: the primary-signer invariant (Signatures[0].SignerDID ==
// Header.SignerDID) is enforced by envelope.Deserialize and
// envelope.Entry.Validate. VerifyEntry does NOT re-check this invariant
// because every code path that produces an entry (Deserialize,
// NewEntry, Validate-after-NewUnsignedEntry) already enforces it.
// Callers constructing entries by hand and bypassing validation are
// responsible for their own state integrity.
//
// Under v6 this replaces v5's VerifyEntry(entry, sig, algoID) signature.
// The v5 signature assumed a single external sig; v6 entries carry
// their signatures internally, so the caller no longer passes them
// separately.
func (r *VerifierRegistry) VerifyEntry(entry *envelope.Entry) error {
	if entry == nil {
		return errors.New("did: VerifyEntry requires non-nil entry")
	}
	if len(entry.Signatures) == 0 {
		return errors.New("did: VerifyEntry: entry has no signatures")
	}

	hash := sha256.Sum256(envelope.SigningPayload(entry))

	for i, sig := range entry.Signatures {
		if err := r.Verify(sig.SignerDID, hash[:], sig.Bytes, sig.AlgoID); err != nil {
			return fmt.Errorf("did: VerifyEntry: signature[%d] did=%q algo=0x%04x: %w",
				i, sig.SignerDID, sig.AlgoID, err)
		}
	}
	return nil
}
