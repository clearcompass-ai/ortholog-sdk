/*
FILE PATH:
    did/method_router.go

DESCRIPTION:
    Method router: parses a DID string to extract its method, then dispatches
    to the registered DIDResolver for that method. This is the composition
    root for multi-method DID resolution.

KEY ARCHITECTURAL DECISIONS:
    - Registration is explicit and fail-loud. Re-registering a method returns
      an error rather than silently overwriting. Callers must unregister first
      if they want to replace.
    - Resolution of an unregistered method returns ErrDIDMethodNotSupported,
      wrapped with the method name for diagnostic clarity.
    - ExtractMethod is exported because the signature verifier registry
      performs the same parse independently. Avoiding duplication.
    - The router itself satisfies the DIDResolver interface, so it can be
      composed (wrapped with CachingResolver, for example).
    - Thread-safe: guards the resolver map with a RWMutex so registration
      at startup and resolution at steady-state don't race. Registration is
      expected to be infrequent (wiring time); resolution is hot-path.

OVERVIEW:
    Typical wiring in a deployment bootstrap:
        router := did.NewMethodRouter()
        router.MustRegister("web", did.NewWebDIDResolver(nil))
        router.MustRegister("key", did.NewKeyResolver())
        router.MustRegister("pkh", did.NewPKHResolver())

        cached := did.NewCachingResolver(router, 5*time.Minute)

    Consumers that accept a DIDResolver interface work with the router
    unchanged — it's just another resolver.

KEY DEPENDENCIES:
    - did/resolver.go: DIDResolver interface, DIDDocument, error constants
*/
package did

import (
	"fmt"
	"strings"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrInvalidDIDFormat is returned when a DID string cannot be parsed.
var ErrInvalidDIDFormat = fmt.Errorf("did/router: invalid DID format")

// ErrMethodAlreadyRegistered is returned by Register when the method already
// has a resolver.
var ErrMethodAlreadyRegistered = fmt.Errorf("did/router: method already registered")

// -------------------------------------------------------------------------------------------------
// 2) ExtractMethod
// -------------------------------------------------------------------------------------------------

// ExtractMethod returns the method name from a DID string.
//
//	"did:web:example.com"         -> "web"
//	"did:pkh:eip155:1:0xABC..."   -> "pkh"
//	"did:key:z6Mk..."             -> "key"
//
// Returns ErrInvalidDIDFormat if the input does not start with "did:" or
// does not contain a method segment.
func ExtractMethod(did string) (string, error) {
	if !strings.HasPrefix(did, "did:") {
		return "", fmt.Errorf("%w: missing 'did:' prefix in %q", ErrInvalidDIDFormat, did)
	}
	rest := did[4:]
	colonIdx := strings.IndexByte(rest, ':')
	if colonIdx <= 0 {
		return "", fmt.Errorf("%w: missing method in %q", ErrInvalidDIDFormat, did)
	}
	return rest[:colonIdx], nil
}

// -------------------------------------------------------------------------------------------------
// 3) MethodRouter
// -------------------------------------------------------------------------------------------------

// MethodRouter dispatches DID resolution by DID method to registered
// per-method resolvers.
type MethodRouter struct {
	mu        sync.RWMutex
	resolvers map[string]DIDResolver
}

// NewMethodRouter creates an empty router. Callers must register resolvers
// before resolving any DIDs.
func NewMethodRouter() *MethodRouter {
	return &MethodRouter{resolvers: make(map[string]DIDResolver)}
}

// Register installs a resolver for the given method. Returns
// ErrMethodAlreadyRegistered if a resolver is already registered for the
// method; caller must explicitly Unregister first.
func (r *MethodRouter) Register(method string, resolver DIDResolver) error {
	if method == "" {
		return fmt.Errorf("did/router: cannot register empty method")
	}
	if resolver == nil {
		return fmt.Errorf("did/router: cannot register nil resolver for method %q", method)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.resolvers[method]; exists {
		return fmt.Errorf("%w: %q", ErrMethodAlreadyRegistered, method)
	}
	r.resolvers[method] = resolver
	return nil
}

// MustRegister panics if registration fails. Intended for deployment wiring
// where registration errors are programmer bugs, not runtime conditions.
func (r *MethodRouter) MustRegister(method string, resolver DIDResolver) {
	if err := r.Register(method, resolver); err != nil {
		panic(err)
	}
}

// Unregister removes the resolver for the given method, returning true if
// a resolver was removed and false if no resolver was registered.
func (r *MethodRouter) Unregister(method string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.resolvers[method]
	delete(r.resolvers, method)
	return existed
}

// Methods returns the set of registered DID methods, sorted alphabetically
// for stable iteration. Useful for diagnostics and configuration dumps.
func (r *MethodRouter) Methods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.resolvers))
	for m := range r.resolvers {
		out = append(out, m)
	}
	// sort.Strings would pull a dependency only needed here; do a simple
	// insertion sort since registered methods are typically <10.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Resolve extracts the method from the DID and dispatches to the registered
// resolver for that method. Returns ErrDIDMethodNotSupported if no resolver
// is registered.
func (r *MethodRouter) Resolve(didStr string) (*DIDDocument, error) {
	method, err := ExtractMethod(didStr)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	resolver, ok := r.resolvers[method]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: method %q not registered", ErrDIDMethodNotSupported, method)
	}
	return resolver.Resolve(didStr)
}
