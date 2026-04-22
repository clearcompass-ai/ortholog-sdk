/*
Package types — escrow_package.go defines the persistable envelope that
wraps a holder's escrowed secret for M-of-N cooperative recovery.

# Architectural role

EscrowPackage is the data structure written to content-addressed
storage at escrow setup time and fetched back at recovery time. It
is the transport and rest form of an M-of-N Shamir escrow.

Lifecycle:

	Setup    → domain app generates the holder's Master Identity Key,
	           Shamir-splits it into N shares, ECIES-wraps each share
	           for one escrow node's public key, and assembles an
	           EscrowPackage. The package is serialized, stored
	           content-addressed, and referenced by its CID in the
	           InitiateRecovery request entry.

	Recovery → escrow nodes fetch the package, each one decrypts its
	           own share via its private key, and returns the plaintext
	           V1 Share struct to the recovery orchestrator. The
	           orchestrator calls escrow.Reconstruct to recover the
	           original Master Identity Key.

# What this struct holds

The escrow scheme operates exclusively on 32-byte identity secrets —
typically the holder's Master Identity Key. NEVER artifact-encryption
keys, NEVER artifact-encryption nonces. Under V1 this is enforced
cryptographically by the escrow package (SecretSize = 32); under V2
(reserved) it remains true by protocol.

Artifact concerns (re-encryption, key rotation, nonce management) are
strictly domain-layer responsibilities that sit OUTSIDE this package.
See lifecycle/recovery.go for the scope boundary and
lifecycle/artifact_access.go (ReEncryptWithGrant) for the domain-side
artifact rotation primitive.

# Scheme-agnosticism

The Version byte identifies which cryptographic scheme produced the
shares. EscrowPackage is a forward-compatible container: a V2 package
looks structurally identical to a V1 package, differing only in the
Version byte and in the interpretation of the underlying share wire
format (which is itself fixed at 131 bytes across V1 and V2).

A decoder that reads an EscrowPackage with an unsupported Version
value MUST reject it rather than silently process it as the last
version it understands. Version is NOT a feature negotiation field —
it's a binding commitment to the cryptographic scheme used.

# Consumers

  - Domain applications: construct and serialize EscrowPackage at
    escrow setup; deserialize and use it at recovery time.
  - crypto/escrow package: reads the Version byte to select the
    correct reconstruction routine.
  - lifecycle/recovery.go: references EscrowPackage by CID (does not
    parse it directly — parsing is domain-layer work).

# Serialization

EscrowPackage does not define its own wire format in this file.
Callers serialize it using whatever canonical encoding the domain
requires (JSON, CBOR, Protobuf, etc.). Before serialization, callers
MUST call Canonicalize() to ensure deterministic ordering — the
resulting CID must be reproducible across marshalers.
*/
package types

import (
	"errors"
	"fmt"
	"sort"
)

// ─────────────────────────────────────────────────────────────────────
// Scheme version constants
//
// These values MUST match crypto/escrow.VersionV1 and
// crypto/escrow.VersionV2 respectively. Duplication is accepted to
// avoid a circular import (crypto/escrow imports types, not the other
// way around). When the crypto/escrow constants change, update these
// in lockstep.
// ─────────────────────────────────────────────────────────────────────

const (
	// EscrowSchemeV1 identifies version 1 of the escrow scheme:
	// GF(256) Shamir secret sharing with SplitID binding and
	// threshold enforcement. Produces 131-byte shares via the wire
	// format defined in crypto/escrow/share_format.go. Does not
	// provide cryptographic share verification — use V2 when
	// malicious-node resistance is required.
	EscrowSchemeV1 byte = 0x01

	// EscrowSchemeV2 identifies version 2 of the escrow scheme:
	// Pedersen Verifiable Secret Sharing over secp256k1. Provides
	// per-share cryptographic verification against published
	// commitments. Shares use the same 131-byte wire format as V1
	// but populate BlindingFactor and CommitmentHash. Reserved;
	// implementation ships with V2 escrow package release.
	EscrowSchemeV2 byte = 0x02
)

// ─────────────────────────────────────────────────────────────────────
// Validation constants
// ─────────────────────────────────────────────────────────────────────

const (
	// MinEscrowThreshold is the minimum value of M (quorum size).
	// M=1 is rejected because a 1-of-N split gives any single share
	// holder full recovery authority, defeating the purpose of
	// threshold escrow. An attacker who compromises any single node
	// can reconstruct the secret — no better than storing the secret
	// on that node directly.
	MinEscrowThreshold = 2

	// MinEscrowNodes is the minimum value of N (total share count).
	// N must be at least M. When M = MinEscrowThreshold (2), N must
	// also be at least 2.
	MinEscrowNodes = 2

	// MaxEscrowNodes is the maximum value of N. Shares are indexed
	// by a single byte in the wire format (Share.Index), and index
	// 0 is reserved for the secret itself, leaving 1..255 available
	// for share positions.
	MaxEscrowNodes = 255
)

// ─────────────────────────────────────────────────────────────────────
// Sentinel errors
//
// Validate returns these for errors.Is dispatching by callers (e.g.
// HTTP handlers mapping validation failures to 400 responses).
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrEscrowEmptyHolderDID is returned when HolderDID is empty.
	// Every package must be attributable to a specific identity —
	// without it, recovery has no subject.
	ErrEscrowEmptyHolderDID = errors.New("types/escrow_package: empty HolderDID")

	// ErrEscrowInvalidThreshold is returned when M is out of range.
	// See MinEscrowThreshold.
	ErrEscrowInvalidThreshold = errors.New("types/escrow_package: invalid threshold M")

	// ErrEscrowInvalidNodeCount is returned when N is out of range
	// or when N < M. See MinEscrowNodes and MaxEscrowNodes.
	ErrEscrowInvalidNodeCount = errors.New("types/escrow_package: invalid node count N")

	// ErrEscrowUnknownVersion is returned when Version is neither
	// EscrowSchemeV1 nor EscrowSchemeV2.
	ErrEscrowUnknownVersion = errors.New("types/escrow_package: unknown scheme version")

	// ErrEscrowShareCountMismatch is returned when
	// len(EncryptedShares) != N.
	ErrEscrowShareCountMismatch = errors.New("types/escrow_package: share count does not match N")

	// ErrEscrowEmptyNodeDID is returned when an EncryptedShare has
	// an empty EscrowNodeDID. Each share must be attributable to
	// the node that can decrypt it.
	ErrEscrowEmptyNodeDID = errors.New("types/escrow_package: empty EscrowNodeDID")

	// ErrEscrowEmptyBlob is returned when an EncryptedShare has
	// an empty EncryptedBlob. An empty ciphertext cannot decrypt
	// to anything recoverable.
	ErrEscrowEmptyBlob = errors.New("types/escrow_package: empty EncryptedBlob")

	// ErrEscrowDuplicateNodeDID is returned when two shares are
	// addressed to the same escrow node. Each node holds exactly
	// one share — duplicates indicate either a construction bug
	// (accidentally wrapping the same plaintext twice) or an
	// attempt to bias recovery toward a compromised node.
	ErrEscrowDuplicateNodeDID = errors.New("types/escrow_package: duplicate EscrowNodeDID")
)

// ─────────────────────────────────────────────────────────────────────
// EscrowPackage
// ─────────────────────────────────────────────────────────────────────

// EscrowPackage is the persistable M-of-N escrow envelope for a
// single holder's identity secret.
//
// # Invariants
//
// A well-formed EscrowPackage satisfies:
//
//   - HolderDID is non-empty
//   - M >= MinEscrowThreshold (2)
//   - N >= M and N in [MinEscrowNodes, MaxEscrowNodes]
//   - Version in {EscrowSchemeV1, EscrowSchemeV2}
//   - len(EncryptedShares) == N
//   - Every EncryptedShare has non-empty EscrowNodeDID and
//     non-empty EncryptedBlob
//   - No two EncryptedShares share the same EscrowNodeDID
//
// Call Validate to check all invariants. Call Canonicalize to establish
// deterministic ordering before serialization.
//
// # Secret contents (what EncryptedBlob wraps)
//
// Each EncryptedBlob is an ECIES ciphertext produced by
// crypto/escrow.EncryptShareForNode. The ciphertext wraps a single
// 131-byte V1 (or V2) Share struct — not the raw secret. The raw
// secret is reconstructed only after M nodes each decrypt their
// individual shares and the shares are passed to escrow.Reconstruct.
//
// No part of the plaintext secret is recoverable from this struct
// alone. An attacker who obtains the EscrowPackage bytes still needs
// the private keys of at least M escrow nodes.
//
// # The Version field is a binding commitment
//
// Version identifies the cryptographic scheme that produced the
// shares contained in EncryptedBlob. It is NOT a hint and NOT a
// feature negotiation field. A decoder reading this struct MUST route
// reconstruction through the scheme identified by Version and MUST
// reject unknown values.
type EscrowPackage struct {
	// HolderDID is the DID of the identity whose Master Identity Key
	// is escrowed in this package. Required.
	HolderDID string

	// M is the threshold — the minimum number of shares required to
	// reconstruct the secret. Must be >= MinEscrowThreshold.
	M int

	// N is the total number of shares produced. Must be >= M and
	// within [MinEscrowNodes, MaxEscrowNodes]. len(EncryptedShares)
	// must equal N.
	N int

	// Version identifies the cryptographic scheme. Must be
	// EscrowSchemeV1 or EscrowSchemeV2. See the Version section in
	// the struct doc for binding semantics.
	//
	// Renamed from FieldTag in V1. FieldTag was pre-V1 terminology
	// that mixed scheme identification with share wire-format tags.
	// The V1 design separates these concerns: Version identifies
	// the scheme; share-internal tags live inside the share wire
	// format (see crypto/escrow/share_format.go).
	Version byte

	// EncryptedShares carries the N per-node ECIES ciphertexts.
	// Each ciphertext wraps a single Share struct encrypted for one
	// escrow node's public key. Order is canonicalized by sorting
	// on EscrowNodeDID (see Canonicalize). Must contain exactly N
	// entries with no duplicate EscrowNodeDIDs.
	EncryptedShares []EncryptedShare

	// ArtifactKeyCIDs is OPTIONAL domain-layer metadata. The SDK
	// does NOT interpret this field; it is a convenience slot for
	// the domain application to record which artifact CIDs are
	// associated with this escrow (e.g., "these are the artifacts
	// the holder will want to re-encrypt after recovery").
	//
	// Including CIDs here does not cause ExecuteRecovery to touch
	// those artifacts — artifact re-encryption is orchestrated by
	// the domain layer separately, typically via repeated calls to
	// lifecycle.ReEncryptWithGrant.
	//
	// Sorted lexicographically by Canonicalize for deterministic
	// serialization.
	ArtifactKeyCIDs []string
}

// ─────────────────────────────────────────────────────────────────────
// EncryptedShare
// ─────────────────────────────────────────────────────────────────────

// EncryptedShare is one ECIES-wrapped Shamir share addressed to a
// specific escrow node.
//
// # Contents
//
// EncryptedBlob is the output of crypto/escrow.EncryptShareForNode,
// which:
//
//  1. Serializes a Share struct to its 131-byte wire form
//  2. Generates a fresh ephemeral ECIES keypair
//  3. Derives an AES-256-GCM key from ECDH(ephemeral_priv, node_pub)
//  4. Encrypts the share wire bytes with AES-256-GCM
//  5. Returns ephemeral_pub || nonce || ciphertext || tag (224 bytes for V1)
//
// Only the escrow node holding the private key corresponding to
// EscrowNodeDID can decrypt this blob.
//
// # Why separate from the share itself
//
// The plaintext Share struct has a fixed 131-byte wire format shared
// across V1 and V2. The ECIES wrapping is a separate layer that makes
// the share transportable to a specific node without the escrow
// package leaking share plaintexts at rest.
type EncryptedShare struct {
	// EscrowNodeDID identifies the escrow node authorized to
	// decrypt this blob. The node's public key is resolved from
	// this DID at encryption time and at recovery time via DID
	// resolution.
	EscrowNodeDID string

	// EncryptedBlob is the ECIES ciphertext wrapping one Share.
	// For V1 shares the length is fixed at 224 bytes (65-byte
	// ephemeral pubkey + 12-byte GCM nonce + 131-byte ciphertext +
	// 16-byte GCM tag). Validate enforces non-empty but does not
	// check the exact length to keep the types package decoupled
	// from crypto/escrow's ECIES internals.
	EncryptedBlob []byte
}

// ─────────────────────────────────────────────────────────────────────
// Methods
// ─────────────────────────────────────────────────────────────────────

// Validate checks all EscrowPackage invariants and returns a wrapped
// sentinel error identifying the first failure. Returns nil for a
// well-formed package.
//
// Callers should call Validate immediately after constructing or
// deserializing an EscrowPackage and before doing anything else with
// it. A malformed package passed to crypto/escrow functions would
// surface as a more confusing cryptographic error far downstream.
func (p *EscrowPackage) Validate() error {
	if p == nil {
		return errors.New("types/escrow_package: nil EscrowPackage")
	}

	if p.HolderDID == "" {
		return ErrEscrowEmptyHolderDID
	}

	if p.M < MinEscrowThreshold {
		return fmt.Errorf("%w: M=%d, minimum is %d",
			ErrEscrowInvalidThreshold, p.M, MinEscrowThreshold)
	}

	if p.N < MinEscrowNodes || p.N > MaxEscrowNodes {
		return fmt.Errorf("%w: N=%d, valid range [%d, %d]",
			ErrEscrowInvalidNodeCount, p.N, MinEscrowNodes, MaxEscrowNodes)
	}
	if p.N < p.M {
		return fmt.Errorf("%w: N=%d must be >= M=%d",
			ErrEscrowInvalidNodeCount, p.N, p.M)
	}

	switch p.Version {
	case EscrowSchemeV1, EscrowSchemeV2:
		// known version
	default:
		return fmt.Errorf("%w: got 0x%02x (valid: 0x%02x, 0x%02x)",
			ErrEscrowUnknownVersion, p.Version, EscrowSchemeV1, EscrowSchemeV2)
	}

	if len(p.EncryptedShares) != p.N {
		return fmt.Errorf("%w: have %d shares, N=%d",
			ErrEscrowShareCountMismatch, len(p.EncryptedShares), p.N)
	}

	// Per-share validation + duplicate detection in a single pass.
	seen := make(map[string]bool, p.N)
	for i, share := range p.EncryptedShares {
		if share.EscrowNodeDID == "" {
			return fmt.Errorf("%w: share index %d",
				ErrEscrowEmptyNodeDID, i)
		}
		if len(share.EncryptedBlob) == 0 {
			return fmt.Errorf("%w: share index %d for node %s",
				ErrEscrowEmptyBlob, i, share.EscrowNodeDID)
		}
		if seen[share.EscrowNodeDID] {
			return fmt.Errorf("%w: node %s appears more than once",
				ErrEscrowDuplicateNodeDID, share.EscrowNodeDID)
		}
		seen[share.EscrowNodeDID] = true
	}

	return nil
}

// Canonicalize establishes deterministic ordering for EncryptedShares
// and ArtifactKeyCIDs. Idempotent — safe to call multiple times.
//
// Callers MUST call Canonicalize before serializing an EscrowPackage
// to a content-addressed store. Without canonicalization, two
// EscrowPackages with identical cryptographic content would hash to
// different CIDs depending on the order Go's map iteration or the
// caller's share-assembly loop produced — breaking content-addressed
// fetch and dedup.
//
// The sort keys are the DIDs/CIDs themselves, which are opaque
// strings to this package but stable identifiers at the domain layer.
func (p *EscrowPackage) Canonicalize() {
	if p == nil {
		return
	}
	sort.Slice(p.EncryptedShares, func(i, j int) bool {
		return p.EncryptedShares[i].EscrowNodeDID < p.EncryptedShares[j].EscrowNodeDID
	})
	sort.Strings(p.ArtifactKeyCIDs)
}

// SortShares is a backward-compatible alias for Canonicalize limited
// to the EncryptedShares slice. New code should call Canonicalize,
// which additionally orders ArtifactKeyCIDs.
//
// Retained so existing callers continue to compile. May be marked
// Deprecated in a future release once all known callers migrate.
func (p *EscrowPackage) SortShares() {
	if p == nil {
		return
	}
	sort.Slice(p.EncryptedShares, func(i, j int) bool {
		return p.EncryptedShares[i].EscrowNodeDID < p.EncryptedShares[j].EscrowNodeDID
	})
}

// FindShareForNode returns the EncryptedShare addressed to the given
// escrow node DID, or nil if no such share exists. Returns a pointer
// into p.EncryptedShares (not a copy) — callers MUST NOT mutate the
// returned share.
//
// Runs in O(N) — acceptable because N is bounded by MaxEscrowNodes
// (255). If callers need repeated lookups against a single package,
// they should build their own map once rather than calling this in
// a loop.
func (p *EscrowPackage) FindShareForNode(nodeDID string) *EncryptedShare {
	if p == nil || nodeDID == "" {
		return nil
	}
	for i := range p.EncryptedShares {
		if p.EncryptedShares[i].EscrowNodeDID == nodeDID {
			return &p.EncryptedShares[i]
		}
	}
	return nil
}

// NodeDIDs returns the set of escrow-node DIDs referenced by this
// package, in canonicalized (sorted) order. Allocates a fresh slice
// on each call. Empty result if p is nil or has no shares.
//
// Useful for building an escrow-node set passed to
// lifecycle.ArbitrationParams.EscrowNodeSet during override
// evaluation.
func (p *EscrowPackage) NodeDIDs() []string {
	if p == nil || len(p.EncryptedShares) == 0 {
		return nil
	}
	out := make([]string, len(p.EncryptedShares))
	for i, s := range p.EncryptedShares {
		out[i] = s.EscrowNodeDID
	}
	sort.Strings(out)
	return out
}
