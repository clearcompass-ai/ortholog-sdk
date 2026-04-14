/*
Package verifier provides verification primitives for the Ortholog protocol.

bootstrap.go defines three methods for establishing trust in a log's
witness set — the first step before any cross-log verification.

HardcodedGenesis: compiled-in genesis set → rotation chain → verify head.
AnchorLogSync:    fetch anchor log tree head via DID → verify → accept.
TrustOnFirstUse:  accept first head seen, pin it (no cryptographic proof).
*/
package verifier

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var ErrBootstrapFailed = errors.New("verifier/bootstrap: trust establishment failed")
var ErrHeadVerificationFailed = errors.New("verifier/bootstrap: tree head verification failed")
var ErrEmptyHead = errors.New("verifier/bootstrap: empty tree head")

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// BootstrapMethod identifies how trust was established.
type BootstrapMethod int

const (
	MethodHardcodedGenesis BootstrapMethod = iota + 1
	MethodAnchorLogSync
	MethodTrustOnFirstUse
)

// BootstrapResult is the outcome of trust establishment.
type BootstrapResult struct {
	Method          BootstrapMethod
	WitnessKeys     []types.WitnessPublicKey
	QuorumK         int
	VerifiedHead    types.CosignedTreeHead
	EstablishedAt   time.Time
	TrustAnchorHash [32]byte // Hash of the trust anchor (genesis set, anchor head, or TOFU head).
}

// ─────────────────────────────────────────────────────────────────────
// HardcodedGenesis
// ─────────────────────────────────────────────────────────────────────

// HardcodedGenesis establishes trust from a compiled-in genesis witness set.
//
// Steps:
//  1. Walk rotation chain from genesis → current set (witness.VerifyRotationChain)
//  2. Verify latest tree head against the current set (witness.VerifyTreeHead)
//  3. Return the verified head and current witness set
//
// This is the strongest bootstrap method — the genesis set is embedded
// in the binary. An attacker cannot substitute it without replacing
// the binary itself.
func HardcodedGenesis(
	genesisSet []types.WitnessPublicKey,
	rotations []types.WitnessRotation,
	quorumK int,
	latestHead types.CosignedTreeHead,
	blsVerifier signatures.BLSVerifier,
) (*BootstrapResult, error) {
	if len(genesisSet) == 0 {
		return nil, fmt.Errorf("%w: empty genesis set", ErrBootstrapFailed)
	}

	// Walk rotation chain to derive current set.
	currentSet, err := witness.VerifyRotationChain(genesisSet, rotations, quorumK, blsVerifier)
	if err != nil {
		return nil, fmt.Errorf("%w: rotation chain: %v", ErrBootstrapFailed, err)
	}

	// Verify latest head against current set.
	_, err = witness.VerifyTreeHead(latestHead, currentSet, quorumK, blsVerifier)
	if err != nil {
		return nil, fmt.Errorf("%w: head verification: %v", ErrHeadVerificationFailed, err)
	}

	genesisHash := witness.ComputeSetHash(genesisSet)

	return &BootstrapResult{
		Method:          MethodHardcodedGenesis,
		WitnessKeys:     currentSet,
		QuorumK:         quorumK,
		VerifiedHead:    latestHead,
		EstablishedAt:   time.Now().UTC(),
		TrustAnchorHash: genesisHash,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// AnchorLogSync
// ─────────────────────────────────────────────────────────────────────

// AnchorLogSync establishes trust by fetching and verifying the tree head
// from a trusted anchor log. The anchor log's witness keys and quorum
// must be provided (typically from a prior HardcodedGenesis bootstrap
// of the anchor log itself).
//
// Used when a new domain log trusts an existing anchor log's witness
// infrastructure. The anchor log's tree head serves as the trust root.
func AnchorLogSync(
	anchorLogDID string,
	client *witness.TreeHeadClient,
	anchorWitnessKeys []types.WitnessPublicKey,
	anchorQuorumK int,
	blsVerifier signatures.BLSVerifier,
) (*BootstrapResult, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil tree head client", ErrBootstrapFailed)
	}
	if len(anchorWitnessKeys) == 0 {
		return nil, fmt.Errorf("%w: empty anchor witness keys", ErrBootstrapFailed)
	}

	// Fetch anchor log's latest tree head.
	head, _, err := client.FetchLatestTreeHead(anchorLogDID)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch anchor head: %v", ErrBootstrapFailed, err)
	}

	// Verify the anchor head.
	_, err = witness.VerifyTreeHead(head, anchorWitnessKeys, anchorQuorumK, blsVerifier)
	if err != nil {
		return nil, fmt.Errorf("%w: anchor head verification: %v", ErrHeadVerificationFailed, err)
	}

	anchorHash := TreeHeadHash(head.TreeHead)

	return &BootstrapResult{
		Method:          MethodAnchorLogSync,
		WitnessKeys:     anchorWitnessKeys,
		QuorumK:         anchorQuorumK,
		VerifiedHead:    head,
		EstablishedAt:   time.Now().UTC(),
		TrustAnchorHash: anchorHash,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// TrustOnFirstUse (TOFU)
// ─────────────────────────────────────────────────────────────────────

// TrustOnFirstUse accepts the first tree head seen without cryptographic
// verification. The head is pinned — subsequent updates must be consistent
// with it (append-only: tree size only grows, root must extend prior tree).
//
// This is the weakest bootstrap method. Suitable for development,
// testing, and scenarios where the first contact is assumed secure
// (e.g., initial onboarding over a trusted channel).
func TrustOnFirstUse(
	head types.CosignedTreeHead,
	fetchedAt time.Time,
) (*BootstrapResult, error) {
	if head.TreeSize == 0 && head.RootHash == [32]byte{} {
		return nil, ErrEmptyHead
	}

	tofuHash := TreeHeadHash(head.TreeHead)

	return &BootstrapResult{
		Method:          MethodTrustOnFirstUse,
		WitnessKeys:     nil, // No witness verification for TOFU.
		QuorumK:         0,
		VerifiedHead:    head,
		EstablishedAt:   fetchedAt,
		TrustAnchorHash: tofuHash,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// TreeHeadHash computes a deterministic hash of a TreeHead.
// Used as the trust anchor reference in BootstrapResult and CrossLogProof.
func TreeHeadHash(head types.TreeHead) [32]byte {
	msg := types.WitnessCosignMessage(head)
	return sha256.Sum256(msg[:])
}
