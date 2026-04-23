// Package escrow — vss_v2.go wires the core/vss Pedersen primitive
// into the escrow wire format. Public API for Phase D consumers:
//
//   - SplitV2 produces cryptographically-verifiable shares + a
//     published commitment set + a deterministic SplitID.
//   - ReconstructV2 verifies every share against the commitments
//     before Lagrange interpolation; a substituted share fails
//     loudly instead of producing a silently-wrong secret.
//   - VerifyShareAgainstCommitments lets any party (escrow node at
//     distribution time, recovery client at reconstruction time,
//     auditor after the fact) gate on Pedersen consistency.
//
// Phase D consumers:
//
//   - exchange/identity/mapping_escrow.go StoreMapping / LookupMapping
//   - lifecycle/provision.go ProvisionSingleLog
//   - lifecycle/recovery.go ExecuteRecovery
//
// Phase B ships the primitive; Phase D wires it into lifecycle paths.
// Nothing inside the SDK routes through SplitV2 until Phase D.
//
// Honest-dealer assumption: SplitV2 is called by SDK-controlled
// processes (provisioning, key rotation, grant emission). A malicious
// dealer that publishes commitments inconsistent with distributed
// shares can cause reconstruction to fail — not to produce a wrong
// secret — but the equivocation itself is cryptographic evidence
// under the dealer's signature, handled at the lifecycle / witness
// layer per ADR-005 §7.4.
package escrow

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// EscrowSplitDST is the domain separation tag that prefixes every
// escrow SplitID computation, per ADR-005 §6.1. Changing this
// string invalidates every escrow SplitID ever produced and requires
// a protocol version bump — not a routine change.
const EscrowSplitDST = "ORTHOLOG-V7.75-ESCROW-SPLIT"

// ComputeEscrowSplitID derives the escrow SplitID for a given
// dealer DID and nonce, per ADR-005 §6.1:
//
//	SplitID = SHA-256(
//	    "ORTHOLOG-V7.75-ESCROW-SPLIT"   (27 bytes ASCII)
//	    || BE_uint16(len(dealerDID))    (2 bytes)
//	    || dealerDID                    (caller-normalised UTF-8)
//	    || nonce                        (32 bytes)
//	)
//
// Exposed as a public helper so Phase D builders can compute SplitID
// without re-implementing the derivation. Tests and auditors also
// use it to reproduce fixtures.
//
// NFC normalisation of dealerDID is the CALLER's responsibility.
// Phase B does not force normalisation (would pull in golang.org/x/text
// for a property SDK-produced DIDs already satisfy). Production
// callers that accept DIDs from external input MUST normalise before
// calling; ADR-005 §6.5 documents the discipline.
func ComputeEscrowSplitID(dealerDID string, nonce [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(EscrowSplitDST))
	var didLen [2]byte
	binary.BigEndian.PutUint16(didLen[:], uint16(len(dealerDID)))
	h.Write(didLen[:])
	h.Write([]byte(dealerDID))
	h.Write(nonce[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SplitV2 produces N Pedersen-verifiable shares of a 32-byte secret
// with threshold M. Returns shares, the commitment set callers MUST
// publish on-log before share distribution (Phase D invariant), and
// the deterministic SplitID.
//
// Constraints:
//
//   - len(secret) == 32.
//   - 2 ≤ M ≤ N ≤ 255.
//   - dealerDID non-empty.
//   - nonce MUST be fresh random bytes; callers SHOULD use crypto/rand
//     (Phase D wires this into provisioning).
//
// The secret is reduced mod n (secp256k1 group order) as a scalar;
// zero secrets are rejected at the vss primitive layer (ADR-005 §3.2
// rationale — application-layer concern, not cryptographic).
//
// SplitV2 uses crypto/rand for polynomial coefficient sampling.
// Tests that need deterministic output call splitV2WithReader with
// a seeded DRBG; that path is unexported to keep production flows
// on the CSPRNG.
func SplitV2(
	secret []byte,
	M, N int,
	dealerDID string,
	nonce [32]byte,
) ([]Share, vss.Commitments, [32]byte, error) {
	return splitV2WithReader(secret, M, N, dealerDID, nonce, nil)
}

// splitV2WithReader is SplitV2 parameterised on the randomness source.
// nil reader means "use crypto/rand via the vss.Split default path".
// Any non-nil reader is passed through to the primitive; tests supply
// a deterministic DRBG for byte-reproducible fixtures.
func splitV2WithReader(
	secret []byte,
	M, N int,
	dealerDID string,
	nonce [32]byte,
	r io.Reader,
) ([]Share, vss.Commitments, [32]byte, error) {
	var zeroID [32]byte

	// Structural gates — cheap failures before any curve math.
	if len(secret) != SecretSize {
		return nil, vss.Commitments{}, zeroID, fmt.Errorf(
			"escrow/split_v2: secret must be %d bytes, got %d",
			SecretSize, len(secret),
		)
	}
	if dealerDID == "" {
		return nil, vss.Commitments{}, zeroID, errors.New("escrow/split_v2: dealerDID must be non-empty")
	}
	if M < 2 {
		return nil, vss.Commitments{}, zeroID, fmt.Errorf("%w: M=%d, minimum is 2", ErrInvalidThreshold, M)
	}
	if N < M {
		return nil, vss.Commitments{}, zeroID, fmt.Errorf("%w: N=%d < M=%d", ErrInvalidThreshold, N, M)
	}
	if N > 255 {
		return nil, vss.Commitments{}, zeroID, fmt.Errorf("%w: N=%d exceeds 255", ErrInvalidThreshold, N)
	}

	// SplitID: deterministic from (dealerDID, nonce). Distinct
	// nonces from the same dealer yield distinct SplitIDs, which is
	// the mechanism for legitimate re-splitting of the same secret
	// (e.g., delegation-key rotation).
	splitID := ComputeEscrowSplitID(dealerDID, nonce)

	// Polynomial generation + commitments via the core primitive.
	var secretArr [vss.SecretSize]byte
	copy(secretArr[:], secret)

	var (
		coreShares []vss.Share
		commits    vss.Commitments
		err        error
	)
	if r == nil {
		coreShares, commits, err = vss.Split(secretArr, M, N)
	} else {
		coreShares, commits, err = vss.SplitWithReader(secretArr, M, N, r)
	}
	if err != nil {
		return nil, vss.Commitments{}, zeroID, fmt.Errorf("escrow/split_v2: %w", err)
	}

	// Wrap each primitive Share in the escrow wire-level Share,
	// stamping Version, Threshold, SplitID, and FieldTag.
	shares := make([]Share, len(coreShares))
	for i, cs := range coreShares {
		shares[i] = Share{
			Version:        VersionV2,
			Threshold:      byte(M),
			Index:          cs.Index,
			Value:          cs.Value,
			BlindingFactor: cs.BlindingFactor,
			CommitmentHash: cs.CommitmentHash,
			SplitID:        splitID,
			FieldTag:       SchemePedersenTag,
		}
	}
	return shares, commits, splitID, nil
}

// ReconstructV2 recovers the original 32-byte secret from M or more
// V2 shares, gated on Pedersen verification against the supplied
// commitment set. Substituted shares, cross-split shares, shares
// with mangled blinding factors — all produce a typed error rather
// than a silently-wrong secret. This is the load-bearing property
// that V2 provides and V1 does not.
//
// Preconditions:
//
//   - commitments was published by the dealer on-log (Phase D
//     consumer responsibility to fetch before calling).
//   - all shares are V2; mixed V1/V2 is rejected.
//   - all shares share the same SplitID and CommitmentHash.
//   - len(shares) ≥ threshold implied by commitments.
//
// The returned secret is a freshly-allocated 32-byte slice. Callers
// SHOULD ZeroBytes it after use.
func ReconstructV2(shares []Share, commitments vss.Commitments) ([]byte, error) {
	if len(shares) == 0 {
		return nil, ErrEmptyShareSet
	}
	if commitments.Threshold() == 0 {
		return nil, fmt.Errorf("escrow/reconstruct_v2: empty commitment set")
	}

	// Structural consistency across the set. VerifyShareSet handles
	// per-share ValidateShareFormat, SplitID agreement, duplicate
	// indices, and threshold count. Version-mismatch (V1 mixed with
	// V2) surfaces here as ErrVersionMismatch.
	if err := VerifyShareSet(shares); err != nil {
		return nil, fmt.Errorf("escrow/reconstruct_v2: %w", err)
	}
	if shares[0].Version != VersionV2 {
		return nil, fmt.Errorf(
			"%w: ReconstructV2 called with version 0x%02x set",
			ErrUnsupportedVersion, shares[0].Version,
		)
	}

	// Per-share cryptographic verification. This is the step that
	// transforms a Shamir-only "might produce wrong secret silently"
	// into a Pedersen "must produce right secret or loud error".
	// Every share is checked; the first failure aborts with an
	// index-tagged error so operators can attribute.
	//
	// We skip the structural ValidateShareFormat call here because
	// VerifyShareSet (above) already ran it on every share. The
	// crypto-only path verifyShareCryptoOnly does just the Pedersen
	// equation check + commitment-hash match.
	for i, s := range shares {
		if err := verifyShareCryptoOnly(s, commitments); err != nil {
			return nil, fmt.Errorf(
				"escrow/reconstruct_v2: share at slot %d (index %d): %w",
				i, s.Index, err,
			)
		}
	}

	// All shares verified. Hand off to the primitive for Lagrange.
	coreShares := make([]vss.Share, len(shares))
	for i, s := range shares {
		coreShares[i] = vss.Share{
			Index:          s.Index,
			Value:          s.Value,
			BlindingFactor: s.BlindingFactor,
			CommitmentHash: s.CommitmentHash,
		}
	}
	secretArr, err := vss.Reconstruct(coreShares, commitments)
	if err != nil {
		return nil, fmt.Errorf("escrow/reconstruct_v2: %w", err)
	}
	out := make([]byte, SecretSize)
	copy(out, secretArr[:])
	return out, nil
}

// VerifyShareAgainstCommitments checks one V2 share against the
// published commitment set. Returns nil iff the share is a valid
// Pedersen-VSS share of the secret the commitments commit to.
//
// Callable at distribution time: when an escrow node receives a
// share, it MAY (SHOULD, in Phase D production deployments) call
// this function against the commitment entry fetched from the log
// before acknowledging receipt. Rejected shares attribute dealer
// malice or in-flight tampering immediately.
//
// Callable at reconstruction time: ReconstructV2 gates on this for
// every share before Lagrange.
//
// Callable at audit time: any party with the share and the
// on-log commitment entry can re-verify after the fact. No
// interactive protocol; no additional data beyond what is already
// on-log and in the share itself.
//
// Returns one of:
//
//   - nil on success.
//   - ErrUnsupportedVersion if the share is not V2.
//   - An ErrV2FieldEmpty / ErrSplitIDMissing wrapping from
//     ValidateShareFormat on structural failure.
//   - ErrCommitmentMismatch on CommitmentHash mismatch OR
//     polynomial-consistency failure. Wraps the core/vss layer's
//     sentinels (vss.ErrCommitmentHashMismatch,
//     vss.ErrCommitmentMismatch) so callers matching on either
//     succeed.
func VerifyShareAgainstCommitments(s Share, commitments vss.Commitments) error {
	if s.Version != VersionV2 {
		return fmt.Errorf(
			"%w: VerifyShareAgainstCommitments requires V2, got 0x%02x",
			ErrUnsupportedVersion, s.Version,
		)
	}
	if err := ValidateShareFormat(s); err != nil {
		return err
	}
	return verifyShareCryptoOnly(s, commitments)
}

// verifyShareCryptoOnly runs ONLY the cryptographic check —
// CommitmentHash match + Pedersen polynomial-consistency equation.
// The caller is responsible for ensuring the share has already been
// structurally validated (Version, Index, SplitID, non-zero V2
// fields). This is the function ReconstructV2 uses after
// VerifyShareSet to avoid running ValidateShareFormat twice per
// share.
//
// Public callers should use VerifyShareAgainstCommitments instead;
// this internal entry point exists only to skip redundant work
// inside the package's own pipeline.
func verifyShareCryptoOnly(s Share, commitments vss.Commitments) error {
	if commitments.Threshold() == 0 {
		return fmt.Errorf("escrow/verify_share: empty commitment set")
	}
	// Delegate the actual Pedersen check to the primitive. The
	// primitive already performs CommitmentHash match, on-curve
	// point validation, and the f(i)·G + r(i)·H == Σ i^j·C_j equation.
	coreShare := vss.Share{
		Index:          s.Index,
		Value:          s.Value,
		BlindingFactor: s.BlindingFactor,
		CommitmentHash: s.CommitmentHash,
	}
	if err := vss.Verify(coreShare, commitments); err != nil {
		return fmt.Errorf("%w: index %d: %w", ErrCommitmentMismatch, s.Index, err)
	}
	return nil
}

// VerifyShareAgainstCommitmentHash is a fast pre-check that a share's
// CommitmentHash matches the expected hash derived from a commitment
// set, without running the full polynomial-consistency check. Useful
// as an early filter at distribution time when a node has the hash
// cached but not yet the full commitment set.
//
// Returns nil iff share.Version == V2 AND share.CommitmentHash ==
// commitments.Hash(). A V1 share fails the version gate immediately
// (its CommitmentHash is always zero by V1 contract — comparing zero
// against a real hash would also fail, but failing on version first
// gives a clearer error and prevents accidental V1-via-zero-hash
// confusion).
//
// Does NOT imply the share is a valid Pedersen share — callers MUST
// follow up with VerifyShareAgainstCommitments for the cryptographic
// check.
func VerifyShareAgainstCommitmentHash(s Share, commitments vss.Commitments) error {
	if s.Version != VersionV2 {
		return fmt.Errorf(
			"%w: VerifyShareAgainstCommitmentHash requires V2, got 0x%02x",
			ErrUnsupportedVersion, s.Version,
		)
	}
	expected := commitments.Hash()
	if s.CommitmentHash != expected {
		return fmt.Errorf(
			"%w: share index %d commitment-hash mismatch",
			ErrCommitmentMismatch, s.Index,
		)
	}
	return nil
}
