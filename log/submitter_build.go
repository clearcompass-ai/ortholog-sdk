/*
Package log — submitter_build.go owns the entry-construction
pipeline (Mode A sign-once + Mode B PoW loop). All HTTP-free and
testable in isolation.
*/
package log

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Header preparation
// ─────────────────────────────────────────────────────────────────────

// prepareHeader fills in submitter-side defaults for fields the
// caller commonly leaves zero. Returns a copy — the caller's
// header is not mutated.
//
// Auto-fills:
//
//	Destination — LogDID when zero. The operator's admission step
//	              3b binds entries to the destination log; an
//	              entry with Destination != LogDID is rejected
//	              with HTTP 403.
//	SignerDID   — cfg.SignerDID when zero. Matches the primary
//	              signature's DID per envelope's primary-signer
//	              invariant (Signatures[0].SignerDID ==
//	              Header.SignerDID).
//	EventTime   — time.Now().UTC().UnixMicro() when zero. The
//	              operator's exchange/policy.CheckFreshness reads
//	              this as microseconds (NOT seconds, despite the
//	              field doc comment) — pin to the actual
//	              implementation so freshness windows accept the
//	              entry instead of stale-rejecting it as ~56 years
//	              old.
func (s *HTTPSubmitter) prepareHeader(h envelope.ControlHeader) envelope.ControlHeader {
	if h.Destination == "" {
		h.Destination = s.cfg.LogDID
	}
	if h.SignerDID == "" {
		h.SignerDID = s.cfg.SignerDID
	}
	if h.EventTime == 0 {
		h.EventTime = time.Now().UTC().UnixMicro()
	}
	return h
}

// ─────────────────────────────────────────────────────────────────────
// Sign helper (shared by Mode A and the PoW inner loop)
// ─────────────────────────────────────────────────────────────────────

// signAndSerialize signs the given unsigned entry with the
// submitter's private key and returns the canonical wire bytes
// (SigningPayload || signatures_section).
//
// Behavior:
//   - Computes signingHash := sha256(envelope.SigningPayload(entry)).
//   - Signs via signatures.SignEntry.
//   - Attaches Signatures[0] = {SignerDID, ECDSA, sig}.
//   - Calls envelope.Serialize.
//
// Note: envelope.Serialize panics on hand-constructed entries that
// fail validation; signAndSerialize never produces those because
// it routes through NewUnsignedEntry + Validate-equivalent
// invariants enforced by the envelope package.
func (s *HTTPSubmitter) signAndSerialize(entry *envelope.Entry) ([]byte, error) {
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(signingHash, s.cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("log/submitter: SignEntry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: s.cfg.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("log/submitter: entry validation: %w", err)
	}
	return envelope.Serialize(entry), nil
}

// ─────────────────────────────────────────────────────────────────────
// Mode A — sign once, no PoW
// ─────────────────────────────────────────────────────────────────────

// buildModeA produces canonical wire bytes for an authenticated
// (Bearer token) submission. No AdmissionProof is attached; the
// operator's admission step 7 skips Mode B verification when the
// request carries Authorization: Bearer.
func (s *HTTPSubmitter) buildModeA(header envelope.ControlHeader, payload []byte) ([]byte, error) {
	header = s.prepareHeader(header)
	// Mode A entries MUST NOT carry an AdmissionProof body. If the
	// caller hand-set one, drop it — Mode A is dispatched by config.
	header.AdmissionProof = nil

	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, fmt.Errorf("log/submitter: NewUnsignedEntry: %w", err)
	}
	return s.signAndSerialize(entry)
}

// ─────────────────────────────────────────────────────────────────────
// Mode B — PoW search
// ─────────────────────────────────────────────────────────────────────

// buildModeB performs the proof-of-work nonce search for an
// unauthenticated submission. The (difficulty, hashFuncName) pair
// is supplied by the caller (typically from getDifficulty); this
// function does NOT read the cache itself so callers can drive
// retry-with-fresh-difficulty cleanly.
//
// Iterates nonce in [0, PoWMaxIterations). On each iteration:
//   - If nonce%PoWCheckInterval == 0, checks ctx.Err to stay
//     interruptible under cancellation.
//   - Updates header.AdmissionProof.Nonce.
//   - Builds a fresh unsigned entry, signs it, serializes — every
//     iteration, because the post-signature canonical bytes (which
//     the entry hash covers) embed the freshly signed nonce.
//     SigningPayload itself does NOT cover the signatures section;
//     signatures are appended after signing.
//   - Computes entryHash := sha256(canonical) and runs
//     sdkadmission.VerifyStamp.
//   - On VerifyStamp success: returns the canonical bytes.
//
// Returns:
//   - ErrDifficultyOutOfRange if the operator-supplied difficulty
//     does not fit the wire byte (> math.MaxUint8). Surfaces
//     immediately, before any PoW iteration, because retrying with
//     the same difficulty would silently truncate again.
//   - ErrPoWExhausted if the loop runs PoWMaxIterations times
//     without finding a valid nonce.
//   - ctx.Err() if cancelled mid-search.
func (s *HTTPSubmitter) buildModeB(
	ctx context.Context,
	header envelope.ControlHeader,
	payload []byte,
	difficulty uint32,
	hashFuncName string,
) ([]byte, error) {
	header = s.prepareHeader(header)

	// BUG #1 guard: AdmissionProofBody.Difficulty is uint8 on the
	// wire, but the operator advertises uint32 in its difficulty JSON
	// (and difficultyMax is 256). Without this check, a uint32 → uint8
	// cast silently wraps; the resulting stamp does not satisfy the
	// operator's intended threshold and the 403-retry loop sees the
	// same wrapped value and refuses to retry. Surface a typed error
	// instead so the caller learns the operator picked an unsupported
	// difficulty.
	if difficulty > math.MaxUint8 {
		return nil, fmt.Errorf("%w: %d > %d",
			ErrDifficultyOutOfRange, difficulty, math.MaxUint8)
	}

	hashFuncWire, hashErr := hashFuncByte(hashFuncName)
	if hashErr != nil {
		return nil, hashErr
	}
	header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: uint8(difficulty),
		HashFunc:   hashFuncWire,
		Epoch:      sdkadmission.CurrentEpoch(s.cfg.EpochWindowSec),
	}

	hashFunc, hashErr2 := hashFuncTyped(hashFuncName)
	if hashErr2 != nil {
		return nil, hashErr2
	}
	currentEpoch := sdkadmission.CurrentEpoch(s.cfg.EpochWindowSec)
	checkInterval := uint64(s.cfg.PoWCheckInterval)
	if checkInterval == 0 {
		checkInterval = defaultPoWCheckInterval
	}

	for nonce := uint64(0); nonce < s.cfg.PoWMaxIterations; nonce++ {
		// Periodic ctx check — keeps the loop interruptible under
		// caller cancellation without blowing the budget on a
		// per-iteration syscall.
		if nonce%checkInterval == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		header.AdmissionProof.Nonce = nonce

		entry, err := envelope.NewUnsignedEntry(header, payload)
		if err != nil {
			return nil, fmt.Errorf("log/submitter: NewUnsignedEntry: %w", err)
		}
		canonical, err := s.signAndSerialize(entry)
		if err != nil {
			return nil, err
		}

		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(header.AdmissionProof, s.cfg.LogDID)
		if err := sdkadmission.VerifyStamp(
			apiProof,
			entryHash,
			s.cfg.LogDID,
			difficulty,
			hashFunc,
			nil, // argon2id params: SDK default
			currentEpoch,
			s.cfg.EpochAcceptanceWindow,
		); err == nil {
			return canonical, nil
		}
	}
	return nil, fmt.Errorf("%w: searched %d nonces at difficulty %d",
		ErrPoWExhausted, s.cfg.PoWMaxIterations, difficulty)
}

// ─────────────────────────────────────────────────────────────────────
// Build dispatch
// ─────────────────────────────────────────────────────────────────────

// buildOne dispatches Mode A or Mode B based on AuthToken.
// Returns the canonical wire bytes ready for POST.
//
// For Mode B, the caller supplies (difficulty, hashFunc) — usually
// pulled from getDifficulty. Cache-bust retries pass refreshed
// values from refreshDifficulty.
func (s *HTTPSubmitter) buildOne(
	ctx context.Context,
	header envelope.ControlHeader,
	payload []byte,
	difficulty uint32,
	hashFuncName string,
) ([]byte, error) {
	if s.modeIsAuthenticated() {
		return s.buildModeA(header, payload)
	}
	return s.buildModeB(ctx, header, payload, difficulty, hashFuncName)
}
