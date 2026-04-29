/*
Package sct defines the SDK-side SignedCertificateTimestamp (SCT)
type, canonical signing payload, and verification function.

Background:

	The SCT is the operator's binding promise on admission: signed
	with the operator's secp256k1 ECDSA identity key, it commits the
	operator to sequence (LogDID, canonical_hash) into the Merkle
	tree within Maximum Merge Delay. RFC-6962-style domain separation
	binds the signature to this protocol version; tampering with any
	field of the signed-over set invalidates the signature.

Where the pieces live:

	The operator (which holds the private key) retains SignSCT in
	ortholog-operator/api/sct.go. Everything verifier-side — the
	type definition, the byte packer, and Verify — lives here so
	consumers (submit clients, audit jobs, witness cosigners) and
	the operator's own VerifySCT all produce byte-identical signing
	payloads. Without this single source of truth, the consumer's
	hand-rolled byte packing would drift from the operator's, the
	SHA-256 would diverge, and every SCT would silently fail to
	verify.

Wire shape (length-prefixed, version-tagged, big-endian):

	domain_sep        16 bytes  "ORTHOLOG_SCT_V1\x00"
	version           1  byte   uint8
	signerDID_len     2  bytes  uint16 BE
	signerDID_bytes   N  bytes  N <= 65535
	sigAlgoID_len     2  bytes  uint16 BE
	sigAlgoID_bytes   N  bytes  N <= 65535
	logDID_len        2  bytes  uint16 BE
	logDID_bytes      N  bytes  N <= 65535
	canonical_hash    32 bytes
	log_time_micros   8  bytes  uint64 BE  (signed-over)

Total: 65 + len(signerDID) + len(sigAlgoID) + len(logDID) bytes.

Verify-side rules:

	LogTimeMicros is the signed-over timestamp; LogTime (RFC-3339)
	is a derived rendering verified for exact equality before any
	signature math runs. Sub-microsecond producer drift is therefore
	rejected at parse time and never reaches VerifyEntry.

Domain-separation rationale:

	The 16-byte domain separator prevents cross-protocol signature
	confusion: a forger cannot replay an SCT signature as any other
	signed Ortholog blob. The trailing NUL byte makes the prefix
	non-mistakable for any UTF-8 ASCII string in human or grep
	contexts.
*/
package sct

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// Version is the wire-format version of the SCT signing payload.
// Bumping this is a breaking change for every consumer; the version
// byte at the front of the signing payload makes future formats
// dispatchable.
const Version uint8 = 1

const (
	// DomainSep is the 16-byte cross-protocol domain separator.
	// The trailing NUL byte makes the prefix unambiguous in any
	// ASCII or UTF-8 text context.
	DomainSep = "ORTHOLOG_SCT_V1\x00"

	// SigAlgoECDSASecp256k1SHA256 is the only signature algorithm
	// the v1 SCT format supports.
	SigAlgoECDSASecp256k1SHA256 = "ecdsa-secp256k1-sha256"
)

// MaxFieldLen caps the length of length-prefixed string fields
// (signer_did, sig_algo_id, log_did). Equal to math.MaxUint16; held
// as an int constant so callers can range-check without arithmetic.
const MaxFieldLen = 0xFFFF

// SignedCertificateTimestamp is the JSON shape returned by the
// operator's POST /v1/entries on successful admission. Consumers
// verify the signature against the operator's public key (reachable
// via cfg.OperatorDID) before treating the SCT as a binding promise.
//
// LogTimeMicros is signed-over. LogTime is a derived RFC-3339Nano
// rendering for human consumption only — never trust it for
// signature reconstruction. Verify rebuilds LogTime from
// LogTimeMicros and rejects any drift.
type SignedCertificateTimestamp struct {
	Version       uint8  `json:"version"`
	SignerDID     string `json:"signer_did"`
	SigAlgoID     string `json:"sig_algo_id"`
	LogDID        string `json:"log_did"`
	CanonicalHash string `json:"canonical_hash"`
	LogTimeMicros int64  `json:"log_time_micros"`
	LogTime       string `json:"log_time"`
	Signature     string `json:"signature"`
}

// Errors surfaced by SigningPayload and Verify.
var (
	ErrSignerDIDTooLong = errors.New("sct: signerDID exceeds 65535 bytes")
	ErrSigAlgoTooLong   = errors.New("sct: sigAlgoID exceeds 65535 bytes")
	ErrLogDIDTooLong    = errors.New("sct: logDID exceeds 65535 bytes")
	ErrNilPubKey        = errors.New("sct: Verify requires non-nil pub")
	ErrNilSCT           = errors.New("sct: Verify requires non-nil sct")
	ErrUnsupportedVer   = errors.New("sct: unsupported version")
	ErrMissingSignerDID = errors.New("sct: missing signer_did")
	ErrUnsupportedAlgo  = errors.New("sct: unsupported sig_algo_id")
	ErrLogTimeMismatch  = errors.New("sct: log_time mismatch")
	ErrBadCanonicalHash = errors.New("sct: canonical_hash decode")
	ErrBadHashLength    = errors.New("sct: canonical_hash length != 32")
	ErrBadSignature     = errors.New("sct: signature decode")
)

// SigningPayload builds the deterministic byte sequence that the SCT
// signature is computed over. The operator builds it during SignSCT;
// the consumer rebuilds it during Verify; the two MUST match
// byte-for-byte.
//
// Returns ErrSignerDIDTooLong / ErrSigAlgoTooLong / ErrLogDIDTooLong
// when any length-prefixed field exceeds the 65535-byte uint16 cap.
// All field-length checks happen before any byte is appended so a
// caller never observes a partial buffer on error.
func SigningPayload(
	signerDID string,
	sigAlgoID string,
	logDID string,
	canonicalHash [32]byte,
	logTimeMicros int64,
) ([]byte, error) {
	if len(signerDID) > MaxFieldLen {
		return nil, fmt.Errorf("%w: length %d", ErrSignerDIDTooLong, len(signerDID))
	}
	if len(sigAlgoID) > MaxFieldLen {
		return nil, fmt.Errorf("%w: length %d", ErrSigAlgoTooLong, len(sigAlgoID))
	}
	if len(logDID) > MaxFieldLen {
		return nil, fmt.Errorf("%w: length %d", ErrLogDIDTooLong, len(logDID))
	}

	total := len(DomainSep) + 1 + 2 + len(signerDID) + 2 + len(sigAlgoID) + 2 + len(logDID) + 32 + 8
	buf := make([]byte, 0, total)
	buf = append(buf, DomainSep...)
	buf = append(buf, Version)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(signerDID)))
	buf = append(buf, signerDID...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sigAlgoID)))
	buf = append(buf, sigAlgoID...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(logDID)))
	buf = append(buf, logDID...)
	buf = append(buf, canonicalHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(logTimeMicros))
	return buf, nil
}

// Verify recomputes the canonical signing payload from the SCT's
// fields and verifies the signature against pub. Returns nil on
// success or a wrapped error sentinel.
//
// Tampering with any of (Version, SignerDID, SigAlgoID, LogDID,
// CanonicalHash, LogTimeMicros) invalidates the signature. LogTime
// (the human-readable rendering) is not part of the signed payload —
// consumers MUST rebuild it from LogTimeMicros, and Verify rejects
// any submitted SCT whose LogTime field does not match the exact
// time.UnixMicro(LogTimeMicros).UTC().Format(time.RFC3339Nano)
// rendering. This rule is load-bearing: if Verify ignored LogTime,
// a consumer that read LogTime instead of LogTimeMicros to display
// admission time would silently render times the signature did not
// commit to.
func Verify(pub *ecdsa.PublicKey, s *SignedCertificateTimestamp) error {
	if pub == nil {
		return ErrNilPubKey
	}
	if s == nil {
		return ErrNilSCT
	}
	if s.Version != Version {
		return fmt.Errorf("%w: got %d want %d", ErrUnsupportedVer, s.Version, Version)
	}
	if s.SignerDID == "" {
		return ErrMissingSignerDID
	}
	if s.SigAlgoID != SigAlgoECDSASecp256k1SHA256 {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgo, s.SigAlgoID)
	}
	expectedLogTime := time.UnixMicro(s.LogTimeMicros).UTC().Format(time.RFC3339Nano)
	if s.LogTime != expectedLogTime {
		return fmt.Errorf("%w: got %q want %q", ErrLogTimeMismatch, s.LogTime, expectedLogTime)
	}
	hashBytes, err := hex.DecodeString(s.CanonicalHash)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadCanonicalHash, err)
	}
	if len(hashBytes) != 32 {
		return fmt.Errorf("%w: got %d", ErrBadHashLength, len(hashBytes))
	}
	var canonicalHash [32]byte
	copy(canonicalHash[:], hashBytes)

	sigBytes, err := hex.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	payload, err := SigningPayload(s.SignerDID, s.SigAlgoID, s.LogDID, canonicalHash, s.LogTimeMicros)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if err := signatures.VerifyEntry(digest, sigBytes, pub); err != nil {
		return fmt.Errorf("sct: VerifyEntry: %w", err)
	}
	return nil
}
