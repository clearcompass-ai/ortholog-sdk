/*
FILE PATH:
    did/key_resolver.go

DESCRIPTION:
    did:key method resolver. Parses did:key:z<multibase-base58btc> identifiers,
    dispatches on the multicodec prefix to determine the key type, and returns
    a synthesized DIDDocument with the appropriate verification method.

KEY ARCHITECTURAL DECISIONS:
    - Strict W3C did-method-key spec compliance. Only multibase 'z' (base58btc)
      prefix is accepted. Other multibase encodings — including the legacy
      non-standard 'f' (hex) format — are rejected.
    - Three multicodec prefixes are recognized:
        0xed 0x01   Ed25519 public key       (32 bytes follow)
        0xe7 0x01   secp256k1 compressed key (33 bytes follow)
        0x12 0x00   P-256 compressed key     (33 bytes follow)
      These cover every curve used by Ortholog signers:
          secp256k1 for Ethereum wallets and KMS
          Ed25519   for Solana, NEAR, Cosmos
          P-256     for WebAuthn passkeys
    - Multicodec prefix is encoded as unsigned varint per the spec. We parse
      with a minimal inline decoder rather than pulling a full multicodec
      library for 2 bytes of work.
    - The resolver returns a DIDDocument with exactly one VerificationMethod
      whose Type string matches the W3C DID Core Vocabulary term for the
      curve. This Type is what downstream verifiers consult to choose
      the correct primitive.

OVERVIEW:
    Parse flow:
        1. Strip "did:key:" prefix
        2. Reject unless first character is 'z'
        3. base58btc-decode the remainder
        4. Varint-decode the multicodec prefix (2 bytes for all supported
           curves — 0xed01, 0xe701, 0x1200)
        5. Remaining bytes are the raw public key for that curve
        6. Synthesize DIDDocument with one VerificationMethod

    Example:
        did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrua8PsbV1mvrt9rs3x
            -> z strips multibase
            -> decoded starts with 0xed 0x01 (Ed25519)
            -> followed by 32 bytes of Ed25519 public key

KEY DEPENDENCIES:
    - github.com/mr-tron/base58: base58btc encoding/decoding
    - did/resolver.go: DIDDocument, VerificationMethod types
*/
package did

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// -------------------------------------------------------------------------------------------------
// 1) Multicodec prefix constants
// -------------------------------------------------------------------------------------------------

// Multicodec prefixes for did:key public key types, per the multicodec table:
//   https://github.com/multiformats/multicodec/blob/master/table.csv
//
// Each prefix is an unsigned varint. For the codes we use, the varint encoding
// is exactly 2 bytes, as recorded below.
var (
	// MulticodecEd25519 is the prefix 0xed followed by 0x01 (continuation bit
	// set on the low byte of varint code 0xed, then the high byte 0x01).
	MulticodecEd25519 = [2]byte{0xed, 0x01}

	// MulticodecSecp256k1 is the prefix for compressed secp256k1 public keys.
	MulticodecSecp256k1 = [2]byte{0xe7, 0x01}

	// MulticodecP256 is the prefix for compressed P-256 public keys.
	MulticodecP256 = [2]byte{0x12, 0x00}
)

// -------------------------------------------------------------------------------------------------
// 2) Verification method type strings
// -------------------------------------------------------------------------------------------------

// W3C DID Core / DID Specification Registries verification method types.
// Used to label VerificationMethod.Type in synthesized DID documents.
const (
	VerificationMethodEd25519   = "Ed25519VerificationKey2020"
	VerificationMethodSecp256k1 = "EcdsaSecp256k1VerificationKey2019"
	VerificationMethodP256      = "EcdsaSecp256r1VerificationKey2019"

	// EcdsaSecp256k1RecoveryMethod2020 is the verification method type used
	// for did:pkh — signature verification via ecrecover + address compare
	// rather than pubkey compare.
	VerificationMethodSecp256k1Recovery = "EcdsaSecp256k1RecoveryMethod2020"
)

// -------------------------------------------------------------------------------------------------
// 3) Errors
// -------------------------------------------------------------------------------------------------

// ErrInvalidDIDKey is returned when a did:key identifier cannot be parsed.
var ErrInvalidDIDKey = errors.New("did/key: invalid did:key identifier")

// ErrUnsupportedMulticodec is returned when a did:key identifier uses a
// multicodec prefix not in the set we support.
var ErrUnsupportedMulticodec = errors.New("did/key: unsupported multicodec prefix")

// -------------------------------------------------------------------------------------------------
// 4) KeyResolver
// -------------------------------------------------------------------------------------------------

// KeyResolver resolves did:key identifiers by parsing the multibase-encoded
// key material directly from the identifier. No network IO. No state.
type KeyResolver struct{}

// NewKeyResolver returns a new did:key resolver.
func NewKeyResolver() *KeyResolver {
	return &KeyResolver{}
}

// Resolve parses a did:key identifier and returns a synthesized DIDDocument
// with one VerificationMethod corresponding to the key type.
func (r *KeyResolver) Resolve(didStr string) (*DIDDocument, error) {
	pubKey, vmType, err := ParseDIDKey(didStr)
	if err != nil {
		return nil, err
	}

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: didStr,
		VerificationMethod: []VerificationMethod{
			{
				ID:           didStr + "#" + strings.TrimPrefix(didStr, "did:key:"),
				Type:         vmType,
				Controller:   didStr,
				PublicKeyHex: hex.EncodeToString(pubKey),
			},
		},
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 5) ParseDIDKey
// -------------------------------------------------------------------------------------------------

// ParseDIDKey decomposes a did:key identifier into its raw public key bytes
// and the matching W3C verification method type string.
//
// Returns ErrInvalidDIDKey for structurally malformed identifiers, and
// ErrUnsupportedMulticodec for identifiers whose multicodec prefix is not in
// the supported set.
func ParseDIDKey(didStr string) (pubKey []byte, verificationMethodType string, err error) {
	const prefix = "did:key:"
	if !strings.HasPrefix(didStr, prefix) {
		return nil, "", fmt.Errorf("%w: missing %q prefix", ErrInvalidDIDKey, prefix)
	}

	identifier := strings.TrimPrefix(didStr, prefix)
	if len(identifier) < 2 {
		return nil, "", fmt.Errorf("%w: identifier too short", ErrInvalidDIDKey)
	}
	if identifier[0] != 'z' {
		return nil, "", fmt.Errorf(
			"%w: only multibase 'z' (base58btc) is supported, got %q",
			ErrInvalidDIDKey, identifier[0])
	}

	decoded, err := base58.Decode(identifier[1:])
	if err != nil {
		return nil, "", fmt.Errorf("%w: base58 decode: %v", ErrInvalidDIDKey, err)
	}
	if len(decoded) < 2 {
		return nil, "", fmt.Errorf("%w: decoded bytes too short", ErrInvalidDIDKey)
	}

	prefix2 := [2]byte{decoded[0], decoded[1]}
	rest := decoded[2:]

	switch prefix2 {
	case MulticodecEd25519:
		if len(rest) != 32 {
			return nil, "", fmt.Errorf(
				"%w: Ed25519 key must be 32 bytes, got %d",
				ErrInvalidDIDKey, len(rest))
		}
		return rest, VerificationMethodEd25519, nil

	case MulticodecSecp256k1:
		if len(rest) != 33 {
			return nil, "", fmt.Errorf(
				"%w: secp256k1 compressed key must be 33 bytes, got %d",
				ErrInvalidDIDKey, len(rest))
		}
		return rest, VerificationMethodSecp256k1, nil

	case MulticodecP256:
		if len(rest) != 33 {
			return nil, "", fmt.Errorf(
				"%w: P-256 compressed key must be 33 bytes, got %d",
				ErrInvalidDIDKey, len(rest))
		}
		return rest, VerificationMethodP256, nil

	default:
		return nil, "", fmt.Errorf(
			"%w: 0x%02x%02x",
			ErrUnsupportedMulticodec, prefix2[0], prefix2[1])
	}
}

// -------------------------------------------------------------------------------------------------
// 6) EncodeDIDKey (used by did/creation.go)
// -------------------------------------------------------------------------------------------------

// EncodeDIDKey composes a did:key identifier from a multicodec prefix and
// raw public key bytes.
func EncodeDIDKey(multicodec [2]byte, pubKey []byte) string {
	payload := make([]byte, 0, 2+len(pubKey))
	payload = append(payload, multicodec[0], multicodec[1])
	payload = append(payload, pubKey...)
	return "did:key:z" + base58.Encode(payload)
}
