/*
FILE PATH:
    did/pkh.go

DESCRIPTION:
    did:pkh method resolver. Parses did:pkh identifiers in CAIP-10 format and
    synthesizes a DIDDocument whose verification method carries the embedded
    blockchain account address.

KEY ARCHITECTURAL DECISIONS:
    - Strict CAIP-10 format: did:pkh:<namespace>:<reference>:<account_address>
      e.g., did:pkh:eip155:1:0xAbCdEf0123456789abcdef0123456789abcdef01
    - Namespace support is extensible but ships with only 'eip155' (EVM chains)
      because that is what Ortholog actually verifies signatures for today.
      Adding Solana (solana), Cosmos (cosmos), Bitcoin (bip122) requires new
      signature verifiers, so the resolver rejects unsupported namespaces
      loudly rather than returning a document that can't be verified against.
    - No network IO. No RPC. The address IS the identity — resolution is pure
      parsing plus synthesis.
    - EIP-55 checksum is NOT enforced on parse. Mixed-case hex addresses are
      treated case-insensitively, but the canonical address returned in the
      DIDDocument is always lowercased. Verifier comparisons are byte-equal
      on the 20-byte binary form, so case does not affect verification.
    - The synthesized verification method type is
      EcdsaSecp256k1RecoveryMethod2020 — the W3C-registered type for
      signatures verified via ecrecover + address compare rather than pubkey
      compare. This is the correct type string for did:pkh on EVM chains.

OVERVIEW:
    Typical identifier and its decomposition:
        did:pkh:eip155:1:0xAbCdEf0123456789abcdef0123456789abcdef01
              namespace=eip155   reference=1 (mainnet)   address=0xAbCd...

    The resolver returns a DIDDocument with a single VerificationMethod
    whose blockchainAccountId is the full CAIP-10 account identifier and
    whose publicKeyHex is the 20-byte address. The signature verifier reads
    blockchainAccountId to determine the address to compare against.

KEY DEPENDENCIES:
    - did/resolver.go: DIDDocument, VerificationMethod, Service types
*/
package did

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// NamespaceEIP155 is the CAIP-2 namespace for EVM-compatible chains.
const NamespaceEIP155 = "eip155"

// pkhPrefix is the full method prefix for did:pkh identifiers.
const pkhPrefix = "did:pkh:"

// ethereumAddressHexLen is the length of an Ethereum address hex string
// without the "0x" prefix (20 bytes = 40 hex characters).
const ethereumAddressHexLen = 40

// -------------------------------------------------------------------------------------------------
// 2) Errors
// -------------------------------------------------------------------------------------------------

// ErrInvalidDIDPKH is returned when a did:pkh identifier cannot be parsed.
var ErrInvalidDIDPKH = errors.New("did/pkh: invalid did:pkh identifier")

// ErrUnsupportedNamespace is returned when the CAIP-2 namespace is not one
// this SDK can verify signatures for.
var ErrUnsupportedNamespace = errors.New("did/pkh: unsupported CAIP-2 namespace")

// -------------------------------------------------------------------------------------------------
// 3) Parsed representation
// -------------------------------------------------------------------------------------------------

// PKHIdentifier is the parsed form of a did:pkh identifier.
type PKHIdentifier struct {
	// Namespace is the CAIP-2 namespace (e.g., "eip155" for EVM chains).
	Namespace string

	// Reference is the chain reference within the namespace (e.g., "1" for
	// Ethereum mainnet, "137" for Polygon, "10" for Optimism).
	Reference string

	// AddressHex is the account address as lowercase hex without "0x".
	// For eip155 this is 40 hex characters (20 bytes).
	AddressHex string

	// AddressBytes is the decoded 20-byte binary address for eip155, or
	// empty for other namespaces.
	AddressBytes []byte

	// FullDID is the original DID string.
	FullDID string

	// CAIPAccountID is the account identifier portion of CAIP-10, which is
	// "<namespace>:<reference>:<address>". This is what populates
	// VerificationMethod.BlockchainAccountId in the DID document.
	CAIPAccountID string
}

// -------------------------------------------------------------------------------------------------
// 4) PKHResolver
// -------------------------------------------------------------------------------------------------

// PKHResolver resolves did:pkh identifiers by pure parsing. It performs no
// network IO. The address is the identity.
type PKHResolver struct {
	// supportedNamespaces limits which CAIP-2 namespaces this resolver will
	// synthesize documents for. Defaults to {"eip155"} if nil.
	supportedNamespaces map[string]struct{}
}

// NewPKHResolver returns a did:pkh resolver accepting only the eip155
// namespace. Use NewPKHResolverWithNamespaces to register additional.
func NewPKHResolver() *PKHResolver {
	return &PKHResolver{
		supportedNamespaces: map[string]struct{}{
			NamespaceEIP155: {},
		},
	}
}

// NewPKHResolverWithNamespaces returns a did:pkh resolver that accepts the
// given CAIP-2 namespaces. At least one namespace must be provided.
func NewPKHResolverWithNamespaces(namespaces ...string) (*PKHResolver, error) {
	if len(namespaces) == 0 {
		return nil, fmt.Errorf("did/pkh: at least one namespace required")
	}
	set := make(map[string]struct{}, len(namespaces))
	for _, ns := range namespaces {
		if ns == "" {
			return nil, fmt.Errorf("did/pkh: namespace cannot be empty")
		}
		set[ns] = struct{}{}
	}
	return &PKHResolver{supportedNamespaces: set}, nil
}

// Resolve parses a did:pkh identifier and returns a synthesized DIDDocument.
func (r *PKHResolver) Resolve(didStr string) (*DIDDocument, error) {
	parsed, err := ParseDIDPKH(didStr)
	if err != nil {
		return nil, err
	}
	if _, ok := r.supportedNamespaces[parsed.Namespace]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedNamespace, parsed.Namespace)
	}

	vm := VerificationMethod{
		ID:                   didStr + "#blockchainAccountId",
		Type:                 VerificationMethodSecp256k1Recovery,
		Controller:           didStr,
		BlockchainAccountID:  parsed.CAIPAccountID,
		PublicKeyHex:         parsed.AddressHex,
	}

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/secp256k1recovery-2020/v2",
		},
		ID:                 didStr,
		VerificationMethod: []VerificationMethod{vm},
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 5) ParseDIDPKH
// -------------------------------------------------------------------------------------------------

// ParseDIDPKH decomposes a did:pkh identifier without enforcing which
// namespaces the local resolver supports. Returns ErrInvalidDIDPKH on
// structural errors; the caller decides whether to accept the namespace.
func ParseDIDPKH(didStr string) (*PKHIdentifier, error) {
	if !strings.HasPrefix(didStr, pkhPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrInvalidDIDPKH, pkhPrefix)
	}

	body := strings.TrimPrefix(didStr, pkhPrefix)
	parts := strings.Split(body, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf(
			"%w: expected <namespace>:<reference>:<address>, got %d segments",
			ErrInvalidDIDPKH, len(parts))
	}

	namespace := parts[0]
	reference := parts[1]
	address := parts[2]

	if namespace == "" || reference == "" || address == "" {
		return nil, fmt.Errorf("%w: empty segment", ErrInvalidDIDPKH)
	}

	parsed := &PKHIdentifier{
		Namespace:     namespace,
		Reference:     reference,
		FullDID:       didStr,
		CAIPAccountID: body,
	}

	// For eip155, decode the 0x-prefixed hex address into 20 bytes.
	if namespace == NamespaceEIP155 {
		addrHex, addrBytes, err := normalizeEthereumAddress(address)
		if err != nil {
			return nil, err
		}
		parsed.AddressHex = addrHex
		parsed.AddressBytes = addrBytes
	} else {
		// Non-EVM namespaces: keep the raw address string for now.
		// Signature verification for these requires a dedicated verifier.
		parsed.AddressHex = address
	}

	return parsed, nil
}

// normalizeEthereumAddress validates an Ethereum address string and returns
// the lowercased hex (without 0x) and the 20-byte binary form.
//
// EIP-55 checksum is NOT validated. Mixed-case addresses are accepted and
// lowercased. This matches the behavior of every major wallet and explorer.
func normalizeEthereumAddress(addr string) (hexNoPrefix string, bytesOut []byte, err error) {
	addr = strings.TrimPrefix(addr, "0x")
	addr = strings.TrimPrefix(addr, "0X")
	if len(addr) != ethereumAddressHexLen {
		return "", nil, fmt.Errorf(
			"%w: Ethereum address must be %d hex characters, got %d",
			ErrInvalidDIDPKH, ethereumAddressHexLen, len(addr))
	}
	lower := strings.ToLower(addr)
	decoded, decErr := hex.DecodeString(lower)
	if decErr != nil {
		return "", nil, fmt.Errorf(
			"%w: address hex decode: %v", ErrInvalidDIDPKH, decErr)
	}
	return lower, decoded, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Construction helper
// -------------------------------------------------------------------------------------------------

// NewPKHDIDEthereum constructs a did:pkh identifier for an EVM account.
//   chainID   CAIP-2 chain reference (1 mainnet, 137 polygon, 10 optimism, ...)
//   address   hex string with or without 0x prefix
//
//	NewPKHDIDEthereum("1", "0xAbCd...") -> "did:pkh:eip155:1:0xabcd..."
func NewPKHDIDEthereum(chainID string, address string) (string, error) {
	if chainID == "" {
		return "", fmt.Errorf("did/pkh: chainID required")
	}
	hexAddr, _, err := normalizeEthereumAddress(address)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("did:pkh:%s:%s:0x%s", NamespaceEIP155, chainID, hexAddr), nil
}
