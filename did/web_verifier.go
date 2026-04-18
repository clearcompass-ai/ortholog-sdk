/*
FILE PATH:
    did/web_verifier.go

DESCRIPTION:
    SignatureVerifier implementation for did:web. Resolves the DID document,
    selects the verification method indicated by the DID URL fragment (or
    the sole VM if the document has exactly one), and dispatches to the
    appropriate per-curve, per-algorithm primitive.

KEY ARCHITECTURAL DECISIONS:
    - Key selection is strict and unambiguous. The caller MUST either:
        (a) provide a fragment in the DID (e.g., did:web:x.com#key-0), which
            selects the VM whose id ends with that fragment, OR
        (b) the document must have exactly ONE verification method.
      If neither holds, verification fails with an explicit error. This
      eliminates "try every key until one works" behavior, which is an
      anti-pattern: it masks mis-routed signatures and breaks audit trails.
    - Verification method dispatch mirrors did:key: the vmType determines
      which primitive is called, and the algoID must match the type:
        EcdsaSecp256k1VerificationKey2019     + SigAlgoECDSA
        Ed25519VerificationKey2020            + SigAlgoEd25519
        EcdsaSecp256r1VerificationKey2019     + SigAlgoECDSA
        EcdsaSecp256k1RecoveryMethod2020      + SigAlgoECDSA / EIP191 / EIP712
          (the recovery method type permits did:pkh-style ecrecover against
           an explicitly-listed address in BlockchainAccountID)
      Mismatches fail loudly.
    - Resolved documents come from an injected DIDResolver. In production
      this is typically a CachingResolver wrapping a WebDIDResolver.
    - The resolver is called on EVERY verify unless wrapped in a cache. The
      WebVerifier does not maintain its own cache — composition is the right
      place to manage that.

OVERVIEW:
    Given did:web:example.com#key-0, message, sig, algoID:
        1. Strip fragment, remember it.
        2. Resolver.Resolve(did_without_fragment) -> DIDDocument
        3. Select VM by fragment (or sole VM).
        4. Dispatch on vm.Type + algoID to the correct primitive.

KEY DEPENDENCIES:
    - did/resolver.go:            DIDDocument, DIDResolver, VerificationMethod
    - did/key_resolver.go:        VerificationMethod* type string constants
    - crypto/signatures/*.go:     verification primitives
    - core/envelope/signature_wire.go: SigAlgo* constants
*/
package did

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrAmbiguousKeySelection is returned when a did:web identifier has no
// fragment and the document contains more than one verification method.
var ErrAmbiguousKeySelection = fmt.Errorf("did/web: ambiguous key selection (fragment required when document has multiple verification methods)")

// ErrVerificationMethodNotFound is returned when the DID URL fragment does
// not match any verification method in the resolved document.
var ErrVerificationMethodNotFound = fmt.Errorf("did/web: verification method not found in document")

// -------------------------------------------------------------------------------------------------
// 2) WebVerifier
// -------------------------------------------------------------------------------------------------

// WebVerifier verifies signatures for did:web identifiers by resolving the
// DID document and dispatching on the selected verification method.
type WebVerifier struct {
	resolver DIDResolver
}

// NewWebVerifier returns a verifier that uses the given resolver to fetch
// did:web documents. The resolver MUST be non-nil.
func NewWebVerifier(resolver DIDResolver) *WebVerifier {
	if resolver == nil {
		panic("did/web: NewWebVerifier requires a non-nil resolver")
	}
	return &WebVerifier{resolver: resolver}
}

// Verify resolves the DID document, selects a verification method, and
// verifies the signature against it.
func (v *WebVerifier) Verify(did string, message []byte, sig []byte, algoID uint16) error {
	baseDID, fragment := splitDIDFragment(did)

	doc, err := v.resolver.Resolve(baseDID)
	if err != nil {
		return fmt.Errorf("did/web: resolve: %w", err)
	}
	if len(doc.VerificationMethod) == 0 {
		return fmt.Errorf("did/web: document for %s contains no verification methods", baseDID)
	}

	vm, err := selectVerificationMethod(doc, fragment)
	if err != nil {
		return err
	}

	return verifyAgainstMethod(vm, message, sig, algoID)
}

// -------------------------------------------------------------------------------------------------
// 3) DID fragment handling
// -------------------------------------------------------------------------------------------------

// splitDIDFragment separates a DID URL from its optional fragment.
//
//	"did:web:x.com#key-0" -> ("did:web:x.com", "key-0")
//	"did:web:x.com"        -> ("did:web:x.com", "")
func splitDIDFragment(did string) (baseDID string, fragment string) {
	hashIdx := strings.IndexByte(did, '#')
	if hashIdx < 0 {
		return did, ""
	}
	return did[:hashIdx], did[hashIdx+1:]
}

// -------------------------------------------------------------------------------------------------
// 4) Verification method selection
// -------------------------------------------------------------------------------------------------

// selectVerificationMethod returns the verification method identified by
// the fragment, or the sole VM if the fragment is empty and there is
// exactly one VM. Otherwise returns an error — no fallback to "the first one".
func selectVerificationMethod(doc *DIDDocument, fragment string) (*VerificationMethod, error) {
	if fragment == "" {
		if len(doc.VerificationMethod) == 1 {
			return &doc.VerificationMethod[0], nil
		}
		return nil, fmt.Errorf("%w: document %s has %d VMs",
			ErrAmbiguousKeySelection, doc.ID, len(doc.VerificationMethod))
	}

	// Match by fragment at the end of the vm.id. Fragment can be compared
	// against the fragment portion of vm.id, which is typically formatted
	// as "<did>#<fragment>".
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vmFragment := extractVMFragment(vm.ID); vmFragment == fragment {
			return vm, nil
		}
	}
	return nil, fmt.Errorf("%w: fragment %q not present in %s",
		ErrVerificationMethodNotFound, fragment, doc.ID)
}

// extractVMFragment returns the portion of a verification method ID after
// its '#' character, or the entire ID if there is no '#'.
func extractVMFragment(vmID string) string {
	hashIdx := strings.IndexByte(vmID, '#')
	if hashIdx < 0 {
		return vmID
	}
	return vmID[hashIdx+1:]
}

// -------------------------------------------------------------------------------------------------
// 5) Per-method verification dispatch
// -------------------------------------------------------------------------------------------------

// verifyAgainstMethod dispatches on vm.Type + algoID to the correct primitive.
func verifyAgainstMethod(vm *VerificationMethod, message []byte, sig []byte, algoID uint16) error {
	switch vm.Type {

	case VerificationMethodEd25519:
		if algoID != envelope.SigAlgoEd25519 {
			return fmt.Errorf("%w: Ed25519 VM requires SigAlgoEd25519, got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		pubKey, err := decodePublicKey(*vm)
		if err != nil {
			return err
		}
		return signatures.VerifyEd25519(pubKey, message, sig)

	case VerificationMethodSecp256k1:
		if algoID != envelope.SigAlgoECDSA {
			return fmt.Errorf("%w: secp256k1 VM requires SigAlgoECDSA, got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		hash, err := requireHash32(message)
		if err != nil {
			return err
		}
		pubKey, err := decodePublicKey(*vm)
		if err != nil {
			return err
		}
		return signatures.VerifySecp256k1Compressed(pubKey, hash, sig)

	case VerificationMethodP256:
		if algoID != envelope.SigAlgoECDSA {
			return fmt.Errorf("%w: P-256 VM requires SigAlgoECDSA, got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		hash, err := requireHash32(message)
		if err != nil {
			return err
		}
		pubKey, err := decodePublicKey(*vm)
		if err != nil {
			return err
		}
		return signatures.VerifyP256(pubKey, hash, sig)

	case VerificationMethodSecp256k1Recovery:
		// Address-based verification. BlockchainAccountID carries the
		// CAIP-10 account identifier; PublicKeyHex carries the 20-byte
		// address (same information, different encoding).
		return verifyRecoveryMethod(vm, message, sig, algoID)

	default:
		return fmt.Errorf("did/web: unsupported verification method type %q", vm.Type)
	}
}

// requireHash32 enforces that message is exactly 32 bytes and returns it as
// a fixed-size array.
func requireHash32(message []byte) ([32]byte, error) {
	var out [32]byte
	if len(message) != 32 {
		return out, fmt.Errorf("did/web: message must be 32 bytes (canonical hash), got %d",
			len(message))
	}
	copy(out[:], message)
	return out, nil
}

// verifyRecoveryMethod performs ecrecover-based verification for VMs of type
// EcdsaSecp256k1RecoveryMethod2020. Accepts the three Ethereum algorithm IDs.
func verifyRecoveryMethod(vm *VerificationMethod, message []byte, sig []byte, algoID uint16) error {
	// Resolve the 20-byte address. Prefer BlockchainAccountID (CAIP-10), fall
	// back to PublicKeyHex (raw address hex).
	addr, err := addressFromRecoveryVM(vm)
	if err != nil {
		return err
	}

	hash, err := requireHash32(message)
	if err != nil {
		return err
	}

	switch algoID {
	case envelope.SigAlgoECDSA:
		return signatures.VerifySecp256k1Raw(addr, hash, sig)
	case envelope.SigAlgoEIP191:
		return signatures.VerifySecp256k1EIP191(addr, hash, sig)
	case envelope.SigAlgoEIP712:
		return signatures.VerifySecp256k1EIP712(addr, hash, sig)
	default:
		return fmt.Errorf("%w: recovery VM does not accept algorithm 0x%04x",
			ErrAlgorithmNotSupported, algoID)
	}
}

// addressFromRecoveryVM extracts the 20-byte Ethereum address from a
// recovery-method verification method, preferring BlockchainAccountID
// (CAIP-10) and falling back to PublicKeyHex.
func addressFromRecoveryVM(vm *VerificationMethod) ([signatures.EthereumAddressLen]byte, error) {
	var out [signatures.EthereumAddressLen]byte

	if vm.BlockchainAccountID != "" {
		// CAIP-10 format: "<namespace>:<reference>:<address>"
		parts := strings.Split(vm.BlockchainAccountID, ":")
		if len(parts) != 3 {
			return out, fmt.Errorf(
				"did/web: BlockchainAccountId %q not in CAIP-10 format",
				vm.BlockchainAccountID)
		}
		if parts[0] != NamespaceEIP155 {
			return out, fmt.Errorf(
				"%w: recovery VM namespace %q (only eip155 supported)",
				ErrUnsupportedNamespace, parts[0])
		}
		_, bytesOut, err := normalizeEthereumAddress(parts[2])
		if err != nil {
			return out, fmt.Errorf("did/web: BlockchainAccountId address: %w", err)
		}
		copy(out[:], bytesOut)
		return out, nil
	}

	if vm.PublicKeyHex != "" {
		decoded, err := hex.DecodeString(strings.TrimPrefix(vm.PublicKeyHex, "0x"))
		if err != nil {
			return out, fmt.Errorf("did/web: PublicKeyHex decode: %w", err)
		}
		if len(decoded) != signatures.EthereumAddressLen {
			return out, fmt.Errorf(
				"did/web: recovery VM PublicKeyHex must be %d bytes, got %d",
				signatures.EthereumAddressLen, len(decoded))
		}
		copy(out[:], decoded)
		return out, nil
	}

	return out, fmt.Errorf("did/web: recovery VM has no BlockchainAccountId or PublicKeyHex")
}
