/*
FILE PATH:
    did/pkh_verifier.go

DESCRIPTION:
    SignatureVerifier implementation for did:pkh. Extracts the Ethereum
    address from the DID identifier and dispatches to the appropriate
    ecrecover-based verification primitive based on the signature algorithm
    ID.

KEY ARCHITECTURAL DECISIONS:
    - did:pkh verification is address-based, not pubkey-based. The DID IS
      the 20-byte Ethereum address. ecrecover reconstructs a candidate
      address from the signature; we compare for equality.
    - Only eip155-namespace identifiers are accepted. Other CAIP-2 namespaces
      (solana, cosmos, bip122) would require entirely different recovery
      primitives and are rejected with a clear error.
    - Three signature algorithms are supported:
        SigAlgoECDSA  raw secp256k1 signature (65 bytes r || s || v) over
                      the canonical hash — used by automated signers
        SigAlgoEIP191 wallet personal_sign over the canonical hash
        SigAlgoEIP712 wallet eth_signTypedData_v4 over the Ortholog entry
                      typed-data schema
      Other algorithm IDs return ErrAlgorithmNotSupported.
    - The message parameter MUST be exactly 32 bytes (the canonical entry
      hash). Anything else is a protocol error and rejected immediately —
      there is no ambiguous "accept arbitrary-length messages" path.

OVERVIEW:
    Given did:pkh:eip155:1:0xAbC..., message (32 bytes), sig (65 bytes),
    algoID:
        1. ParseDIDPKH -> PKHIdentifier with 20-byte address
        2. Require Namespace == "eip155"
        3. Require len(message) == 32
        4. Switch on algoID to the correct primitive
        5. Primitive does ecrecover against its algorithm-specific digest
           and compares the recovered address to the DID's address

KEY DEPENDENCIES:
    - did/pkh.go: ParseDIDPKH, PKHIdentifier
    - crypto/signatures/verify_primitives.go: VerifySecp256k1Raw/EIP191/EIP712
    - core/envelope/signature_wire.go: SigAlgo* constants
*/
package did

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// pkhMessageLen is the required length of the message parameter for did:pkh
// verification. The message is always the 32-byte canonical entry hash.
const pkhMessageLen = 32

// -------------------------------------------------------------------------------------------------
// 2) PKHVerifier
// -------------------------------------------------------------------------------------------------

// PKHVerifier verifies signatures for did:pkh identifiers by dispatching on
// the signature algorithm ID to an ecrecover-based primitive.
type PKHVerifier struct{}

// NewPKHVerifier returns a verifier accepting the eip155 namespace.
func NewPKHVerifier() *PKHVerifier {
	return &PKHVerifier{}
}

// Verify verifies sig as a signature produced by the holder of did over
// message, using the algorithm identified by algoID.
//
// message MUST be exactly 32 bytes (the canonical entry hash). sig MUST be
// exactly 65 bytes (r || s || v).
func (v *PKHVerifier) Verify(did string, message []byte, sig []byte, algoID uint16) error {
	parsed, err := ParseDIDPKH(did)
	if err != nil {
		return err
	}
	if parsed.Namespace != NamespaceEIP155 {
		return fmt.Errorf(
			"%w: PKHVerifier only supports eip155, got %q",
			ErrUnsupportedNamespace, parsed.Namespace)
	}
	if len(parsed.AddressBytes) != signatures.EthereumAddressLen {
		return fmt.Errorf(
			"did/pkh: internal: parsed address is %d bytes, expected %d",
			len(parsed.AddressBytes), signatures.EthereumAddressLen)
	}
	if len(message) != pkhMessageLen {
		return fmt.Errorf(
			"did/pkh: message must be exactly %d bytes (canonical entry hash), got %d",
			pkhMessageLen, len(message))
	}

	var addr [signatures.EthereumAddressLen]byte
	copy(addr[:], parsed.AddressBytes)

	var hash [pkhMessageLen]byte
	copy(hash[:], message)

	switch algoID {
	case envelope.SigAlgoECDSA:
		return signatures.VerifySecp256k1Raw(addr, hash, sig)

	case envelope.SigAlgoEIP191:
		return signatures.VerifySecp256k1EIP191(addr, hash, sig)

	case envelope.SigAlgoEIP712:
		return signatures.VerifySecp256k1EIP712(addr, hash, sig)

	default:
		return fmt.Errorf(
			"%w: did:pkh does not accept algorithm 0x%04x (expect 0x0001, 0x0003, or 0x0004)",
			ErrAlgorithmNotSupported, algoID)
	}
}
