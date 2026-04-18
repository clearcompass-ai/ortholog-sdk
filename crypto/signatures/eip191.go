/*
FILE PATH:
    crypto/signatures/eip191.go

DESCRIPTION:
    EIP-191 "personal_sign" message digest construction. Produces the 32-byte
    digest that a wallet signs when invoked via personal_sign / eth_sign.

KEY ARCHITECTURAL DECISIONS:
    - Version 0x45 ("E") only. This is the personal_sign variant used by every
      EVM wallet (MetaMask, Ledger, Rainbow, Coinbase Wallet, WalletConnect).
      We do NOT implement version 0x00 (data-with-intended-validator) or
      version 0x01 (alias for EIP-712) — those have their own flows.
    - The length prefix uses decimal ASCII digits per the spec, not hex.
    - Input is raw bytes. The caller is responsible for deciding what bytes
      are signed — typically the canonical entry hash (32 bytes) or a SIWE
      structured message.

OVERVIEW:
    Digest formula (EIP-191 v0x45):
        prefix  = "\x19Ethereum Signed Message:\n" || decimal_ascii(len(message))
        digest  = keccak256(prefix || message)

    For Ortholog entry signing via EIP-191, the wallet signs over the 32-byte
    canonical entry hash. The verifier reconstructs:
        digest = EIP191Digest(canonicalHash[:])

    ...then runs ecrecover against that digest.

KEY DEPENDENCIES:
    - crypto/signatures/ethereum_primitives.go: Keccak256
*/
package signatures

import (
	"strconv"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// eip191PersonalSignPrefix is the fixed prefix for EIP-191 version 0x45.
// The byte 0x19 is the EIP-191 version selector.
const eip191PersonalSignPrefix = "\x19Ethereum Signed Message:\n"

// -------------------------------------------------------------------------------------------------
// 2) Digest
// -------------------------------------------------------------------------------------------------

// EIP191Digest computes the Keccak256 digest a wallet produces when signing
// the given message via personal_sign (EIP-191 version 0x45).
//
// This is the digest that ecrecover must be called against to recover the
// signer's address.
func EIP191Digest(message []byte) [32]byte {
	prefix := eip191PersonalSignPrefix + strconv.Itoa(len(message))
	return Keccak256([]byte(prefix), message)
}
