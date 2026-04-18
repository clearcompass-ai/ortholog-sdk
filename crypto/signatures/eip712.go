/*
FILE PATH:
    crypto/signatures/eip712.go

DESCRIPTION:
    EIP-712 typed data signing for Ortholog entries. Defines the frozen protocol
    domain separator and entry type hash, and exposes EntrySigningDigest() —
    the client-side helper a wallet application calls to produce the 32-byte
    digest it passes to eth_signTypedData.

KEY ARCHITECTURAL DECISIONS:
    - All domain parameters are FROZEN protocol constants. They MUST NEVER
      change. Changing any one of them — name, version, chainId,
      verifyingContract, salt — invalidates every signature ever produced
      against the protocol. Regression tests lock these values.
    - chainId is 0 (chain-agnostic). Ortholog is a protocol, not an EVM
      contract, so there is no chain to bind to. Wallets accept chainId 0 for
      signTypedData purposes.
    - verifyingContract is the zero address. Same reason: no contract.
    - salt is keccak256("ortholog.v1.entry-signature"). Deterministic, unique
      to this protocol, committed forever. Prevents cross-protocol replay
      even if another protocol ever shipped with name="Ortholog" version="1".
    - The struct type is minimal: OrthologEntry(bytes32 canonicalHash). Wallet
      UIs that support named display wrap this with richer display types, but
      the on-the-wire typed data the verifier reconstructs is this single
      field. The canonical hash commits to everything else.

OVERVIEW:
    EIP-712 digest formula:
        domainSeparator = keccak256(
            keccak256(EIP712Domain_type_string) ||
            keccak256(name) ||
            keccak256(version) ||
            uint256_be(chainId) ||
            address_padded(verifyingContract) ||
            salt
        )
        structHash = keccak256(
            keccak256(struct_type_string) ||
            canonical_hash
        )
        digest = keccak256(0x1901 || domainSeparator || structHash)

    Clients use EntrySigningDigest(canonicalHash) to produce the 32-byte digest
    for eth_signTypedData_v4. Verifiers reconstruct the same digest and call
    ecrecover.

KEY DEPENDENCIES:
    - crypto/signatures/ethereum_primitives.go: Keccak256
*/
package signatures

// -------------------------------------------------------------------------------------------------
// 1) Frozen domain constants (MUST NEVER CHANGE)
// -------------------------------------------------------------------------------------------------

// EIP712DomainName is the fixed protocol name. Hashed into the domain separator.
const EIP712DomainName = "Ortholog"

// EIP712DomainVersion is the fixed protocol version. Hashed into the domain separator.
const EIP712DomainVersion = "1"

// EIP712DomainChainID is the fixed chain ID. Zero means chain-agnostic.
const EIP712DomainChainID = uint64(0)

// eip712DomainTypeString is the canonical EIP-712 domain type declaration.
// The order of fields in the string determines the hash; this MUST NOT change.
const eip712DomainTypeString = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"

// entryTypeString is the Ortholog entry typed data declaration.
const entryTypeString = "OrthologEntry(bytes32 canonicalHash)"

// eip712Prefix is the EIP-712 digest prefix: 0x19 (EIP-191 version selector)
// followed by 0x01 (EIP-712 version discriminator).
var eip712Prefix = []byte{0x19, 0x01}

// -------------------------------------------------------------------------------------------------
// 2) Precomputed constants (derived from the frozen constants above)
// -------------------------------------------------------------------------------------------------

// These are computed at package initialization to avoid recomputation on every
// signature verification. Their correctness is locked by a regression test.

var (
	// eip712DomainTypeHash = keccak256(eip712DomainTypeString)
	eip712DomainTypeHash [32]byte

	// entryTypeHash = keccak256(entryTypeString)
	entryTypeHash [32]byte

	// eip712ProtocolSalt = keccak256("ortholog.v1.entry-signature")
	//
	// Unique salt for this protocol. Changing this invalidates all prior
	// signatures. Locked by regression test.
	eip712ProtocolSalt [32]byte

	// eip712DomainSeparator is the fully-computed domain separator for this
	// protocol. Constant for the lifetime of the protocol.
	eip712DomainSeparator [32]byte
)

// -------------------------------------------------------------------------------------------------
// 3) Initialization
// -------------------------------------------------------------------------------------------------

func init() {
	eip712DomainTypeHash = Keccak256([]byte(eip712DomainTypeString))
	entryTypeHash = Keccak256([]byte(entryTypeString))
	eip712ProtocolSalt = Keccak256([]byte("ortholog.v1.entry-signature"))

	// Compose the domain separator:
	//   keccak256(
	//     domainTypeHash ||
	//     keccak256(name) ||
	//     keccak256(version) ||
	//     uint256_be(chainId) ||
	//     address_padded(0x0) ||
	//     salt
	//   )
	nameHash := Keccak256([]byte(EIP712DomainName))
	versionHash := Keccak256([]byte(EIP712DomainVersion))

	var chainIDBytes [32]byte
	// chainId is 0 so the array stays all-zero; left in place for clarity if it ever changes.
	uint256BE(&chainIDBytes, EIP712DomainChainID)

	var verifyingContract [32]byte // zero address padded to 32 bytes

	eip712DomainSeparator = Keccak256(
		eip712DomainTypeHash[:],
		nameHash[:],
		versionHash[:],
		chainIDBytes[:],
		verifyingContract[:],
		eip712ProtocolSalt[:],
	)
}

// uint256BE writes a uint64 as big-endian 256-bit integer into the last 8
// bytes of out. The first 24 bytes remain zero.
func uint256BE(out *[32]byte, v uint64) {
	out[24] = byte(v >> 56)
	out[25] = byte(v >> 48)
	out[26] = byte(v >> 40)
	out[27] = byte(v >> 32)
	out[28] = byte(v >> 24)
	out[29] = byte(v >> 16)
	out[30] = byte(v >> 8)
	out[31] = byte(v)
}

// -------------------------------------------------------------------------------------------------
// 4) Public API
// -------------------------------------------------------------------------------------------------

// EntrySigningDigest computes the 32-byte EIP-712 digest a wallet produces
// when signing an Ortholog entry via eth_signTypedData_v4.
//
// Callers (wallet clients, verifiers) compute this over the 32-byte canonical
// entry hash. The wallet signs this digest; the verifier reconstructs it
// and runs ecrecover.
//
// Thread-safe. Pure function.
func EntrySigningDigest(canonicalHash [32]byte) [32]byte {
	structHash := Keccak256(entryTypeHash[:], canonicalHash[:])
	return Keccak256(eip712Prefix, eip712DomainSeparator[:], structHash[:])
}

// EIP712DomainSeparator returns the frozen domain separator. Exported for
// verifier implementations that need it directly and for regression tests
// that lock the constant.
func EIP712DomainSeparator() [32]byte {
	return eip712DomainSeparator
}

// EIP712EntryTypeHash returns the frozen entry type hash. Exported for
// regression tests that lock the constant.
func EIP712EntryTypeHash() [32]byte {
	return entryTypeHash
}

// EIP712ProtocolSalt returns the frozen protocol salt. Exported for regression
// tests that lock the constant.
func EIP712ProtocolSalt() [32]byte {
	return eip712ProtocolSalt
}
