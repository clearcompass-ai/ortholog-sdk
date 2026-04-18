// tests/fixtures/generate-web3-fixtures.mjs
//
// Regenerate tests/fixtures/web3-interop.json from the canonical EIP-712
// domain using ethers v6 as the reference implementation.
//
// ONE-TIME DEVELOPER TOOL. NOT required by CI. The committed JSON is
// consumed by tests/web3_interop_test.go, which is pure Go.
//
// Usage:
//   cd tests/fixtures
//   npm init -y
//   npm install ethers@^6
//   node generate-web3-fixtures.mjs > web3-interop.json
//
// What it produces:
//   For each (privKey, canonicalHash) test case, the script outputs:
//     - the 20-byte address derived from the private key
//     - the 32-byte EIP-712 digest the SDK's EntrySigningDigest() must reproduce
//     - the 65-byte EIP-712 signature produced by ethers.signTypedData
//     - the 32-byte EIP-191 digest the SDK's EIP191Digest() must reproduce
//     - the 65-byte EIP-191 signature produced by ethers.signMessage
//
// The Ortholog domain constants are embedded here AND in the Go code; if you
// change one, you must change the other, and regenerate these fixtures.

import { ethers } from "ethers";

const DOMAIN = {
  name: "Ortholog",
  version: "1",
  chainId: 0,
  verifyingContract: "0x0000000000000000000000000000000000000000",
  salt: ethers.keccak256(ethers.toUtf8Bytes("ortholog.v1.entry-signature")),
};

const TYPES = {
  OrthologEntry: [{ name: "canonicalHash", type: "bytes32" }],
};

// ─────────────────────────────────────────────────────────────────────────
// Test cases. Extend by appending; do NOT modify existing cases (existing
// fixtures lock verifier-side behavior).
// ─────────────────────────────────────────────────────────────────────────
const CASES = [
  {
    name: "priv_01_canon_zero",
    privKeyHex: "0x" + "00".repeat(31) + "01",
    canonicalHex: "0x" + "00".repeat(32),
  },
  {
    name: "priv_01_canon_pattern",
    privKeyHex: "0x" + "00".repeat(31) + "01",
    canonicalHex: "0x" + "11".repeat(32),
  },
  {
    name: "priv_2a_canon_deadbeef",
    privKeyHex: "0x" + "00".repeat(31) + "2a",
    canonicalHex: "0x" + "deadbeef".repeat(8),
  },
  {
    name: "priv_ff_canon_random",
    privKeyHex: "0x" + "00".repeat(31) + "ff",
    canonicalHex: "0x" + "aa".repeat(32),
  },
];

// ─────────────────────────────────────────────────────────────────────────
// Generation
// ─────────────────────────────────────────────────────────────────────────
const fixtures = [];
for (const c of CASES) {
  const wallet = new ethers.Wallet(c.privKeyHex);
  const address = wallet.address.toLowerCase().replace(/^0x/, "");

  // EIP-712 digest + signature
  const eip712Digest = ethers.TypedDataEncoder.hash(DOMAIN, TYPES, {
    canonicalHash: c.canonicalHex,
  });
  const eip712Sig = await wallet.signTypedData(DOMAIN, TYPES, {
    canonicalHash: c.canonicalHex,
  });

  // EIP-191 digest + signature
  const canonicalBytes = ethers.getBytes(c.canonicalHex);
  const eip191Digest = ethers.hashMessage(canonicalBytes);
  const eip191Sig = await wallet.signMessage(canonicalBytes);

  fixtures.push({
    source: "ethers-v6",
    name: c.name,
    priv_key_hex: c.privKeyHex.replace(/^0x/, ""),
    address_hex: address,
    canonical_hex: c.canonicalHex.replace(/^0x/, ""),
    eip191_digest: eip191Digest.replace(/^0x/, ""),
    eip191_sig: eip191Sig.replace(/^0x/, ""),
    eip712_digest: eip712Digest.replace(/^0x/, ""),
    eip712_sig: eip712Sig.replace(/^0x/, ""),
  });
}

const out = {
  domain: {
    name: DOMAIN.name,
    version: DOMAIN.version,
    chain_id: DOMAIN.chainId,
    verifying_contract: DOMAIN.verifyingContract,
    salt_hex: DOMAIN.salt.replace(/^0x/, ""),
  },
  fixtures,
};

console.log(JSON.stringify(out, null, 2));
