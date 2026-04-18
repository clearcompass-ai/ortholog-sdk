#!/bin/bash
# scan-refactor-impact.sh
# Finds every usage of symbols being touched by the web3 sign-in refactor.
# Run from repo root. Outputs go to ./refactor-scan/

set -e
OUT=./refactor-scan
mkdir -p "$OUT"
rm -f "$OUT"/*.txt

# Use rg if available, fall back to grep -rn
if command -v rg >/dev/null 2>&1; then
  GREP() { rg --no-heading -n --type go "$@" . 2>/dev/null || true; }
else
  GREP() { grep -rn --include='*.go' "$@" . 2>/dev/null || true; }
fi

echo "== 1. Package-level imports (who depends on what) =="

# Anyone importing the did/ package
GREP 'ortholog-sdk/did"' > "$OUT/01-imports-did.txt"

# Anyone importing crypto/signatures
GREP 'ortholog-sdk/crypto/signatures"' > "$OUT/02-imports-signatures.txt"

# Anyone importing core/envelope
GREP 'ortholog-sdk/core/envelope"' > "$OUT/03-imports-envelope.txt"

# Anyone importing exchange/identity
GREP 'ortholog-sdk/exchange/identity"' > "$OUT/04-imports-identity.txt"

echo "== 2. did/ package symbols being changed =="

# Functions/types that will change signature or behavior
for sym in \
  'GenerateDIDKey\b' \
  'GenerateRawKey\b' \
  'DIDKeyPair\b' \
  'CreateDIDDocument\b' \
  'CreateDIDDocumentConfig\b' \
  'NewWebDID\b' \
  'VerificationMethod\b' \
  'EcdsaSecp256r1VerificationKey2019' \
  'decodePublicKey\b' \
  'WitnessKeys\b' \
  'PublicKeyHex\b' \
  'PublicKeyMultibase\b'; do
  echo "--- $sym ---" >> "$OUT/10-did-symbols.txt"
  GREP -w "$sym" >> "$OUT/10-did-symbols.txt"
  echo "" >> "$OUT/10-did-symbols.txt"
done

# Resolver interface + implementations — staying as-is but verifying no hidden dependents
for sym in \
  'DIDResolver\b' \
  'WebDIDResolver\b' \
  'CachingResolver\b' \
  'VendorDIDResolver\b' \
  'VendorMapping\b' \
  'DIDEndpointAdapter\b' \
  'DIDWitnessAdapter\b'; do
  echo "--- $sym ---" >> "$OUT/11-did-resolvers.txt"
  GREP -w "$sym" >> "$OUT/11-did-resolvers.txt"
  echo "" >> "$OUT/11-did-resolvers.txt"
done

echo "== 3. crypto/signatures symbols =="

# SignEntry/VerifyEntry will become dispatchers — must preserve signatures
for sym in \
  'signatures\.SignEntry\b' \
  'signatures\.VerifyEntry\b' \
  'signatures\.GenerateKey\b' \
  'signatures\.PubKeyBytes\b' \
  'signatures\.ParsePubKey\b' \
  'signatures\.Secp256k1\b'; do
  echo "--- $sym ---" >> "$OUT/20-signatures-symbols.txt"
  GREP "$sym" >> "$OUT/20-signatures-symbols.txt"
  echo "" >> "$OUT/20-signatures-symbols.txt"
done

# Same symbols but from inside crypto/signatures itself (internal callers)
for sym in 'SignEntry\b' 'VerifyEntry\b' 'GenerateKey\b' 'PubKeyBytes\b' 'ParsePubKey\b'; do
  echo "--- $sym (intra-package) ---" >> "$OUT/21-signatures-intra.txt"
  GREP -w "$sym" | grep -v '_test\.go' >> "$OUT/21-signatures-intra.txt"
  echo "" >> "$OUT/21-signatures-intra.txt"
done

echo "== 4. core/envelope signature algorithm IDs =="

# Existing algo constants and anywhere they're switched on
for sym in \
  'SigAlgoECDSA\b' \
  'SigAlgoEd25519\b' \
  'SigAlgoID\b' \
  'ValidateAlgorithmID\b' \
  'AlgorithmID\b'; do
  echo "--- $sym ---" >> "$OUT/30-envelope-algo.txt"
  GREP -w "$sym" >> "$OUT/30-envelope-algo.txt"
  echo "" >> "$OUT/30-envelope-algo.txt"
done

echo "== 5. exchange/identity — CredentialRef rename check =="

# Every callsite if you rename CredentialRef → EntryRef
for sym in \
  'CredentialRef\b' \
  'MappingRecord\b' \
  'StoredMapping\b' \
  'MappingEscrow\b' \
  'NewMappingEscrow\b'; do
  echo "--- $sym ---" >> "$OUT/40-identity-symbols.txt"
  GREP -w "$sym" >> "$OUT/40-identity-symbols.txt"
  echo "" >> "$OUT/40-identity-symbols.txt"
done

echo "== 6. Entity-neutral language sweep (doc & comment hits) =="

# Domain-slanted terms that should be neutralized
for term in \
  'judicial.network' \
  'judicial network' \
  'consortium' \
  'credentialing' \
  'credential platform' \
  'professional' \
  'companies' \
  'court\b' \
  'physician' \
  'licensee' \
  'licensing officer'; do
  echo "--- $term ---" >> "$OUT/50-language-sweep.txt"
  GREP -i "$term" >> "$OUT/50-language-sweep.txt"
  echo "" >> "$OUT/50-language-sweep.txt"
done

echo "== 7. did:key legacy format usage (the f+hex you can now break) =="

# Find any hardcoded did:key:f... that would break with the multicodec+multibase fix
GREP 'did:key:f' > "$OUT/60-legacy-didkey-format.txt"
GREP 'did:key:z' >> "$OUT/60-legacy-didkey-format.txt"

echo "== 8. Hardcoded curve / key-type strings =="

# Places that assume specific curve/key types — these become branches or lookups
for sym in \
  'EcdsaSecp256r1VerificationKey2019' \
  'EcdsaSecp256k1VerificationKey2019' \
  'EcdsaSecp256k1RecoveryMethod2020' \
  'Ed25519VerificationKey2020' \
  'Bls12381G2Key2020' \
  'secp256k1' \
  'secp256r1' \
  'P-256' \
  'P256k1'; do
  echo "--- $sym ---" >> "$OUT/70-key-types.txt"
  GREP "$sym" >> "$OUT/70-key-types.txt"
  echo "" >> "$OUT/70-key-types.txt"
done

echo "== 9. Signer DID usage in builder / lifecycle =="

# Where the builder treats SignerDID — confirming it stays opaque
for sym in \
  'SignerDID\b' \
  'DelegateDID\b' \
  'AuthoritySet\b' \
  'ProposerDID\b' \
  'ExecutorDID\b' \
  'TargetDID\b'; do
  echo "--- $sym ---" >> "$OUT/80-did-strings.txt"
  GREP -w "$sym" >> "$OUT/80-did-strings.txt"
  echo "" >> "$OUT/80-did-strings.txt"
done

echo "== 10. Ethereum / web3 references already in repo =="

# Any existing web3 language — to avoid duplicating effort
for term in \
  'ethereum' \
  'eip.?191' \
  'eip.?712' \
  'eip.?4361' \
  'erc.?1056' \
  'erc.?1271' \
  'erc.?4337' \
  'caip.?10' \
  'keccak' \
  'ecrecover' \
  'wallet' \
  'siwe'; do
  echo "--- $term ---" >> "$OUT/90-web3-prior-art.txt"
  GREP -i "$term" >> "$OUT/90-web3-prior-art.txt"
  echo "" >> "$OUT/90-web3-prior-art.txt"
done

echo ""
echo "======================================================"
echo "Scan complete. Results in $OUT/"
echo ""
echo "Line counts per file:"
wc -l "$OUT"/*.txt | sort -n
echo ""
echo "Next steps:"
echo "  1. Review 10-did-symbols.txt   — everything that touches the DID types being changed"
echo "  2. Review 20-signatures-symbols.txt — entry signing/verifying callers"
echo "  3. Review 40-identity-symbols.txt — CredentialRef rename blast radius"
echo "  4. Review 50-language-sweep.txt — entity-neutral doc sweep targets"
echo "  5. Review 60-legacy-didkey-format.txt — any hardcoded did:key:f<hex> to kill"
echo "  6. Review 70-key-types.txt — anywhere curve/key-type strings are hardcoded"
echo "  7. Review 90-web3-prior-art.txt — confirm no pre-existing web3 code to avoid duplicating"
echo ""