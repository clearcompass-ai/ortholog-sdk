/*
FILE PATH:
    did/creation.go

DESCRIPTION:
    DID document and key-pair construction. Supports three curves for did:key
    generation (secp256k1, Ed25519, P-256) with spec-compliant
    multicodec + multibase base58btc encoding. Also builds DIDDocument values
    for did:web identities.

KEY ARCHITECTURAL DECISIONS:
    - No backward compatibility with the previous non-standard
      "did:key:f<hex>" format. Only the W3C spec-compliant "did:key:z..."
      format is produced.
    - Three distinct generator functions per curve rather than a polymorphic
      constructor. Each returns a concrete keypair type with the correct
      private key type for that curve, eliminating type assertions at the
      call site.
    - CreateDIDDocument accepts a VerificationMethodType per public key,
      replacing the previous hardcoded "EcdsaSecp256r1VerificationKey2019".
      Callers specify the curve/encoding used for each key explicitly.
    - Secp256k1 did:key entries compress the 65-byte uncompressed pubkey to
      33 bytes before multicodec encoding, per did:key spec.
    - Ed25519 and P-256 entries use the stdlib types directly. No vendor deps.

OVERVIEW:
    Four generators ship:
        GenerateDIDKeySecp256k1 -> secp256k1, 33-byte compressed pubkey
        GenerateDIDKeyEd25519   -> Ed25519,   32-byte pubkey
        GenerateDIDKeyP256      -> P-256,     33-byte compressed pubkey
        GenerateRawKey          -> secp256k1 key without DID wrapping (tests)

    CreateDIDDocument produces a full W3C-compliant DIDDocument with
    per-key verification method types and operator/witness/artifact store
    service endpoints. NewWebDID constructs did:web identifiers with
    proper path handling.

KEY DEPENDENCIES:
    - crypto/signatures: secp256k1 key generation, pubkey compression
    - crypto/ed25519:    Ed25519 key generation (stdlib)
    - crypto/ecdsa, crypto/elliptic: P-256 key generation (stdlib)
    - did/key_resolver.go: multicodec prefixes, EncodeDIDKey
*/
package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Keypair types
// -------------------------------------------------------------------------------------------------

// DIDKeyPairSecp256k1 is a generated secp256k1 keypair with its did:key
// identifier. The PrivateKey is a concrete *ecdsa.PrivateKey ready to pass
// to signatures.SignEntry.
type DIDKeyPairSecp256k1 struct {
	DID        string
	PrivateKey *ecdsa.PrivateKey
	// PublicKeyCompressed is the 33-byte compressed form used in did:key.
	PublicKeyCompressed []byte
	// PublicKeyUncompressed is the 65-byte uncompressed form used elsewhere
	// in the SDK (PRE, delegation keys, ECIES).
	PublicKeyUncompressed []byte
	KeyID                 [32]byte
}

// DIDKeyPairEd25519 is a generated Ed25519 keypair with its did:key identifier.
type DIDKeyPairEd25519 struct {
	DID        string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      [32]byte
}

// DIDKeyPairP256 is a generated P-256 keypair with its did:key identifier.
// Intended for passkey / WebAuthn integration scenarios where P-256 is the
// native curve.
type DIDKeyPairP256 struct {
	DID                 string
	PrivateKey          *ecdsa.PrivateKey
	PublicKeyCompressed []byte
	KeyID               [32]byte
}

// -------------------------------------------------------------------------------------------------
// 2) Generators
// -------------------------------------------------------------------------------------------------

// GenerateDIDKeySecp256k1 generates a secp256k1 keypair and wraps its
// compressed public key in a spec-compliant did:key identifier.
func GenerateDIDKeySecp256k1() (*DIDKeyPairSecp256k1, error) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("did/creation: generate secp256k1: %w", err)
	}
	uncompressed := signatures.PubKeyBytes(&priv.PublicKey)
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("did/creation: compress secp256k1: %w", err)
	}
	keyID := sha256.Sum256(compressed)

	return &DIDKeyPairSecp256k1{
		DID:                   EncodeDIDKey(MulticodecSecp256k1, compressed),
		PrivateKey:            priv,
		PublicKeyCompressed:   compressed,
		PublicKeyUncompressed: uncompressed,
		KeyID:                 keyID,
	}, nil
}

// GenerateDIDKeyEd25519 generates an Ed25519 keypair and wraps its public key
// in a spec-compliant did:key identifier.
func GenerateDIDKeyEd25519() (*DIDKeyPairEd25519, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("did/creation: generate Ed25519: %w", err)
	}
	keyID := sha256.Sum256(pub)
	return &DIDKeyPairEd25519{
		DID:        EncodeDIDKey(MulticodecEd25519, pub),
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      keyID,
	}, nil
}

// GenerateDIDKeyP256 generates a P-256 (secp256r1) keypair and wraps its
// compressed public key in a spec-compliant did:key identifier.
//
// Primarily intended for passkey / WebAuthn adjacent flows where the public
// key is already in P-256 form.
func GenerateDIDKeyP256() (*DIDKeyPairP256, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("did/creation: generate P-256: %w", err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	keyID := sha256.Sum256(compressed)
	return &DIDKeyPairP256{
		DID:                 EncodeDIDKey(MulticodecP256, compressed),
		PrivateKey:          priv,
		PublicKeyCompressed: compressed,
		KeyID:               keyID,
	}, nil
}

// GenerateRawKey generates a secp256k1 keypair without DID wrapping. Returns
// the private key and the 65-byte uncompressed public key. Used by tests
// and internal flows that need a raw keypair (delegation keys, ECIES).
func GenerateRawKey() (*ecdsa.PrivateKey, []byte, error) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return priv, signatures.PubKeyBytes(&priv.PublicKey), nil
}

// -------------------------------------------------------------------------------------------------
// 3) DID Document creation
// -------------------------------------------------------------------------------------------------

// PublicKeyEntry is one verification key to include in a generated DID
// document. The caller explicitly specifies the curve/encoding via
// VerificationMethodType.
type PublicKeyEntry struct {
	// VerificationMethodType is the W3C verification method type string.
	// Must be one of the VerificationMethod* constants defined in
	// did/key_resolver.go.
	VerificationMethodType string

	// PublicKeyHex is the hex-encoded public key bytes in the encoding
	// expected by the verification method type:
	//   - VerificationMethodSecp256k1: 33-byte compressed
	//   - VerificationMethodEd25519:   32-byte raw
	//   - VerificationMethodP256:      33-byte compressed
	//   - VerificationMethodSecp256k1Recovery: 20-byte Ethereum address
	PublicKeyHex string
}

// CreateDIDDocumentConfig configures DID document creation.
type CreateDIDDocumentConfig struct {
	// DID is the identifier for this document.
	DID string

	// OperatorEndpoint is the operator's API base URL.
	OperatorEndpoint string

	// WitnessEndpoints are URLs for witness services.
	WitnessEndpoints []string

	// ArtifactStoreEndpoint is the artifact store URL (optional).
	ArtifactStoreEndpoint string

	// PublicKeys are the verification methods to include. Each entry
	// specifies its own curve/encoding.
	PublicKeys []PublicKeyEntry

	// WitnessQuorumK is the K-of-N quorum requirement.
	WitnessQuorumK int
}

// CreateDIDDocument builds a W3C-compliant DIDDocument.
func CreateDIDDocument(cfg CreateDIDDocumentConfig) (*DIDDocument, error) {
	if cfg.DID == "" {
		return nil, fmt.Errorf("did/creation: DID is required")
	}

	now := time.Now().UTC()
	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://ortholog.org/ns/did/v1",
		},
		ID:             cfg.DID,
		Created:        &now,
		Updated:        &now,
		WitnessQuorumK: cfg.WitnessQuorumK,
	}

	for i, pk := range cfg.PublicKeys {
		if pk.VerificationMethodType == "" {
			return nil, fmt.Errorf(
				"did/creation: PublicKeys[%d].VerificationMethodType required", i)
		}
		if pk.PublicKeyHex == "" {
			return nil, fmt.Errorf(
				"did/creation: PublicKeys[%d].PublicKeyHex required", i)
		}
		doc.VerificationMethod = append(doc.VerificationMethod, VerificationMethod{
			ID:           fmt.Sprintf("%s#key-%d", cfg.DID, i),
			Type:         pk.VerificationMethodType,
			Controller:   cfg.DID,
			PublicKeyHex: pk.PublicKeyHex,
		})
	}

	if cfg.OperatorEndpoint != "" {
		doc.Service = append(doc.Service, Service{
			ID:              cfg.DID + "#operator",
			Type:            ServiceTypeOperator,
			ServiceEndpoint: cfg.OperatorEndpoint,
		})
	}

	for i, ep := range cfg.WitnessEndpoints {
		doc.Service = append(doc.Service, Service{
			ID:              fmt.Sprintf("%s#witness-%d", cfg.DID, i),
			Type:            ServiceTypeWitness,
			ServiceEndpoint: ep,
		})
	}

	if cfg.ArtifactStoreEndpoint != "" {
		doc.Service = append(doc.Service, Service{
			ID:              cfg.DID + "#artifact-store",
			Type:            ServiceTypeArtifactStore,
			ServiceEndpoint: cfg.ArtifactStoreEndpoint,
		})
	}

	return doc, nil
}

// -------------------------------------------------------------------------------------------------
// 4) did:web identifier construction
// -------------------------------------------------------------------------------------------------

// NewWebDID creates a did:web identifier from a domain and optional path.
//
//	NewWebDID("example.com", "")                   -> "did:web:example.com"
//	NewWebDID("example.com", "logs/domain-01")     -> "did:web:example.com:logs:domain-01"
func NewWebDID(domain string, path string) string {
	if path == "" {
		return "did:web:" + domain
	}
	return "did:web:" + domain + ":" + strings.ReplaceAll(path, "/", ":")
}
