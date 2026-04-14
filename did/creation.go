/*
did/creation.go — DID document creation and key generation.

GenerateDIDKey: generates ECDSA P-256 key pair + did:key identifier.
CreateDIDDocument: builds a complete DIDDocument for a new Ortholog log.
NewWebDID: creates a did:web identifier from a domain and optional path.

Used by:
  - Operator bootstrap (create DID for new log)
  - Domain onboarding (generate keys + publish DID document)
  - Test fixtures
*/
package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// ─────────────────────────────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────────────────────────────

// DIDKeyPair holds a generated key pair and its DID identifier.
type DIDKeyPair struct {
	DID        string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte   // Compressed public key bytes.
	KeyID      [32]byte // SHA-256 of public key bytes.
}

// GenerateDIDKey generates a new ECDSA P-256 key pair and derives a
// did:key identifier from the public key.
//
// The did:key format encodes the public key directly in the identifier,
// making it self-resolving (no HTTP fetch needed). Useful for ephemeral
// or test identities.
func GenerateDIDKey() (*DIDKeyPair, error) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("did/creation: generate key: %w", err)
	}

	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	keyID := sha256.Sum256(pubBytes)

	// did:key uses multicodec prefix 0x1200 for P-256 public key,
	// then multibase base58btc encoding. For simplicity, we use hex.
	didStr := "did:key:f" + hex.EncodeToString(pubBytes)

	return &DIDKeyPair{
		DID:        didStr,
		PrivateKey: priv,
		PublicKey:  pubBytes,
		KeyID:      keyID,
	}, nil
}

// GenerateRawKey generates a raw ECDSA P-256 key pair without DID formatting.
// Returns the private key and compressed public key bytes.
func GenerateRawKey() (*ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	return priv, pubBytes, nil
}

// ─────────────────────────────────────────────────────────────────────
// DID Document creation
// ─────────────────────────────────────────────────────────────────────

// CreateDIDDocumentConfig configures document creation.
type CreateDIDDocumentConfig struct {
	// DID is the identifier for this document (e.g., "did:web:court.example.com").
	DID string

	// OperatorEndpoint is the operator's API base URL.
	OperatorEndpoint string

	// WitnessEndpoints are URLs for witness services.
	WitnessEndpoints []string

	// ArtifactStoreEndpoint is the artifact store URL (optional).
	ArtifactStoreEndpoint string

	// PublicKeys are the verification method public keys (hex-encoded).
	PublicKeys []string

	// WitnessQuorumK is the K-of-N quorum requirement.
	WitnessQuorumK int
}

// CreateDIDDocument builds a complete DIDDocument from the given configuration.
//
// The document follows W3C DID Core spec with Ortholog extensions for
// witness quorum and service endpoint types.
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

	// Add verification methods.
	for i, pubKeyHex := range cfg.PublicKeys {
		vm := VerificationMethod{
			ID:           fmt.Sprintf("%s#key-%d", cfg.DID, i),
			Type:         "EcdsaSecp256r1VerificationKey2019",
			Controller:   cfg.DID,
			PublicKeyHex: pubKeyHex,
		}
		doc.VerificationMethod = append(doc.VerificationMethod, vm)
	}

	// Add operator service.
	if cfg.OperatorEndpoint != "" {
		doc.Service = append(doc.Service, Service{
			ID:              cfg.DID + "#operator",
			Type:            ServiceTypeOperator,
			ServiceEndpoint: cfg.OperatorEndpoint,
		})
	}

	// Add witness services.
	for i, ep := range cfg.WitnessEndpoints {
		doc.Service = append(doc.Service, Service{
			ID:              fmt.Sprintf("%s#witness-%d", cfg.DID, i),
			Type:            ServiceTypeWitness,
			ServiceEndpoint: ep,
		})
	}

	// Add artifact store service.
	if cfg.ArtifactStoreEndpoint != "" {
		doc.Service = append(doc.Service, Service{
			ID:              cfg.DID + "#artifact-store",
			Type:            ServiceTypeArtifactStore,
			ServiceEndpoint: cfg.ArtifactStoreEndpoint,
		})
	}

	return doc, nil
}

// ─────────────────────────────────────────────────────────────────────
// did:web identifier construction
// ─────────────────────────────────────────────────────────────────────

// NewWebDID creates a did:web identifier from a domain and optional path.
//
//	NewWebDID("court.example.com", "")         → "did:web:court.example.com"
//	NewWebDID("example.com", "logs/court-01")  → "did:web:example.com:logs:court-01"
func NewWebDID(domain string, path string) string {
	if path == "" {
		return "did:web:" + domain
	}
	// Replace '/' with ':' per did:web spec.
	colonPath := strings.ReplaceAll(path, "/", ":")
	return "did:web:" + domain + ":" + colonPath
}
