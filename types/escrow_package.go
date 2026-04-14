package types

import "sort"

// EscrowPackage is stored on content-addressed blob storage (CAS).
// Contains Shamir shares for artifact keys and pre-committed signing key.
// Deterministic serialization: shares sorted by escrow node DID.
type EscrowPackage struct {
	HolderDID       string           // Real DID of the holder
	M               int              // Reconstruction threshold
	N               int              // Total shares
	FieldTag        byte             // 0x01 = GF(256). All shares use same field.
	EncryptedShares []EncryptedShare // Sorted by EscrowNodeDID for determinism
	ArtifactKeyCIDs []string         // CIDs of encrypted artifact keys
}

// EncryptedShare is a single Shamir share encrypted for a specific escrow node.
type EncryptedShare struct {
	EscrowNodeDID string // DID of the escrow node holding this share
	EncryptedBlob []byte // ECIES-encrypted share (34 bytes plaintext -> ~113 bytes encrypted)
}

// SortShares sorts EncryptedShares by EscrowNodeDID for deterministic serialization.
// Must be called before serialization. Round-trip identity requires sorted order.
func (p *EscrowPackage) SortShares() {
	sort.Slice(p.EncryptedShares, func(i, j int) bool {
		return p.EncryptedShares[i].EscrowNodeDID < p.EncryptedShares[j].EscrowNodeDID
	})
}
