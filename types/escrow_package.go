package types

import "sort"

type EscrowPackage struct {
	HolderDID       string
	M               int
	N               int
	FieldTag        byte
	EncryptedShares []EncryptedShare
	ArtifactKeyCIDs []string
}

type EncryptedShare struct {
	EscrowNodeDID string
	EncryptedBlob []byte
}

func (p *EscrowPackage) SortShares() {
	sort.Slice(p.EncryptedShares, func(i, j int) bool {
		return p.EncryptedShares[i].EscrowNodeDID < p.EncryptedShares[j].EscrowNodeDID
	})
}
