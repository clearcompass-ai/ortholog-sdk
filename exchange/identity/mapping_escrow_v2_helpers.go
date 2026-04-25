// Package identity — mapping_escrow_v2_helpers.go holds the small
// V2-internal utilities reused by StoreMappingV2. Split out of
// mapping_escrow_v2.go so each file stays well under the 300-line
// budget documented in CONTRIBUTING. The helpers themselves are
// mechanical: marshal, share-wrapping rollback, index swap, V2
// atomic-emission gate.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// assertV2AtomicEmission enforces the V2 atomic-emission invariant
// inside StoreMappingV2: encShares non-empty ⇒ commitmentEntry
// non-nil. Returns nil on success, ErrV2AtomicEmissionViolated on
// violation. Gated by muEnableCommitmentEmissionAtomicV2 so the
// audit runner can flip the switch and observe that the binding
// test fires on a pathological tuple. The production happy path
// never produces such a tuple — encShares and commitmentEntry are
// produced together inside storeMappingV2Inner.
func assertV2AtomicEmission(encShares []EncryptedShare, commitmentEntry *envelope.Entry) error {
	if !muEnableCommitmentEmissionAtomicV2 {
		return nil
	}
	if len(encShares) > 0 && commitmentEntry == nil {
		return ErrV2AtomicEmissionViolated
	}
	return nil
}

// muEnableCommitmentEmissionAtomicV2 is the package-local mirror of
// the lifecycle-layer muEnableCommitmentEmissionAtomic switch. Kept
// in the identity package rather than imported from lifecycle
// because exchange/identity does not otherwise depend on lifecycle
// — importing it just for a boolean constant would create an
// unnecessary coupling. The mutation-audit registry names both
// constants explicitly; flipping either has the same observable
// effect on StoreMappingV2.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableCommitmentEmissionAtomicV2. │
//	├─────────────────────────────────────────────────────────────┤
//	│  Mirrors lifecycle.muEnableCommitmentEmissionAtomic. Setting │
//	│  false permanently readmits silent "shares without commit-   │
//	│  ment" emission. The switch exists for audit probes only.    │
//	└─────────────────────────────────────────────────────────────┘
//
// Binding test: TestStoreMappingV2_AtomicCommitmentEmission.
const muEnableCommitmentEmissionAtomicV2 = true

// marshalMappingRecord returns the canonical JSON bytes of a
// MappingRecord. Centralises the marshal call so V1 StoreMapping and
// V2 StoreMappingV2 cannot drift in their encoding.
func marshalMappingRecord(record MappingRecord) ([]byte, error) {
	return json.Marshal(record)
}

// hashBytes32 returns SHA-256 of the supplied bytes. Alias for
// sha256.Sum256 kept local so the V2 code reads symmetrically with
// the V1 identityTag computation without re-importing sha256 in
// every call site.
func hashBytes32(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// wrapSharesOrRollback ECIES-wraps each share for its destination
// node and returns the resulting EncryptedShare slice. If any wrap
// fails, the ciphertext at cid is deleted from the content store
// (rollback) and the error surfaces to the caller. Any partially-
// built EncryptedShare ciphertexts are zeroized before return.
//
// Shared between V1 StoreMapping and V2 StoreMappingV2 via structural
// parity: both go through the same rollback discipline. V1 currently
// inlines this logic; V2 factors it out.
func (me *MappingEscrow) wrapSharesOrRollback(
	cid storage.CID,
	shares []escrow.Share,
	nodes []EscrowNode,
) ([]EncryptedShare, error) {
	encShares := make([]EncryptedShare, len(nodes))
	for i, node := range nodes {
		ct, encErr := escrow.EncryptShareForNode(shares[i], node.PubKey)
		if encErr != nil {
			for j := 0; j < i; j++ {
				escrow.ZeroBytes(encShares[j].Ciphertext)
			}
			if delErr := me.store.Delete(cid); delErr != nil {
				return nil, fmt.Errorf(
					"identity/escrow_v2: ecies node %d (%s): %w; rollback delete also failed: %v",
					i, node.DID, encErr, delErr,
				)
			}
			return nil, fmt.Errorf(
				"identity/escrow_v2: ecies node %d (%s): %w",
				i, node.DID, encErr,
			)
		}
		encShares[i] = EncryptedShare{
			NodeDID:    node.DID,
			Ciphertext: ct,
		}
	}
	return encShares, nil
}

// indexV2 inserts the V2 stored mapping under identityTag. V2 lives
// alongside V1 in the same index map is impossible because the value
// types differ; this MappingEscrow instance maintains a separate V2
// index via the indexV2Map helper. Callers of StoreMappingV2 must not
// mix with V1 StoreMapping on the same identity.
//
// For Phase C, StoreMappingV2 does not support overwrite of an
// existing V2 mapping — each new V2 mapping for a fresh identity is
// indexed; conflicts return via the swap semantics once LookupV2 and
// DeleteV2 are wired. For now, insertion is unconditional; duplicate
// inserts are treated as a test-only scenario.
func (me *MappingEscrow) indexV2(identityTag [32]byte, stored *StoredMappingV2) {
	me.mu.Lock()
	defer me.mu.Unlock()
	if me.indexV2Map == nil {
		me.indexV2Map = make(map[[32]byte]*StoredMappingV2)
	}
	me.indexV2Map[identityTag] = stored
}

// HasMappingV2 reports whether a V2 mapping exists for the given
// identityHash. Parallel to HasMapping for V1.
func (me *MappingEscrow) HasMappingV2(identityHash [32]byte) bool {
	identityTag := hashBytes32(identityHash[:])
	me.mu.RLock()
	defer me.mu.RUnlock()
	if me.indexV2Map == nil {
		return false
	}
	_, ok := me.indexV2Map[identityTag]
	return ok
}

// GetStoredV2 returns the V2 stored metadata for the given
// identityHash, or nil if none. Exposed for verifier/lookup flows
// that need the SplitID and SplitNonce to reconstruct the on-log
// commitment binding.
func (me *MappingEscrow) GetStoredV2(identityHash [32]byte) *StoredMappingV2 {
	identityTag := hashBytes32(identityHash[:])
	me.mu.RLock()
	defer me.mu.RUnlock()
	if me.indexV2Map == nil {
		return nil
	}
	return me.indexV2Map[identityTag]
}
