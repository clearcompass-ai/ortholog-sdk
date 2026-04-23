package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

type preSplitIDVector struct {
	Description            string `json:"description"`
	DST                    string `json:"dst"`
	GrantorDID             string `json:"grantor_did"`
	RecipientDID           string `json:"recipient_did"`
	ArtifactCIDSourceUTF8  string `json:"artifact_cid_source_bytes_utf8"`
	ArtifactCIDBytesHex    string `json:"artifact_cid_bytes_hex"`
	ExpectedSplitIDHex     string `json:"expected_split_id_hex"`
}

// TestComputePREGrantSplitID_GoldenVector locks the exact bytes of
// the v7.75 PRE Grant SplitID derivation. The fixture pins a DST,
// two DIDs, and the source bytes that produce the artifact CID;
// the expected SplitID is recomputed from those inputs and must
// match byte-for-byte. This is the cross-implementation anchor —
// a Rust or TypeScript port that produces different bytes fails
// this test.
func TestComputePREGrantSplitID_GoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "pre_grant_split_id_vector.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx preSplitIDVector
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fx.DST != PREGrantSplitIDDST {
		t.Fatalf("fixture DST %q != package DST %q", fx.DST, PREGrantSplitIDDST)
	}

	digest := sha256.Sum256([]byte(fx.ArtifactCIDSourceUTF8))
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: digest[:]}
	wantCIDBytes, err := hex.DecodeString(fx.ArtifactCIDBytesHex)
	if err != nil {
		t.Fatalf("decode cid bytes: %v", err)
	}
	if hex.EncodeToString(cid.Bytes()) != fx.ArtifactCIDBytesHex {
		t.Fatalf("CID.Bytes() drift: got %x, want %s", cid.Bytes(), fx.ArtifactCIDBytesHex)
	}
	_ = wantCIDBytes

	got := ComputePREGrantSplitID(fx.GrantorDID, fx.RecipientDID, cid)
	if hex.EncodeToString(got[:]) != fx.ExpectedSplitIDHex {
		t.Fatalf("SplitID mismatch:\n  got:  %x\n  want: %s", got[:], fx.ExpectedSplitIDHex)
	}
}

// TestComputePREGrantSplitID_NFCEdgeCase pins the caller-normalizes
// contract from ADR-005 §2: NFC and NFD byte sequences for the same
// visual DID produce different SplitIDs. The SDK does not guess at
// caller intent — if two callers pass different raw bytes, they get
// different SplitIDs. Callers that accept DIDs from external input
// MUST NFC-normalize at the boundary.
//
// Fixture bytes:
//   NFC composed:   did:web:café.example.com
//                   (U+00E9 encoded as 0xC3 0xA9)
//   NFD decomposed: did:web:café.example.com
//                   (U+0065 U+0301 encoded as 0x65 0xCC 0x81)
func TestComputePREGrantSplitID_NFCEdgeCase(t *testing.T) {
	// Reconstruct both forms directly from byte literals so the
	// fixture is portable across any UTF-8 source-file normalisation
	// tooling.
	nfcPrefix := "did:web:caf"
	nfdPrefix := "did:web:cafe"
	nfcGrantor := nfcPrefix + string([]byte{0xC3, 0xA9}) + ".example.com" // é precomposed
	nfdGrantor := nfdPrefix + string([]byte{0xCC, 0x81}) + ".example.com" // e + combining acute
	if nfcGrantor == nfdGrantor {
		t.Fatal("NFC and NFD byte sequences happen to be equal — fixture broken")
	}

	recipient := "did:web:example.com:recipient"
	digest := sha256.Sum256([]byte("artifact/1"))
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: digest[:]}

	nfc := ComputePREGrantSplitID(nfcGrantor, recipient, cid)
	nfd := ComputePREGrantSplitID(nfdGrantor, recipient, cid)
	if nfc == nfd {
		t.Fatalf("NFC and NFD grantors produced the same SplitID — caller-normalizes contract is silently broken\n  digest: %x", nfc)
	}
}

// TestComputePREGrantSplitID_CIDAlgorithmBinding pins the cross-
// algorithm collision resistance property that ADR-005 §2 locks:
// two CIDs carrying identical 32-byte digests under different
// algorithm tags produce distinct SplitIDs. This is why
// ComputePREGrantSplitID hashes artifactCID.Bytes() (which leads
// with the algorithm byte) rather than artifactCID.Digest alone.
func TestComputePREGrantSplitID_CIDAlgorithmBinding(t *testing.T) {
	const hypotheticalAlgo storage.HashAlgorithm = 0xF2
	storage.RegisterAlgorithm(hypotheticalAlgo, "pre-split-id-algo-f2", 32, func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	})

	grantor := "did:web:example.com:grantor"
	recipient := "did:web:example.com:recipient"
	shared := sha256.Sum256([]byte("probe"))

	cid1 := storage.CID{Algorithm: storage.AlgoSHA256, Digest: shared[:]}
	cid2 := storage.CID{Algorithm: hypotheticalAlgo, Digest: shared[:]}

	id1 := ComputePREGrantSplitID(grantor, recipient, cid1)
	id2 := ComputePREGrantSplitID(grantor, recipient, cid2)
	if id1 == id2 {
		t.Fatalf("cross-algorithm SplitID collision — the Bytes() mandate is silently bypassed\n  shared-digest: %x", shared)
	}
}

// TestComputePREGrantSplitID_TupleBinding sweeps each element of
// the (grantor, recipient, CID) tuple and confirms changing any one
// of them changes the SplitID.
func TestComputePREGrantSplitID_TupleBinding(t *testing.T) {
	grantor := "did:web:example.com:grantor"
	recipient := "did:web:example.com:recipient"
	digest := sha256.Sum256([]byte("artifact/1"))
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: digest[:]}
	base := ComputePREGrantSplitID(grantor, recipient, cid)

	if other := ComputePREGrantSplitID(grantor+"x", recipient, cid); other == base {
		t.Fatal("grantor mutation left SplitID unchanged")
	}
	if other := ComputePREGrantSplitID(grantor, recipient+"x", cid); other == base {
		t.Fatal("recipient mutation left SplitID unchanged")
	}
	alt := sha256.Sum256([]byte("artifact/2"))
	otherCID := storage.CID{Algorithm: storage.AlgoSHA256, Digest: alt[:]}
	if other := ComputePREGrantSplitID(grantor, recipient, otherCID); other == base {
		t.Fatal("CID mutation left SplitID unchanged")
	}
}

// TestComputePREGrantSplitID_DSTPinned guards the DST constant
// against silent drift. Any change to PREGrantSplitIDDST — including
// a version bump to "-v2" — must go through ADR review because it
// invalidates every PRE grant SplitID ever produced.
func TestComputePREGrantSplitID_DSTPinned(t *testing.T) {
	if PREGrantSplitIDDST != "ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1" {
		t.Fatalf("PREGrantSplitIDDST drifted: got %q, want %q", PREGrantSplitIDDST, "ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1")
	}
}
