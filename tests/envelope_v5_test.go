/*
V5 wire format tests using the existing test helpers (makeEntry, crypto.CanonicalHash).
Validates:
  - v5 round-trip with DomainManifestVersion present and absent
  - Preamble version is 5
  - Canonical hash covers DomainManifestVersion (differentiates otherwise-identical entries)
  - Admission proof length-prefixing isolates Authority_Skip (SDK-3 regression)
*/
package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestV5_RoundTripWithManifestVersion(t *testing.T) {
	t.Parallel()
	ver := [3]uint16{1, 2, 3}
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:             "did:web:courts.nashville.gov",
		AuthorityPath:         sameSigner(),
		EventTime:             1700000000,
		DomainManifestVersion: &ver,
	}, []byte(`{"case":"2027-CR-4471"}`))
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	b := envelope.Serialize(entry)
	if version := binary.BigEndian.Uint16(b[0:2]); version != 5 {
		t.Errorf("preamble version = %d, want 5", version)
	}

	round, err := envelope.Deserialize(b)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if round.Header.ProtocolVersion != 5 {
		t.Errorf("ProtocolVersion = %d, want 5", round.Header.ProtocolVersion)
	}
	if round.Header.DomainManifestVersion == nil {
		t.Fatal("DomainManifestVersion: got nil, want populated")
	}
	if *round.Header.DomainManifestVersion != ver {
		t.Errorf("DomainManifestVersion: got %v, want %v",
			*round.Header.DomainManifestVersion, ver)
	}
	if !bytes.Equal(round.DomainPayload, entry.DomainPayload) {
		t.Error("payload mismatch after round-trip")
	}
}

func TestV5_RoundTripWithoutManifestVersion(t *testing.T) {
	t.Parallel()
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:web:courts.nashville.gov",
		EventTime: 1700000000,
	}, []byte(`{"note":"commentary"}`))
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	round, err := envelope.Deserialize(envelope.Serialize(entry))
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if round.Header.DomainManifestVersion != nil {
		t.Errorf("DomainManifestVersion: got %v, want nil", *round.Header.DomainManifestVersion)
	}
}

func TestV5_CanonicalHashCoversManifestVersion(t *testing.T) {
	t.Parallel()
	// Two entries identical except for DomainManifestVersion must produce
	// distinct canonical hashes.
	v1 := [3]uint16{1, 0, 0}
	v2 := [3]uint16{1, 0, 1}

	base := func(v *[3]uint16) *envelope.Entry {
		e, err := envelope.NewEntry(envelope.ControlHeader{
			SignerDID:             "did:test:hash",
			AuthorityPath:         sameSigner(),
			EventTime:             1700000000,
			DomainManifestVersion: v,
		}, []byte("{}"))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	h1 := crypto.CanonicalHash(base(&v1))
	h2 := crypto.CanonicalHash(base(&v2))
	if h1 == h2 {
		t.Error("canonical hash did not differentiate entries with different DomainManifestVersion")
	}
}

func TestV5_CanonicalHashDeterministic(t *testing.T) {
	t.Parallel()
	ver := [3]uint16{2, 1, 7}
	header := envelope.ControlHeader{
		SignerDID:             "did:test:determinism",
		AuthorityPath:         sameSigner(),
		EventTime:             1700000000,
		DomainManifestVersion: &ver,
	}
	e1, _ := envelope.NewEntry(header, []byte("{}"))
	e2, _ := envelope.NewEntry(header, []byte("{}"))
	if crypto.CanonicalHash(e1) != crypto.CanonicalHash(e2) {
		t.Error("canonical hash not deterministic")
	}
}

func TestV5_AuthoritySkipIsolatedFromAdmissionProof(t *testing.T) {
	t.Parallel()
	// Admission proof's length-prefixed body must not corrupt Authority_Skip
	// parsing, regardless of admission proof contents.
	skip := types.LogPosition{LogDID: "did:anchor", Sequence: 100}
	commit := [32]byte{1, 2, 3, 4}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}

	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:test:isolation",
		EventTime: 1700000000,
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:            2,
			Difficulty:      20,
			HashFunc:        1,
			Epoch:           1234,
			SubmitterCommit: &commit,
			Nonce:           9876543210,
			Hash:            hash,
		},
		AuthoritySkip: &skip,
	}, []byte("{}"))
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	round, err := envelope.Deserialize(envelope.Serialize(entry))
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if round.Header.AuthoritySkip == nil || !round.Header.AuthoritySkip.Equal(skip) {
		t.Errorf("AuthoritySkip: got %v, want %v", round.Header.AuthoritySkip, skip)
	}
	if round.Header.AdmissionProof == nil {
		t.Fatal("AdmissionProof: got nil")
	}
	if round.Header.AdmissionProof.Epoch != 1234 {
		t.Errorf("AdmissionProof.Epoch = %d, want 1234", round.Header.AdmissionProof.Epoch)
	}
}

func TestV5_RejectsUnknownVersion(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 0, 10)
	buf = binary.BigEndian.AppendUint16(buf, 99)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	_, err := envelope.Deserialize(buf)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("Deserialize(v99) = %v, want ErrUnknownVersion", err)
	}
}

func TestV5_OversizedPayloadRejected(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, envelope.MaxCanonicalBytes+1)
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:test",
		EventTime: 1700000000,
	}, oversized)
	if !errors.Is(err, envelope.ErrCanonicalTooLarge) {
		t.Errorf("oversized = %v, want ErrCanonicalTooLarge", err)
	}
}

func TestV5_EmptySignerDIDRejected(t *testing.T) {
	t.Parallel()
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "",
		EventTime: 1700000000,
	}, nil)
	if !errors.Is(err, envelope.ErrEmptySignerDID) {
		t.Errorf("empty DID = %v, want ErrEmptySignerDID", err)
	}
}

func TestV5_NonASCIISignerDIDRejected(t *testing.T) {
	t.Parallel()
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:test:\x80",
		EventTime: 1700000000,
	}, nil)
	if !errors.Is(err, envelope.ErrNonASCIIDID) {
		t.Errorf("non-ASCII DID = %v, want ErrNonASCIIDID", err)
	}
}
func TestV5_TooManyEvidencePointers(t *testing.T) {
	t.Parallel()
	pointers := make([]types.LogPosition, envelope.MaxEvidencePointers+1)
	for i := range pointers {
		pointers[i] = types.LogPosition{LogDID: "did:web:evidence", Sequence: uint64(i + 1)}
	}
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:        "did:test:evcap",
		EventTime:        1700000000,
		EvidencePointers: pointers,
	}, nil)
	if !errors.Is(err, envelope.ErrTooManyEvidencePointers) {
		t.Errorf("too many evidence pointers = %v, want ErrTooManyEvidencePointers", err)
	}
}

func TestV5_ShortPreambleRejected(t *testing.T) {
	t.Parallel()
	_, err := envelope.Deserialize([]byte{0x00, 0x04, 0x00}) // 3 bytes < 6
	if !errors.Is(err, envelope.ErrMalformedPreamble) {
		t.Errorf("short preamble = %v, want ErrMalformedPreamble", err)
	}
}
