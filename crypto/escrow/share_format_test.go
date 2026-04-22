// Package escrow — share_format_test.go tests the share wire format:
// Serialize/Deserialize round-trip, size/offset invariants, the internal
// zeroArray32 predicate, and rejection of malformed inputs.
package escrow

import (
	"bytes"
	"errors"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// Wire format invariants
// -------------------------------------------------------------------------------------------------

func TestShareFormat_WireLenIs131(t *testing.T) {
	if ShareWireLen != 131 {
		t.Fatalf("ShareWireLen = %d, want 131", ShareWireLen)
	}
}

func TestShareFormat_OffsetsSumTo131(t *testing.T) {
	// The layout is: Version(1) + Threshold(1) + Index(1) + Value(32) +
	// BlindingFactor(32) + CommitmentHash(32) + SplitID(32) = 131.
	if offsetSplitID+32 != ShareWireLen {
		t.Fatalf("offsetSplitID+32 = %d, want %d", offsetSplitID+32, ShareWireLen)
	}
	// Per-field contiguity checks.
	if offsetThreshold != offsetVersion+1 {
		t.Fatalf("offsetThreshold = %d, want %d", offsetThreshold, offsetVersion+1)
	}
	if offsetIndex != offsetThreshold+1 {
		t.Fatalf("offsetIndex = %d, want %d", offsetIndex, offsetThreshold+1)
	}
	if offsetValue != offsetIndex+1 {
		t.Fatalf("offsetValue = %d, want %d", offsetValue, offsetIndex+1)
	}
	if offsetBlindingFactor != offsetValue+32 {
		t.Fatalf("offsetBlindingFactor = %d, want %d", offsetBlindingFactor, offsetValue+32)
	}
	if offsetCommitmentHash != offsetBlindingFactor+32 {
		t.Fatalf("offsetCommitmentHash = %d, want %d", offsetCommitmentHash, offsetBlindingFactor+32)
	}
	if offsetSplitID != offsetCommitmentHash+32 {
		t.Fatalf("offsetSplitID = %d, want %d", offsetSplitID, offsetCommitmentHash+32)
	}
}

// -------------------------------------------------------------------------------------------------
// Serialize / Deserialize round-trip
// -------------------------------------------------------------------------------------------------

func TestShareFormat_SerializeRoundTrip(t *testing.T) {
	original := validV1Share(1, 3)
	wire, err := SerializeShare(original)
	if err != nil {
		t.Fatalf("SerializeShare: %v", err)
	}
	if len(wire) != ShareWireLen {
		t.Fatalf("serialized len = %d, want %d", len(wire), ShareWireLen)
	}

	decoded, err := DeserializeShare(wire)
	if err != nil {
		t.Fatalf("DeserializeShare: %v", err)
	}

	if decoded.Version != original.Version {
		t.Fatalf("Version mismatch: got 0x%02x, want 0x%02x", decoded.Version, original.Version)
	}
	if decoded.Threshold != original.Threshold {
		t.Fatalf("Threshold mismatch: got %d, want %d", decoded.Threshold, original.Threshold)
	}
	if decoded.Index != original.Index {
		t.Fatalf("Index mismatch: got %d, want %d", decoded.Index, original.Index)
	}
	if !bytes.Equal(decoded.Value[:], original.Value[:]) {
		t.Fatal("Value mismatch")
	}
	if !bytes.Equal(decoded.SplitID[:], original.SplitID[:]) {
		t.Fatal("SplitID mismatch")
	}
	if !bytes.Equal(decoded.BlindingFactor[:], original.BlindingFactor[:]) {
		t.Fatal("BlindingFactor mismatch")
	}
	if !bytes.Equal(decoded.CommitmentHash[:], original.CommitmentHash[:]) {
		t.Fatal("CommitmentHash mismatch")
	}
}

func TestShareFormat_SerializePopulatesOffsets(t *testing.T) {
	s := validV1Share(7, 5)
	wire, err := SerializeShare(s)
	if err != nil {
		t.Fatalf("SerializeShare: %v", err)
	}
	if wire[offsetVersion] != VersionV1 {
		t.Fatalf("wire[offsetVersion] = 0x%02x, want 0x%02x", wire[offsetVersion], VersionV1)
	}
	if wire[offsetThreshold] != 5 {
		t.Fatalf("wire[offsetThreshold] = %d, want 5", wire[offsetThreshold])
	}
	if wire[offsetIndex] != 7 {
		t.Fatalf("wire[offsetIndex] = %d, want 7", wire[offsetIndex])
	}
}

// -------------------------------------------------------------------------------------------------
// Serialize rejects malformed shares (validation-before-encoding)
// -------------------------------------------------------------------------------------------------

func TestShareFormat_SerializeRejectsInvalidVersion(t *testing.T) {
	s := validV1Share(1, 3)
	s.Version = 0xFF // not V1, not V2
	_, err := SerializeShare(s)
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

func TestShareFormat_SerializeRejectsZeroSplitID(t *testing.T) {
	s := validV1Share(1, 3)
	s.SplitID = [32]byte{} // zero
	_, err := SerializeShare(s)
	if !errors.Is(err, ErrSplitIDMissing) {
		t.Fatalf("expected ErrSplitIDMissing, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// Deserialize rejects wrong-size inputs
// -------------------------------------------------------------------------------------------------

func TestShareFormat_DeserializeRejectsShortInput(t *testing.T) {
	_, err := DeserializeShare(make([]byte, ShareWireLen-1))
	if err == nil {
		t.Fatal("expected error for short input, got nil")
	}
}

func TestShareFormat_DeserializeRejectsLongInput(t *testing.T) {
	_, err := DeserializeShare(make([]byte, ShareWireLen+1))
	if err == nil {
		t.Fatal("expected error for long input, got nil")
	}
}

func TestShareFormat_DeserializeRejectsEmpty(t *testing.T) {
	_, err := DeserializeShare(nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// Deserialize validates after decoding
// -------------------------------------------------------------------------------------------------

func TestShareFormat_DeserializeRejectsUnsupportedVersion(t *testing.T) {
	wire := make([]byte, ShareWireLen)
	wire[offsetVersion] = 0xFF
	wire[offsetThreshold] = 3
	wire[offsetIndex] = 1
	// Set a non-zero SplitID so we don't hit ErrSplitIDMissing first.
	for i := 0; i < 32; i++ {
		wire[offsetSplitID+i] = 0xAB
	}
	_, err := DeserializeShare(wire)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got: %v", err)
	}
}

func TestShareFormat_DeserializeRejectsV2(t *testing.T) {
	// V1 readers reject V2 until V2 ships.
	wire := make([]byte, ShareWireLen)
	wire[offsetVersion] = VersionV2
	wire[offsetThreshold] = 3
	wire[offsetIndex] = 1
	for i := 0; i < 32; i++ {
		wire[offsetSplitID+i] = 0xCD
	}
	_, err := DeserializeShare(wire)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion for V2 share, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// zeroArray32 (internal predicate)
// -------------------------------------------------------------------------------------------------

func TestShareFormat_ZeroArray32AllZero(t *testing.T) {
	var b [32]byte
	if !zeroArray32(b) {
		t.Fatal("zeroArray32([32]byte{}) = false, want true")
	}
}

func TestShareFormat_ZeroArray32FirstByteNonZero(t *testing.T) {
	var b [32]byte
	b[0] = 1
	if zeroArray32(b) {
		t.Fatal("zeroArray32 with b[0]=1 = true, want false")
	}
}

func TestShareFormat_ZeroArray32LastByteNonZero(t *testing.T) {
	var b [32]byte
	b[31] = 1
	if zeroArray32(b) {
		t.Fatal("zeroArray32 with b[31]=1 = true, want false")
	}
}
