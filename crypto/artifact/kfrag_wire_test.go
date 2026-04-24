package artifact

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// testKFragMinimal constructs a KFrag with deterministic field values
// suitable for round-trip and golden-vector assertions. RKShare=1 so
// VK=1·G, and BK is 2·G compressed.
func testKFragMinimal(t *testing.T, id byte) KFrag {
	t.Helper()
	c := secp256k1.S256()
	rk := big.NewInt(1)
	vkX, vkY := c.ScalarBaseMult(padBigInt(rk))
	two := make([]byte, 32)
	two[31] = 2
	bkX, bkY := c.ScalarBaseMult(two)
	var bk [KFragBKLen]byte
	copy(bk[:], compressedPoint(bkX, bkY))
	return KFrag{
		ID:      id,
		RKShare: rk,
		VKX:     vkX,
		VKY:     vkY,
		BK:      bk,
	}
}

// TestKFrag_SerializeWireFormat_196Bytes pins the fixed wire length.
// Any drift from 196 bytes is a cross-layer break with the CFrag
// length discriminator and with ADR-005 §5.
func TestKFrag_SerializeWireFormat_196Bytes(t *testing.T) {
	kf := testKFragMinimal(t, 7)
	wire, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(wire) != KFragWireLen {
		t.Fatalf("wire length = %d, want %d", len(wire), KFragWireLen)
	}
	if KFragWireLen != 196 {
		t.Fatalf("KFragWireLen = %d, want 196", KFragWireLen)
	}
}

// TestKFrag_LayoutOffsets pins each field's offset. A silent
// layout shift (for example, if someone reorders ID / RKShare) is
// caught here even if the total length happens to survive.
func TestKFrag_LayoutOffsets(t *testing.T) {
	kf := testKFragMinimal(t, 0x2A)
	wire, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if wire[kfragOffsetID] != 0x2A {
		t.Fatalf("ID byte = 0x%02x at offset %d, want 0x2A", wire[kfragOffsetID], kfragOffsetID)
	}
	// RKShare is big-endian padded 1. The last byte must be 1 and the
	// preceding 31 bytes zero.
	if wire[kfragOffsetRKShare+31] != 0x01 {
		t.Fatalf("RKShare last byte = 0x%02x, want 0x01", wire[kfragOffsetRKShare+31])
	}
	for i := 0; i < 31; i++ {
		if wire[kfragOffsetRKShare+i] != 0 {
			t.Fatalf("RKShare pad byte at offset %d = 0x%02x, want 0", kfragOffsetRKShare+i, wire[kfragOffsetRKShare+i])
		}
	}
	// VK compressed prefix must be 0x02 or 0x03.
	vkPfx := wire[kfragOffsetVK]
	if vkPfx != 0x02 && vkPfx != 0x03 {
		t.Fatalf("VK prefix 0x%02x, want 0x02 or 0x03", vkPfx)
	}
	bkPfx := wire[kfragOffsetBK]
	if bkPfx != 0x02 && bkPfx != 0x03 {
		t.Fatalf("BK prefix 0x%02x, want 0x02 or 0x03", bkPfx)
	}
	// Reserved zone must be zero.
	for i := 0; i < kfragReservedLen; i++ {
		if wire[kfragOffsetReserved+i] != 0 {
			t.Fatalf("reserved byte at offset %d nonzero", kfragOffsetReserved+i)
		}
	}
}

// TestKFrag_RoundTripSerialization covers Serialize→Deserialize equality
// for a range of IDs. Skips RKShare pointer equality (we round-trip
// on big.Int bytes, not pointer).
func TestKFrag_RoundTripSerialization(t *testing.T) {
	for _, id := range []byte{1, 2, 7, 42, 128, 255} {
		kf := testKFragMinimal(t, id)
		wire, err := SerializeKFrag(kf)
		if err != nil {
			t.Fatalf("Serialize id=%d: %v", id, err)
		}
		got, err := DeserializeKFrag(wire)
		if err != nil {
			t.Fatalf("Deserialize id=%d: %v", id, err)
		}
		if got.ID != kf.ID {
			t.Fatalf("ID mismatch: got %d want %d", got.ID, kf.ID)
		}
		if got.RKShare.Cmp(kf.RKShare) != 0 {
			t.Fatalf("RKShare mismatch id=%d", id)
		}
		if got.VKX.Cmp(kf.VKX) != 0 || got.VKY.Cmp(kf.VKY) != 0 {
			t.Fatalf("VK mismatch id=%d", id)
		}
		if got.BK != kf.BK {
			t.Fatalf("BK mismatch id=%d", id)
		}
	}
}

// TestKFrag_GoldenVector pins the exact wire bytes for a deterministic
// KFrag. Any change to the layout or to the compressed-point encoding
// of G and 2·G on secp256k1 fails here.
func TestKFrag_GoldenVector(t *testing.T) {
	kf := testKFragMinimal(t, 7)
	wire, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// ID=7, RKShare=1 (big-endian 32-byte pad), VK=compressed(G),
	// BK=compressed(2G), 97 zero bytes.
	const want = "0700000000000000000000000000000000000000000000000000000000000000010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	got := hex.EncodeToString(wire)
	if got != want {
		t.Fatalf("KFrag golden mismatch\n got:  %s\n want: %s", got, want)
	}
}

// TestKFrag_ReservedBytesNonZeroRejected_EachPosition sweeps every byte
// in the reserved zone and verifies that setting it non-zero causes
// DeserializeKFrag to reject via ErrKFragReservedBytesNonZero.
// This is the binding test for muEnableKFragReservedCheck.
func TestKFrag_ReservedBytesNonZeroRejected_EachPosition(t *testing.T) {
	kf := testKFragMinimal(t, 1)
	base, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	for i := 0; i < kfragReservedLen; i++ {
		tampered := make([]byte, len(base))
		copy(tampered, base)
		tampered[kfragOffsetReserved+i] = 0x01
		_, err := DeserializeKFrag(tampered)
		if err == nil {
			t.Fatalf("reserved byte %d non-zero: want error, got nil", kfragOffsetReserved+i)
		}
		if !errors.Is(err, ErrKFragReservedBytesNonZero) {
			t.Fatalf("reserved byte %d: want ErrKFragReservedBytesNonZero, got %v",
				kfragOffsetReserved+i, err)
		}
	}
}

// TestKFrag_ReservedBytesNonZeroRejected_SingleBit guards against an
// implementation that only spot-checks a single byte or only rejects
// 0xFF. A single-bit flip at one arbitrary offset must reject.
func TestKFrag_ReservedBytesNonZeroRejected_SingleBit(t *testing.T) {
	kf := testKFragMinimal(t, 3)
	base, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	tampered := make([]byte, len(base))
	copy(tampered, base)
	tampered[kfragOffsetReserved+50] = 0x01
	if _, err := DeserializeKFrag(tampered); !errors.Is(err, ErrKFragReservedBytesNonZero) {
		t.Fatalf("want ErrKFragReservedBytesNonZero, got %v", err)
	}
}

// TestKFrag_WrongLengthRejected pins the length check that
// discriminates v7.75 from any alternative wire length.
func TestKFrag_WrongLengthRejected(t *testing.T) {
	cases := []int{0, 1, 163, 195, 197, 1024}
	for _, n := range cases {
		buf := make([]byte, n)
		_, err := DeserializeKFrag(buf)
		if err == nil {
			t.Fatalf("len=%d: want error, got nil", n)
		}
		if !errors.Is(err, ErrInvalidKFragFormat) {
			t.Fatalf("len=%d: want ErrInvalidKFragFormat, got %v", n, err)
		}
	}
}

// TestKFrag_IDZeroRejected_Serialize and _Deserialize: ID=0 is the
// reserved sentinel for the polynomial-at-zero evaluation (= the
// secret). Every serializer and deserializer rejects it.
func TestKFrag_IDZeroRejected_Serialize(t *testing.T) {
	kf := testKFragMinimal(t, 0)
	if _, err := SerializeKFrag(kf); !errors.Is(err, ErrInvalidKFragFormat) {
		t.Fatalf("want ErrInvalidKFragFormat on ID=0, got %v", err)
	}
}

func TestKFrag_IDZeroRejected_Deserialize(t *testing.T) {
	kf := testKFragMinimal(t, 1)
	wire, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	wire[kfragOffsetID] = 0
	if _, err := DeserializeKFrag(wire); !errors.Is(err, ErrInvalidKFragFormat) {
		t.Fatalf("want ErrInvalidKFragFormat on ID=0, got %v", err)
	}
}

// TestKFrag_RKShareBounds rejects zero and overflow RKShare values.
func TestKFrag_RKShareBounds(t *testing.T) {
	kf := testKFragMinimal(t, 1)
	wire, err := SerializeKFrag(kf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// Zero RKShare: all 32 bytes of RKShare zero.
	zeroWire := make([]byte, len(wire))
	copy(zeroWire, wire)
	for i := 0; i < 32; i++ {
		zeroWire[kfragOffsetRKShare+i] = 0
	}
	if _, err := DeserializeKFrag(zeroWire); !errors.Is(err, ErrInvalidKFragFormat) {
		t.Fatalf("zero RKShare: want ErrInvalidKFragFormat, got %v", err)
	}
	// RKShare = 0xFF..FF (> curve order n).
	maxWire := make([]byte, len(wire))
	copy(maxWire, wire)
	for i := 0; i < 32; i++ {
		maxWire[kfragOffsetRKShare+i] = 0xFF
	}
	if _, err := DeserializeKFrag(maxWire); !errors.Is(err, ErrInvalidKFragFormat) {
		t.Fatalf("RKShare >= n: want ErrInvalidKFragFormat, got %v", err)
	}
}

// TestKFrag_SerializeMatchesGenerateKFrags asserts the wire format
// is consistent with a KFrag produced by PRE_GenerateKFrags. This
// prevents silent drift between the live primitive output and the
// synthetic test fixture above.
func TestKFrag_SerializeMatchesGenerateKFrags(t *testing.T) {
	c := secp256k1.S256()
	n := c.Params().N

	// Deterministic but valid sk/pk pair for the test.
	skOwner := padBigInt(new(big.Int).SetInt64(3))
	pkRx := func() []byte {
		rxSk := new(big.Int).SetInt64(7)
		rxX, rxY := c.ScalarBaseMult(padBigInt(rxSk))
		pk := make([]byte, 65)
		pk[0] = 0x04
		rxXb := rxX.Bytes()
		rxYb := rxY.Bytes()
		copy(pk[1+32-len(rxXb):33], rxXb)
		copy(pk[33+32-len(rxYb):], rxYb)
		return pk
	}()

	kfrags, _, err := PRE_GenerateKFrags(skOwner, pkRx, 2, 3)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	for _, kf := range kfrags {
		wire, err := SerializeKFrag(kf)
		if err != nil {
			t.Fatalf("SerializeKFrag: %v", err)
		}
		if len(wire) != KFragWireLen {
			t.Fatalf("wire length = %d, want %d", len(wire), KFragWireLen)
		}
		decoded, err := DeserializeKFrag(wire)
		if err != nil {
			t.Fatalf("DeserializeKFrag: %v", err)
		}
		if decoded.ID != kf.ID {
			t.Fatalf("ID mismatch: got %d want %d", decoded.ID, kf.ID)
		}
		if decoded.RKShare.Cmp(new(big.Int).Mod(kf.RKShare, n)) != 0 {
			t.Fatalf("RKShare mismatch on round trip")
		}
		if decoded.VKX.Cmp(kf.VKX) != 0 || decoded.VKY.Cmp(kf.VKY) != 0 {
			t.Fatalf("VK mismatch on round trip")
		}
		if decoded.BK != kf.BK {
			t.Fatalf("BK mismatch on round trip")
		}
	}
	_ = bytes.Equal // keep import stable
}
