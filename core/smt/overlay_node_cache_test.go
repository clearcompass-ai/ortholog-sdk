package smt

import (
	"bytes"
	"sync"
	"testing"
)

func TestOverlayNodeCache_NilBackingPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when backing is nil")
		}
	}()
	_ = NewOverlayNodeCache(nil)
}

func TestOverlayNodeCache_GetFallsThroughToBacking(t *testing.T) {
	backing := NewInMemoryNodeCache()
	key := [32]byte{0x01}
	backing.Set(key, []byte("from-backing"))

	overlay := NewOverlayNodeCache(backing)

	v, ok := overlay.Get(key)
	if !ok {
		t.Fatal("expected hit (via fallthrough)")
	}
	if !bytes.Equal(v, []byte("from-backing")) {
		t.Fatalf("got %q, want from-backing", v)
	}
}

func TestOverlayNodeCache_BufferWinsOverBacking(t *testing.T) {
	backing := NewInMemoryNodeCache()
	key := [32]byte{0x02}
	backing.Set(key, []byte("backing-value"))

	overlay := NewOverlayNodeCache(backing)
	overlay.Set(key, []byte("overlay-value"))

	v, ok := overlay.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if !bytes.Equal(v, []byte("overlay-value")) {
		t.Fatalf("got %q, want overlay-value", v)
	}
}

func TestOverlayNodeCache_SetDoesNotMutateBacking(t *testing.T) {
	backing := NewInMemoryNodeCache()
	key := [32]byte{0x03}

	overlay := NewOverlayNodeCache(backing)
	overlay.Set(key, []byte("only-in-overlay"))

	if _, ok := backing.Get(key); ok {
		t.Fatal("backing should not have received the write")
	}
}

func TestOverlayNodeCache_GetMissReturnsFalse(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())
	if _, ok := overlay.Get([32]byte{0xFF}); ok {
		t.Fatal("expected miss")
	}
}

func TestOverlayNodeCache_SetCopiesValue(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())
	key := [32]byte{0x04}
	src := []byte("original")
	overlay.Set(key, src)

	src[0] = 'X'

	v, _ := overlay.Get(key)
	if string(v) != "original" {
		t.Fatalf("buffer aliased input: got %q", v)
	}
}

func TestOverlayNodeCache_GetReturnsCopy(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())
	key := [32]byte{0x05}
	overlay.Set(key, []byte("stable"))

	v1, _ := overlay.Get(key)
	v1[0] = 'X'

	v2, _ := overlay.Get(key)
	if string(v2) != "stable" {
		t.Fatalf("Get aliased buffer: got %q", v2)
	}
}

func TestOverlayNodeCache_MutationsReturnsBufferedWrites(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())
	overlay.Set([32]byte{0x10}, []byte("a"))
	overlay.Set([32]byte{0x20}, []byte("b"))

	muts := overlay.Mutations()
	if len(muts) != 2 {
		t.Fatalf("expected 2 mutations, got %d", len(muts))
	}
	if !bytes.Equal(muts[[32]byte{0x10}], []byte("a")) {
		t.Fatal("missing/incorrect mutation for 0x10")
	}
	if !bytes.Equal(muts[[32]byte{0x20}], []byte("b")) {
		t.Fatal("missing/incorrect mutation for 0x20")
	}
}

func TestOverlayNodeCache_MutationsDoesNotIncludeBackingOnly(t *testing.T) {
	backing := NewInMemoryNodeCache()
	backing.Set([32]byte{0x01}, []byte("backing-only"))

	overlay := NewOverlayNodeCache(backing)
	overlay.Set([32]byte{0x02}, []byte("buffered"))

	muts := overlay.Mutations()
	if _, ok := muts[[32]byte{0x01}]; ok {
		t.Fatal("Mutations should not include backing-only entries")
	}
	if _, ok := muts[[32]byte{0x02}]; !ok {
		t.Fatal("Mutations should include buffered entry")
	}
}

func TestOverlayNodeCache_MutationsReturnsCopies(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())
	overlay.Set([32]byte{0x11}, []byte("x"))

	muts := overlay.Mutations()
	muts[[32]byte{0x11}][0] = 'Z'

	v, _ := overlay.Get([32]byte{0x11})
	if string(v) != "x" {
		t.Fatalf("Mutations returned aliased value: got %q", v)
	}
}

func TestOverlayNodeCache_ResetClearsBuffer(t *testing.T) {
	backing := NewInMemoryNodeCache()
	overlay := NewOverlayNodeCache(backing)
	overlay.Set([32]byte{0xAA}, []byte("buffered"))

	overlay.Reset()

	if _, ok := overlay.Get([32]byte{0xAA}); ok {
		t.Fatal("buffer should be empty after Reset")
	}
}

func TestOverlayNodeCache_ResetDoesNotTouchBacking(t *testing.T) {
	backing := NewInMemoryNodeCache()
	backing.Set([32]byte{0xBB}, []byte("backing"))
	overlay := NewOverlayNodeCache(backing)

	overlay.Reset()

	if v, ok := backing.Get([32]byte{0xBB}); !ok || string(v) != "backing" {
		t.Fatal("Reset must not modify backing")
	}
}

func TestOverlayNodeCache_SatisfiesNodeCacheInterface(t *testing.T) {
	var _ NodeCache = NewOverlayNodeCache(NewInMemoryNodeCache())
}

func TestOverlayNodeCache_ConcurrentReadWrite(t *testing.T) {
	overlay := NewOverlayNodeCache(NewInMemoryNodeCache())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			var k [32]byte
			k[0] = byte(n)
			overlay.Set(k, []byte{byte(n)})
		}(i)
		go func(n int) {
			defer wg.Done()
			var k [32]byte
			k[0] = byte(n)
			_, _ = overlay.Get(k)
		}(i)
	}
	wg.Wait()
}
