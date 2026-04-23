package crypto

import (
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLengthPrefixed_BoundaryShift pins the load-bearing property that
// LengthPrefixed exists to provide: distinct (dst, fields...) tuples
// that would raw-concatenate to the same byte sequence produce
// distinct digests. This is the boundary-shifting attack the
// universal length-prefix rule exists to prevent.
func TestLengthPrefixed_BoundaryShift(t *testing.T) {
	a := LengthPrefixed("DA", []byte("lice"))
	b := LengthPrefixed("D", []byte("Alice"))
	if a == b {
		t.Fatalf("boundary-shift collision: LengthPrefixed(\"DA\",\"lice\") == LengthPrefixed(\"D\",\"Alice\")\n  digest: %x", a)
	}
}

type lengthPrefixedVector struct {
	Name         string   `json:"name"`
	DST          string   `json:"dst"`
	FieldsHex    []string `json:"fields_hex"`
	ExpectedHex  string   `json:"expected_hex"`
	// PRE-specific metadata:
	GrantorDID     string `json:"grantor_did"`
	RecipientDID   string `json:"recipient_did"`
	ArtifactCIDHex string `json:"artifact_cid_hex"`
}

type lengthPrefixedVectorFile struct {
	Vectors []lengthPrefixedVector `json:"vectors"`
}

// TestLengthPrefixed_GoldenVectors locks four pinned 32-byte digests.
// Any change to the LengthPrefixed encoding rule or to the output of
// SHA-256 on the pinned inputs fails this test. Cross-implementation
// ports consume the same fixture file.
func TestLengthPrefixed_GoldenVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "length_prefixed_vectors.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx lengthPrefixedVectorFile
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Vectors) < 4 {
		t.Fatalf("expected >=4 golden vectors, got %d", len(fx.Vectors))
	}

	for _, v := range fx.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var fields [][]byte
			if v.Name == "pre_grant_canonical" {
				cid, err := hex.DecodeString(v.ArtifactCIDHex)
				if err != nil {
					t.Fatalf("decode cid: %v", err)
				}
				fields = [][]byte{
					[]byte(v.GrantorDID),
					[]byte(v.RecipientDID),
					cid,
				}
			} else {
				for i, fh := range v.FieldsHex {
					b, err := hex.DecodeString(fh)
					if err != nil {
						t.Fatalf("decode field %d: %v", i, err)
					}
					fields = append(fields, b)
				}
			}
			got := LengthPrefixed(v.DST, fields...)
			if hex.EncodeToString(got[:]) != v.ExpectedHex {
				t.Fatalf("digest mismatch\n  got:  %x\n  want: %s", got[:], v.ExpectedHex)
			}
		})
	}
}

// TestLengthPrefixed_DSTIsLengthPrefixed is an independent check that
// moving a byte from the tail of the DST to the head of the first
// field changes the digest. That property falls directly out of
// length-prefixing the DST; omitting the DST length prefix would make
// ("DA", "lice") and ("D", "Alice") collide.
func TestLengthPrefixed_DSTIsLengthPrefixed(t *testing.T) {
	a := LengthPrefixed("ORTHOLOG-TEST", []byte("field"))
	b := LengthPrefixed("ORTHOLOG-TES", []byte("Tfield"))
	if a == b {
		t.Fatalf("DST length-prefix is not load-bearing: ('ORTHOLOG-TEST','field') collides with ('ORTHOLOG-TES','Tfield')")
	}
}

// TestLengthPrefixed_FieldOrderMatters pins that field ordering is part
// of the canonical encoding. Swapping two fields changes the digest.
func TestLengthPrefixed_FieldOrderMatters(t *testing.T) {
	a := LengthPrefixed("DST", []byte("alpha"), []byte("beta"))
	b := LengthPrefixed("DST", []byte("beta"), []byte("alpha"))
	if a == b {
		t.Fatalf("field order not load-bearing: swapping alpha/beta produced same digest")
	}
}

// TestLengthPrefixed_OversizeFieldPanics confirms the 65535-byte
// bound on each length-prefixed component. A caller passing a
// >65KB field is broken and we surface that loudly at the helper,
// not silently as a truncated length prefix.
func TestLengthPrefixed_OversizeFieldPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on oversize field, got none")
		}
	}()
	oversize := make([]byte, 1<<16)
	_ = LengthPrefixed("DST", oversize)
}

// TestLengthPrefixed_RFCCarveoutDocumented parses the crypto/hash.go
// source and verifies the godoc on LengthPrefixed contains both the
// RFC 9380 carveout boundary statement and the explicit naming of
// Ortholog-bespoke tags as migration targets rather than as
// exceptions. This test fails if a future edit inverts the boundary
// or drops the named-target-vs-exception distinction.
//
// Load-bearing because the inverted wording would document a
// vulnerability as policy; the test exists to catch that class of
// error before it reaches review.
func TestLengthPrefixed_RFCCarveoutDocumented(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "hash.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse hash.go: %v", err)
	}
	var doc string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "LengthPrefixed" && fn.Doc != nil {
			doc = fn.Doc.Text()
			break
		}
	}
	if doc == "" {
		t.Fatal("LengthPrefixed godoc not found")
	}
	must := []string{
		// Orientation: IETF suite IDs are the exception.
		"RFC 9380",
		"hash-to-curve",
		"expand_message_xmd",
		// The one concrete example IETF suite ID the text must pin.
		"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
		// Ortholog-bespoke tags must be named as migration targets,
		// not carveouts, and must reference bls_verifier.go as the
		// migration site.
		"cosignature domain tag",
		"Proof-of-Possession",
		"bls_verifier.go",
		"migration targets",
	}
	for _, m := range must {
		if !strings.Contains(doc, m) {
			t.Fatalf("LengthPrefixed godoc missing required phrase %q\n--- doc ---\n%s", m, doc)
		}
	}
	// The godoc MUST NOT describe the Ortholog-bespoke tags as
	// exceptions. That wording would invert the boundary.
	forbidden := []string{
		"cosignature domain tag is an exception",
		"cosignature domain tag is a carveout",
		"PoP domain tag is an exception",
		"PoP domain tag is a carveout",
	}
	for _, bad := range forbidden {
		if strings.Contains(doc, bad) {
			t.Fatalf("LengthPrefixed godoc contains forbidden phrase %q — boundary is inverted", bad)
		}
	}
}
