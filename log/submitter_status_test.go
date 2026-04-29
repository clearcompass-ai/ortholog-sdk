package log

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// drainAndClose
// ─────────────────────────────────────────────────────────────────────

// trackingBody records whether Read and Close were called.
type trackingBody struct {
	io.Reader
	closed   bool
	readEOF  bool
	failRead bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	if b.failRead {
		return 0, errors.New("synthetic read error")
	}
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		b.readEOF = true
	}
	return n, err
}
func (b *trackingBody) Close() error { b.closed = true; return nil }

func TestDrainAndClose_NilSafe(t *testing.T) {
	drainAndClose(nil)
	drainAndClose(&http.Response{Body: nil})
}

func TestDrainAndClose_ShortBody(t *testing.T) {
	tb := &trackingBody{Reader: strings.NewReader("hello")}
	resp := &http.Response{Body: tb}
	drainAndClose(resp)
	if !tb.closed {
		t.Error("body not closed")
	}
	if !tb.readEOF {
		t.Error("body not drained to EOF")
	}
}

func TestDrainAndClose_LongBodyCappedByLimit(t *testing.T) {
	// Body is 8 KiB, drain cap is 4 KiB. The limit reader hits its
	// cap and returns; Close still runs. Without the cap, a
	// malicious operator could pin the client by streaming GBs.
	huge := strings.Repeat("x", maxDrainBytes*2)
	tb := &trackingBody{Reader: strings.NewReader(huge)}
	resp := &http.Response{Body: tb}
	drainAndClose(resp)
	if !tb.closed {
		t.Error("body not closed under cap")
	}
}

func TestDrainAndClose_ReadErrorIgnored(t *testing.T) {
	tb := &trackingBody{Reader: strings.NewReader(""), failRead: true}
	resp := &http.Response{Body: tb}
	// Must not panic; close should still run.
	drainAndClose(resp)
	if !tb.closed {
		t.Error("body not closed after read error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// readBodySnippet
// ─────────────────────────────────────────────────────────────────────

func TestReadBodySnippet_Nil(t *testing.T) {
	if got := readBodySnippet(nil); got != "" {
		t.Errorf("nil reader → %q, want empty", got)
	}
}

func TestReadBodySnippet_Small(t *testing.T) {
	r := strings.NewReader("  hello world  \n")
	if got := readBodySnippet(r); got != "hello world" {
		t.Errorf("got %q, want trimmed", got)
	}
}

func TestReadBodySnippet_Truncated(t *testing.T) {
	huge := strings.Repeat("a", maxErrBodyBytes+100)
	r := strings.NewReader(huge)
	got := readBodySnippet(r)
	if len(got) > maxErrBodyBytes {
		t.Errorf("len=%d > maxErrBodyBytes=%d", len(got), maxErrBodyBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────
// isStampRejection
// ─────────────────────────────────────────────────────────────────────

func TestIsStampRejection_Marker(t *testing.T) {
	if !isStampRejection("entry 0: stamp verification failed: difficulty mismatch") {
		t.Error("marker present, want true")
	}
}

func TestIsStampRejection_Absent(t *testing.T) {
	if isStampRejection("destination mismatch: did:key:zX != did:key:zY") {
		t.Error("marker absent, want false")
	}
}

func TestIsStampRejection_Empty(t *testing.T) {
	if isStampRejection("") {
		t.Error("empty body, want false")
	}
}

// ─────────────────────────────────────────────────────────────────────
// mapStatusToError
// ─────────────────────────────────────────────────────────────────────

func TestMapStatusToError_2xxNil(t *testing.T) {
	for _, s := range []int{200, 202, 204} {
		if err := mapStatusToError(s, ""); err != nil {
			t.Errorf("status %d → %v, want nil", s, err)
		}
	}
}

func TestMapStatusToError_TypedMappings(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{401, "auth", ErrUnauthorized},
		{402, "no credits", ErrInsufficientCredits},
		{403, "stamp verification failed: nope", ErrStampRejected},
		{409, "dup", ErrDuplicateEntry},
		{413, "huge", ErrEntryTooLarge},
		{422, "bad shape", ErrValidation},
		{503, "busy", ErrServiceUnavailable},
	}
	for _, tc := range cases {
		err := mapStatusToError(tc.status, tc.body)
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d → %v, want %v", tc.status, err, tc.want)
		}
		if !strings.Contains(err.Error(), tc.body) {
			t.Errorf("status %d body not in error: %v", tc.status, err)
		}
	}
}

func TestMapStatusToError_403WithoutStampMarker(t *testing.T) {
	err := mapStatusToError(403, "destination mismatch")
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("got %v, want *HTTPError", err)
	}
	if he.StatusCode != 403 {
		t.Errorf("StatusCode=%d", he.StatusCode)
	}
	if errors.Is(err, ErrStampRejected) {
		t.Error("non-stamp 403 must not match ErrStampRejected")
	}
}

func TestMapStatusToError_UnmappedStatus(t *testing.T) {
	err := mapStatusToError(418, "teapot")
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("got %v, want *HTTPError", err)
	}
	if he.StatusCode != 418 {
		t.Errorf("StatusCode=%d", he.StatusCode)
	}
}

// ─────────────────────────────────────────────────────────────────────
// statusToTypedSentinel
// ─────────────────────────────────────────────────────────────────────

func TestStatusToTypedSentinel_Sentinel(t *testing.T) {
	got := statusToTypedSentinel(402, "x")
	if got != ErrInsufficientCredits {
		t.Errorf("got %v, want ErrInsufficientCredits", got)
	}
}

func TestStatusToTypedSentinel_HTTPError(t *testing.T) {
	got := statusToTypedSentinel(418, "x")
	if _, ok := got.(*HTTPError); !ok {
		t.Errorf("got %T, want *HTTPError", got)
	}
}

func TestStatusToTypedSentinel_2xxNil(t *testing.T) {
	if got := statusToTypedSentinel(200, ""); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// stampFailedMarker pin
// ─────────────────────────────────────────────────────────────────────

func TestStampFailedMarker_Pinned(t *testing.T) {
	// This must EXACTLY match the substring written by
	// ortholog-operator/api/submission.go::Step 7. Drift here
	// silently disables the 403-cache-bust retry path.
	if stampFailedMarker != "stamp verification failed:" {
		t.Errorf("stampFailedMarker drifted: %q", stampFailedMarker)
	}
}
