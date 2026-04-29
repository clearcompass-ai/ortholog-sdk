/*
Package log — otel_transport.go provides an OpenTelemetry tracing
wrapper for any http.RoundTripper.

Design:

	OTelTransport.RoundTrip starts a CLIENT span, delegates to the
	wrapped Inner, records status / error, and ends the span. Spans
	are emitted to whatever TracerProvider the consumer's application
	configures globally (or the one provided in cfg.Tracer).

Composition:

	Stack with RetryAfterRoundTripper to get per-attempt spans:

	    traced := WithOTel(&RetryAfterRoundTripper{Inner: DefaultTransport()})
	    client := &http.Client{Transport: traced}

	Stack the OTel wrapper OUTSIDE the retry middleware so each
	retry attempt produces its own span — the operator's
	backpressure pattern shows up directly in traces.

Why not import otelhttp:

	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp
	would also work, but it pulls a heavier import surface
	(propagation, semconv, contrib metrics) that the SDK does not
	need. This 100-line wrapper covers the SDK's spans cleanly and
	keeps the dependency footprint small.
*/
package log

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation name registered with the
// global TracerProvider. Stable identifier so consumers can wire
// per-instrumentation sampling policies if they want.
const tracerName = "ortholog-sdk/log"

// OTelTransport wraps any http.RoundTripper with OTel client
// spans. Stateless and goroutine-safe.
type OTelTransport struct {
	// Inner is the wrapped RoundTripper. nil → http.DefaultTransport.
	Inner http.RoundTripper

	// Tracer is the OTel Tracer used to start spans. nil →
	// otel.Tracer(tracerName) on each call (fast — global lookup).
	Tracer trace.Tracer
}

// WithOTel wraps rt in an OTelTransport using the global Tracer.
// Convenience constructor for the common case.
func WithOTel(rt http.RoundTripper) http.RoundTripper {
	return &OTelTransport{Inner: rt}
}

// RoundTrip executes req under an OTel CLIENT span.
//
// Span lifetime:
//   - Started before delegating to Inner.
//   - Ended in a defer so the span closes even if Inner panics.
//   - Status set to Error on transport failures and 5xx responses.
//
// The defer-ended pattern means span duration captures the full
// roundtrip including connection establishment, TLS handshake,
// headers, and body upload — but NOT body download (the caller
// reads the body after RoundTrip returns).
func (t *OTelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tracer := t.Tracer
	if tracer == nil {
		tracer = otel.Tracer(tracerName)
	}

	ctx, span := tracer.Start(req.Context(),
		spanNameFor(req),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.method", req.Method),
			attribute.String("http.url", trimQuery(req.URL.String())),
			attribute.String("net.peer.name", req.URL.Host),
		),
	)
	defer span.End()

	// Propagate the span context to Inner so child spans (e.g., DNS
	// lookup hooks) attach correctly.
	req = req.WithContext(ctx)

	inner := t.Inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	resp, err := inner.RoundTrip(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		// 5xx: server-side fault. Mark span Error so trace UIs
		// surface it without the consumer parsing status codes.
		span.SetStatus(codes.Error, resp.Status)
	}
	// 4xx is intentionally NOT marked Error — those are client-side
	// classifications (auth, validation), not span failures.
	return resp, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// spanNameFor produces a low-cardinality span name "HTTP {METHOD} {path}".
// Strips query string so high-cardinality query params (sequence
// numbers, search terms) don't blow up trace storage.
func spanNameFor(req *http.Request) string {
	if req.URL == nil {
		return "HTTP " + req.Method
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	return "HTTP " + req.Method + " " + path
}

// trimQuery returns the URL with its query string and fragment
// removed. Pre-empts trace exporters that index http.url and would
// otherwise cardinality-blow on per-request query strings.
func trimQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return s
}
