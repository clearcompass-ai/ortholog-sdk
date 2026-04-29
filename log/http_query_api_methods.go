/*
Package log — http_query_api_methods.go ships the five query
methods that HTTPOperatorQueryAPI implements.
*/
package log

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Position-keyed queries
// ─────────────────────────────────────────────────────────────────────

// QueryByCosignatureOf hits GET /v1/query/cosignature_of/{pos}.
// Returns entries whose Header.CosignatureOf points to pos.
func (q *HTTPOperatorQueryAPI) QueryByCosignatureOf(
	pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(context.Background(), "cosignature_of", pos)
}

// QueryByCosignatureOfCtx is the ctx-aware variant. Public callers
// who hold a context should prefer this; the bare interface method
// uses background ctx for compatibility with OperatorQueryAPI.
func (q *HTTPOperatorQueryAPI) QueryByCosignatureOfCtx(
	ctx context.Context, pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(ctx, "cosignature_of", pos)
}

// QueryByTargetRoot hits GET /v1/query/target_root/{pos}.
func (q *HTTPOperatorQueryAPI) QueryByTargetRoot(
	pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(context.Background(), "target_root", pos)
}

// QueryByTargetRootCtx is the ctx-aware variant.
func (q *HTTPOperatorQueryAPI) QueryByTargetRootCtx(
	ctx context.Context, pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(ctx, "target_root", pos)
}

// QueryBySchemaRef hits GET /v1/query/schema_ref/{pos}.
func (q *HTTPOperatorQueryAPI) QueryBySchemaRef(
	pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(context.Background(), "schema_ref", pos)
}

// QueryBySchemaRefCtx is the ctx-aware variant.
func (q *HTTPOperatorQueryAPI) QueryBySchemaRefCtx(
	ctx context.Context, pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	return q.queryByPosition(ctx, "schema_ref", pos)
}

// queryByPosition is the shared dispatcher for the three
// position-keyed endpoints.
func (q *HTTPOperatorQueryAPI) queryByPosition(
	ctx context.Context, field string, pos types.LogPosition,
) ([]types.EntryWithMetadata, error) {
	if pos.LogDID == "" || pos.Sequence == 0 {
		// pos.Sequence == 0 isn't strictly invalid (the genesis
		// entry has seq=0) but is rare; allow it through and let
		// the operator decide.
	}
	path := fmt.Sprintf("/v1/query/%s/%s", field, encodePosition(pos))
	resp, err := q.doGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("log/query: %s: %w", field, err)
	}
	return q.toEntries(resp.Entries), nil
}

// ─────────────────────────────────────────────────────────────────────
// SignerDID query
// ─────────────────────────────────────────────────────────────────────

// QueryBySignerDID hits GET /v1/query/signer_did/{did}.
// did must be non-empty.
func (q *HTTPOperatorQueryAPI) QueryBySignerDID(
	did string,
) ([]types.EntryWithMetadata, error) {
	return q.QueryBySignerDIDCtx(context.Background(), did)
}

// QueryBySignerDIDCtx is the ctx-aware variant.
func (q *HTTPOperatorQueryAPI) QueryBySignerDIDCtx(
	ctx context.Context, did string,
) ([]types.EntryWithMetadata, error) {
	if did == "" {
		return nil, fmt.Errorf("log/query: signer_did: empty DID")
	}
	path := "/v1/query/signer_did/" + url.PathEscape(did)
	resp, err := q.doGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("log/query: signer_did: %w", err)
	}
	return q.toEntries(resp.Entries), nil
}

// ─────────────────────────────────────────────────────────────────────
// ScanFromPosition (flat-offset pagination)
// ─────────────────────────────────────────────────────────────────────

// ScanFromPosition hits GET /v1/query/scan?start=N&count=M.
// Consumers track lastSeq+1 for the next page; the SDK does not
// embed cursor state.
//
// count <= 0 → operator's DefaultScanCount applies (no validation
// here). count > MaxScanCount on the operator side is silently
// capped.
func (q *HTTPOperatorQueryAPI) ScanFromPosition(
	startPos uint64, count int,
) ([]types.EntryWithMetadata, error) {
	return q.ScanFromPositionCtx(context.Background(), startPos, count)
}

// ScanFromPositionCtx is the ctx-aware variant.
func (q *HTTPOperatorQueryAPI) ScanFromPositionCtx(
	ctx context.Context, startPos uint64, count int,
) ([]types.EntryWithMetadata, error) {
	v := url.Values{}
	v.Set("start", strconv.FormatUint(startPos, 10))
	if count > 0 {
		v.Set("count", strconv.Itoa(count))
	}
	path := "/v1/query/scan?" + v.Encode()
	resp, err := q.doGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("log/query: scan: %w", err)
	}
	return q.toEntries(resp.Entries), nil
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time interface assertion
// ─────────────────────────────────────────────────────────────────────

// Pin: any drift in OperatorQueryAPI's method set breaks the build.
var _ OperatorQueryAPI = (*HTTPOperatorQueryAPI)(nil)
