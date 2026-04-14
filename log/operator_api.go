package log

import "github.com/clearcompass-ai/ortholog-sdk/types"

type OperatorQueryAPI interface {
	QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
	QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error)
	ScanFromPosition(startPos uint64, count int) ([]types.EntryWithMetadata, error)
}
