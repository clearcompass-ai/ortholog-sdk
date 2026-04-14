package schema

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type SchemaParameterExtractor interface {
	Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error)
}
