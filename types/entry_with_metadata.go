package types

import "time"

type EntryWithMetadata struct {
	CanonicalBytes []byte
	LogTime        time.Time
	Position       LogPosition
	SignatureAlgoID uint16
	SignatureBytes  []byte
}
