/*
Package monitoring — types.go defines the shared alert vocabulary for the
Ortholog protocol.

Pure types. Zero logic. Zero imports beyond standard library.

Every domain application (judicial, recording, credentialing) and the
operator produce Alert structs. The operator's engine consumes them.
This package defines only the vocabulary — no interfaces, no engine,
no lifecycle, no goroutines.

Follows the types/ pattern: zero logic, zero external imports.
*/
package monitoring

import "time"

// Severity classifies alert urgency.
type Severity uint8

const (
	Info Severity = iota
	Warning
	Critical
)

// Destination controls where an alert is routed.
type Destination uint8

const (
	Log  Destination = 1 << iota // BuildCommentary on the main log
	Ops                          // Structured log / metrics / PagerDuty
	Both = Log | Ops
)

// MonitorID uniquely identifies a registered monitor.
type MonitorID string

// Alert is the universal alert structure emitted by all monitors.
// Every domain application and the operator produce these.
type Alert struct {
	Monitor     MonitorID
	Severity    Severity
	Destination Destination
	Message     string
	Details     map[string]any
	EmittedAt   time.Time
}
