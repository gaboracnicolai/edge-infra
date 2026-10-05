// Package decisions is edge-egress's decision log (B28.228). Every request an
// edge-egress Envoy decides — sent on, refused, or refused for the agent's rate
// limit — becomes one record, and each record carries the hash of the one
// before it. An exported log therefore shows whether any record was changed,
// removed or reordered after it was written: the hash of line n is the sha256
// of its exact bytes, and line n+1 names it as its prev.
//
// The Envoys send their access-log entries to the control plane over gRPC
// (Envoy's AccessLogService, on the xDS connection they already hold), and the
// control plane appends them to the edge_decisions table.
package decisions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// LogName is the access-log name edge-egress sends its decisions under. The
// receiver records nothing else.
const LogName = "edge-decisions"

// AgentMetadataNamespace and AgentMetadataKey locate the agent in a request's
// dynamic metadata: the auth-service's agent mode emits the ServiceAccount the
// agent proved as ext_authz metadata, and the rate limit and this log read it.
const (
	AgentMetadataNamespace = "envoy.filters.http.ext_authz"
	AgentMetadataKey       = "agent"
)

// Genesis is the prev of the first record in the log.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// The decisions a record can carry.
const (
	Allowed     = "allowed"      // sent on to the destination, whatever it answered
	Denied      = "denied"       // refused by edge-egress (unlisted host, no agent token, CONNECT to a keyless host)
	RateLimited = "rate_limited" // refused because the agent was over its rate limit
)

// Record is one decision edge-egress made.
type Record struct {
	Time        time.Time
	Node        string // the edge-egress Envoy (its xDS node id)
	Agent       string // the ServiceAccount the agent proved; empty when it proved none
	Client      string // the address the request came from
	Decision    string
	Status      uint32 // the status the agent received
	Reason      string // Envoy's response code details, e.g. local_rate_limited
	Method      string
	Authority   string
	Path        string // without its query string, which can carry credentials
	Destination string // the egress route that matched
	RequestID   string
}

// line is a record as it is hashed and exported, in a fixed field order.
type line struct {
	Seq         int64  `json:"seq"`
	Prev        string `json:"prev"`
	Time        string `json:"time"`
	Node        string `json:"node"`
	Agent       string `json:"agent"`
	Client      string `json:"client"`
	Decision    string `json:"decision"`
	Status      uint32 `json:"status"`
	Reason      string `json:"reason"`
	Method      string `json:"method"`
	Authority   string `json:"authority"`
	Path        string `json:"path"`
	Destination string `json:"destination"`
	RequestID   string `json:"request_id"`
}

// Line renders r as record number seq of the log, chained to prev (the hash of
// record seq-1, or Genesis). The result is one line of JSON with no newline.
func (r Record) Line(seq int64, prev string) string {
	b, err := json.Marshal(line{
		Seq:         seq,
		Prev:        prev,
		Time:        r.Time.UTC().Format(time.RFC3339Nano),
		Node:        r.Node,
		Agent:       r.Agent,
		Client:      r.Client,
		Decision:    r.Decision,
		Status:      r.Status,
		Reason:      r.Reason,
		Method:      r.Method,
		Authority:   r.Authority,
		Path:        r.Path,
		Destination: r.Destination,
		RequestID:   r.RequestID,
	})
	if err != nil {
		// Every field is a string, a number or a time: Marshal cannot fail.
		panic("decisions: marshal record: " + err.Error())
	}
	return string(b)
}

// Hash is a line's link in the chain: the hex sha256 of its bytes.
func Hash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

// Classify names the decision behind a response: rate_limited when the agent's
// rate limit refused it, denied when edge-egress answered it itself (the
// auth-service refused the agent, or the route is a refusal), allowed when it
// was sent on to the destination.
func Classify(rateLimited, unauthorized bool, reason string) string {
	switch {
	case rateLimited:
		return RateLimited
	case unauthorized, reason == "direct_response", strings.HasPrefix(reason, "ext_authz"):
		return Denied
	default:
		return Allowed
	}
}

// StripQuery returns path without its query string.
func StripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}
