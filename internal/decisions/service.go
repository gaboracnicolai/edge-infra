package decisions

import (
	"context"
	"errors"
	"io"
	"log/slog"

	accesslogdatav3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Appender adds records to the end of the decision log, in order.
// *store.PostgresStore satisfies it.
type Appender interface {
	AppendDecisions(ctx context.Context, recs []Record) error
}

// Service receives edge-egress's decisions: it implements Envoy's
// AccessLogService, and appends every HTTP entry sent under LogName.
type Service struct {
	accesslogv3.UnimplementedAccessLogServiceServer
	out Appender
	log *slog.Logger
}

// NewService returns a receiver that appends to out.
func NewService(out Appender, log *slog.Logger) *Service {
	return &Service{out: out, log: log}
}

// StreamAccessLogs appends each batch an Envoy sends, in the order it sends
// them. The stream's first message names the Envoy and the log. If a batch
// cannot be appended the stream ends with Unavailable; the Envoy opens a new
// one for its next batch.
func (s *Service) StreamAccessLogs(stream accesslogv3.AccessLogService_StreamAccessLogsServer) error {
	var node, logName string
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&accesslogv3.StreamAccessLogsResponse{})
		}
		if err != nil {
			return err
		}
		if id := msg.GetIdentifier(); id != nil {
			node, logName = id.GetNode().GetId(), id.GetLogName()
		}
		if logName != LogName {
			continue
		}
		entries := msg.GetHttpLogs().GetLogEntry()
		if len(entries) == 0 {
			continue
		}
		recs := make([]Record, 0, len(entries))
		for _, e := range entries {
			recs = append(recs, FromEntry(node, e))
		}
		if err := s.out.AppendDecisions(stream.Context(), recs); err != nil {
			s.log.Error("decision log: append failed; the batch is lost", "node", node, "records", len(recs), "err", err)
			return status.Error(codes.Unavailable, "decision log unavailable")
		}
	}
}

// FromEntry is the decision an Envoy access-log entry records.
func FromEntry(node string, e *accesslogdatav3.HTTPAccessLogEntry) Record {
	c, req, resp := e.GetCommonProperties(), e.GetRequest(), e.GetResponse()
	flags := c.GetResponseFlags()
	reason := resp.GetResponseCodeDetails()
	r := Record{
		Node:        node,
		Client:      c.GetDownstreamRemoteAddress().GetSocketAddress().GetAddress(),
		Decision:    Classify(flags.GetRateLimited(), flags.GetUnauthorizedDetails() != nil, reason),
		Status:      resp.GetResponseCode().GetValue(),
		Reason:      reason,
		Method:      req.GetRequestMethod().String(),
		Authority:   req.GetAuthority(),
		Path:        StripQuery(req.GetPath()),
		Destination: c.GetRouteName(),
		RequestID:   req.GetRequestId(),
	}
	if t := c.GetStartTime(); t != nil {
		r.Time = t.AsTime()
	}
	if md := c.GetMetadata().GetFilterMetadata()[AgentMetadataNamespace]; md != nil {
		r.Agent = md.GetFields()[AgentMetadataKey].GetStringValue()
	}
	return r
}
