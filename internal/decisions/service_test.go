package decisions

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogdatav3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeStream struct {
	grpc.ServerStream
	msgs []*accesslogv3.StreamAccessLogsMessage
}

func (f *fakeStream) Context() context.Context { return context.Background() }
func (f *fakeStream) Recv() (*accesslogv3.StreamAccessLogsMessage, error) {
	if len(f.msgs) == 0 {
		return nil, io.EOF
	}
	m := f.msgs[0]
	f.msgs = f.msgs[1:]
	return m, nil
}
func (f *fakeStream) SendAndClose(*accesslogv3.StreamAccessLogsResponse) error { return nil }

type fakeAppender struct{ batches [][]Record }

func (f *fakeAppender) AppendDecisions(_ context.Context, recs []Record) error {
	f.batches = append(f.batches, recs)
	return nil
}

func entry(status uint32, reason, agent, path string, flags *accesslogdatav3.ResponseFlags) *accesslogdatav3.HTTPAccessLogEntry {
	c := &accesslogdatav3.AccessLogCommon{
		StartTime:     timestamppb.New(time.Date(2026, 10, 6, 1, 2, 3, 0, time.UTC)),
		RouteName:     "mock-llm",
		ResponseFlags: flags,
		DownstreamRemoteAddress: &corev3.Address{Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{Address: "10.244.1.7"},
		}},
	}
	if agent != "" {
		md, _ := structpb.NewStruct(map[string]any{"agent": agent})
		c.Metadata = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy.filters.http.ext_authz": md}}
	}
	return &accesslogdatav3.HTTPAccessLogEntry{
		CommonProperties: c,
		Request: &accesslogdatav3.HTTPRequestProperties{
			RequestMethod: corev3.RequestMethod_GET, Authority: "llm.mock.test", Path: path, RequestId: "r-1",
		},
		Response: &accesslogdatav3.HTTPResponseProperties{
			ResponseCode: wrapperspb.UInt32(status), ResponseCodeDetails: reason,
		},
	}
}

// Every entry edge-egress sends under the decision log's name becomes a record
// naming the Envoy, the agent and the decision, in the order sent; entries
// under any other log name, or from any other Envoy, are not recorded.
func TestService_RecordsEgressDecisions(t *testing.T) {
	sa := "system:serviceaccount:agents:billing-bot"
	stream := &fakeStream{msgs: []*accesslogv3.StreamAccessLogsMessage{
		{
			Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{
				Node: &corev3.Node{Id: "edge-egress/pod-a"}, LogName: LogName,
			},
			LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*accesslogdatav3.HTTPAccessLogEntry{
					entry(200, "via_upstream", sa, "/v1/models?key=sk-1", nil),
					entry(429, "local_rate_limited", sa, "/v1/models", &accesslogdatav3.ResponseFlags{RateLimited: true}),
				},
			}},
		},
		{
			LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*accesslogdatav3.HTTPAccessLogEntry{
					entry(407, "ext_authz_denied", "", "/v1/models", &accesslogdatav3.ResponseFlags{
						UnauthorizedDetails: &accesslogdatav3.ResponseFlags_Unauthorized{},
					}),
				},
			}},
		},
	}}
	out := &fakeAppender{}
	require.NoError(t, NewService(out, isEgress, slog.New(slog.DiscardHandler)).StreamAccessLogs(stream))

	require.Len(t, out.batches, 2)
	got := append(out.batches[0], out.batches[1]...)
	require.Len(t, got, 3)
	assert.Equal(t, Record{
		Time: time.Date(2026, 10, 6, 1, 2, 3, 0, time.UTC), Node: "edge-egress/pod-a", Agent: sa,
		Client: "10.244.1.7", Decision: Allowed, Status: 200, Reason: "via_upstream", Method: "GET",
		Authority: "llm.mock.test", Path: "/v1/models", Destination: "mock-llm", RequestID: "r-1",
	}, got[0], "the query string, which can carry a key, is not recorded")
	assert.Equal(t, RateLimited, got[1].Decision)
	assert.Equal(t, Denied, got[2].Decision)
	assert.Empty(t, got[2].Agent, "an agent that proved no identity is recorded without one")
	assert.Equal(t, "edge-egress/pod-a", got[2].Node, "the identifier holds for the rest of the stream")

	other := &fakeStream{msgs: []*accesslogv3.StreamAccessLogsMessage{{
		Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{Node: &corev3.Node{Id: "edge-proxy"}, LogName: "something-else"},
		LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*accesslogdatav3.HTTPAccessLogEntry{entry(200, "via_upstream", "", "/", nil)},
		}},
	}}}
	out = &fakeAppender{}
	require.NoError(t, NewService(out, isEgress, slog.New(slog.DiscardHandler)).StreamAccessLogs(other))
	assert.Empty(t, out.batches)

	proxy := &fakeStream{msgs: []*accesslogv3.StreamAccessLogsMessage{{
		Identifier: &accesslogv3.StreamAccessLogsMessage_Identifier{Node: &corev3.Node{Id: "edge-proxy"}, LogName: LogName},
		LogEntries: &accesslogv3.StreamAccessLogsMessage_HttpLogs{HttpLogs: &accesslogv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*accesslogdatav3.HTTPAccessLogEntry{entry(200, "via_upstream", "", "/", nil)},
		}},
	}}}
	require.NoError(t, NewService(out, isEgress, slog.New(slog.DiscardHandler)).StreamAccessLogs(proxy))
	assert.Empty(t, out.batches, "only edge-egress Envoys' decisions are recorded")
}

func isEgress(node string) bool { return strings.HasPrefix(node, "edge-egress/") }
