package builders

import (
	"strings"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	otelalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/open_telemetry/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	tracingtypev3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	otlpcommonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

// otelCollectorClusterName is the CDS cluster the OpenTelemetry tracer and access
// logger export to. Not configurable — it is wired end-to-end within the control
// plane, like the auth-service cluster.
const otelCollectorClusterName = "otel_collector"

// TelemetryOptions configures the OpenTelemetry collector every listener exports
// its trace spans and access-log records to, over OTLP/gRPC.
//
// The stdout access log does not depend on it: every listener writes one JSON
// line per request whether or not a collector is configured. Like the rate limit
// service this is fail-open — an unreachable collector loses telemetry, never a
// request.
type TelemetryOptions struct {
	Enabled       bool
	Address       string  // collector DNS name
	Port          uint32  // OTLP/gRPC port
	ServiceName   string  // service.name on every span and log record
	SamplePercent float64 // share of requests traced, 0–100
}

// logField is one key of an access-log record and the Envoy format of its value.
type logField struct{ key, format string }

// accessLogFields is what every access-log record carries, on stdout and in the
// collector alike. request_id is the x-request-id the client receives (the HCM
// always echoes it in the response) and trace_id joins the record to its span.
// The path is logged without its query string, which can carry credentials.
var accessLogFields = []logField{
	{"start_time", "%START_TIME%"},
	{"request_id", "%REQ(X-REQUEST-ID)%"},
	{"trace_id", "%TRACE_ID%"},
	{"method", "%REQ(:METHOD)%"},
	{"authority", "%REQ(:AUTHORITY)%"},
	{"path", "%PATH(NQ)%"},
	{"protocol", "%PROTOCOL%"},
	{"status", "%RESPONSE_CODE%"},
	{"response_flags", "%RESPONSE_FLAGS%"},
	{"response_code_details", "%RESPONSE_CODE_DETAILS%"},
	{"bytes_received", "%BYTES_RECEIVED%"},
	{"bytes_sent", "%BYTES_SENT%"},
	{"duration_ms", "%DURATION%"},
	{"upstream_service_time_ms", "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"},
	{"client_address", "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"},
	{"user_agent", "%REQ(USER-AGENT)%"},
	{"user_id", "%REQ(X-USER-ID)%"},
	{"route", "%ROUTE_NAME%"},
	{"upstream_cluster", "%UPSTREAM_CLUSTER%"},
	{"upstream_host", "%UPSTREAM_HOST%"},
}

// observeConnectionManager gives a listener's HTTP connection manager its access
// logs and tracing:
//
//   - always_set_request_id_in_response: the client gets the x-request-id Envoy
//     logged and traced the request under, so a support ticket can quote it.
//   - a JSON access log line per request on stdout, on every listener.
//   - with a collector configured, the same record to it as an OTLP log, and an
//     OpenTelemetry span per sampled request (Envoy tags it guid:x-request-id).
//
// extra fields are logged after accessLogFields, in both records.
func observeConnectionManager(hcm *hcmv3.HttpConnectionManager, gateway string, tel TelemetryOptions, extra ...logField) {
	fields := append(append([]logField{}, accessLogFields...), extra...)
	hcm.AlwaysSetRequestIdInResponse = true
	hcm.AccessLog = []*accesslogv3.AccessLog{stdoutAccessLog(gateway, fields)}
	if !tel.Enabled {
		return
	}
	hcm.AccessLog = append(hcm.AccessLog, otelAccessLog(gateway, tel, fields))
	hcm.Tracing = &hcmv3.HttpConnectionManager_Tracing{
		RandomSampling: &typev3.Percent{Value: tel.SamplePercent},
		CustomTags: []*tracingtypev3.CustomTag{{
			Tag:  "gateway",
			Type: &tracingtypev3.CustomTag_Literal_{Literal: &tracingtypev3.CustomTag_Literal{Value: gateway}},
		}},
		Provider: &tracev3.Tracing_Http{
			Name: "envoy.tracers.opentelemetry",
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: mustAny(&tracev3.OpenTelemetryConfig{
					GrpcService: otelGrpcService(),
					ServiceName: tel.ServiceName,
				}),
			},
		},
	}
}

// literalFormat escapes s for use as literal text in an access-log format.
func literalFormat(s string) string { return strings.ReplaceAll(s, "%", "%%") }

func stdoutAccessLog(gateway string, logged []logField) *accesslogv3.AccessLog {
	fields := map[string]*structpb.Value{"gateway": structpb.NewStringValue(literalFormat(gateway))}
	for _, f := range logged {
		fields[f.key] = structpb.NewStringValue(f.format)
	}
	return &accesslogv3.AccessLog{
		Name: "envoy.access_loggers.stdout",
		ConfigType: &accesslogv3.AccessLog_TypedConfig{
			TypedConfig: mustAny(&streamv3.StdoutAccessLog{
				AccessLogFormat: &streamv3.StdoutAccessLog_LogFormat{
					LogFormat: &corev3.SubstitutionFormatString{
						Format: &corev3.SubstitutionFormatString_JsonFormat{
							JsonFormat: &structpb.Struct{Fields: fields},
						},
					},
				},
			}),
		},
	}
}

func otelAccessLog(gateway string, tel TelemetryOptions, logged []logField) *accesslogv3.AccessLog {
	attrs := []*otlpcommonv1.KeyValue{otlpString("gateway", literalFormat(gateway))}
	for _, f := range logged {
		attrs = append(attrs, otlpString(f.key, f.format))
	}
	return &accesslogv3.AccessLog{
		Name: "envoy.access_loggers.open_telemetry",
		ConfigType: &accesslogv3.AccessLog_TypedConfig{
			TypedConfig: mustAny(&otelalv3.OpenTelemetryAccessLogConfig{
				GrpcService: otelGrpcService(),
				LogName:     "edge-access",
				Body: &otlpcommonv1.AnyValue{Value: &otlpcommonv1.AnyValue_StringValue{
					StringValue: "%REQ(:METHOD)% %PATH(NQ)% %PROTOCOL% %RESPONSE_CODE%",
				}},
				Attributes: &otlpcommonv1.KeyValueList{Values: attrs},
				ResourceAttributes: &otlpcommonv1.KeyValueList{Values: []*otlpcommonv1.KeyValue{
					otlpString("service.name", tel.ServiceName),
				}},
			}),
		},
	}
}

func otlpString(key, value string) *otlpcommonv1.KeyValue {
	return &otlpcommonv1.KeyValue{Key: key, Value: &otlpcommonv1.AnyValue{
		Value: &otlpcommonv1.AnyValue_StringValue{StringValue: value},
	}}
}

func otelGrpcService() *corev3.GrpcService {
	return &corev3.GrpcService{
		TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
			EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: otelCollectorClusterName},
		},
	}
}

// TelemetryClusters returns the collector cluster when a collector is configured,
// and nothing otherwise.
func TelemetryClusters(tel TelemetryOptions) []types.Resource {
	if !tel.Enabled {
		return nil
	}
	return []types.Resource{&clusterv3.Cluster{
		Name:                 otelCollectorClusterName,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		// OTLP/gRPC requires HTTP/2 to the upstream.
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": mustAny(&httpv3.HttpProtocolOptions{
				UpstreamProtocolOptions: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_{
					ExplicitHttpConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig{
						ProtocolConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
							Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
						},
					},
				},
			}),
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: otelCollectorClusterName,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
						Endpoint: &endpointv3.Endpoint{Address: socketAddress(tel.Address, tel.Port)},
					},
				}},
			}},
		},
	}}
}
