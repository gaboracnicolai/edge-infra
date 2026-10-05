package builders

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	otelalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/open_telemetry/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/edge-infra/control-plane/internal/store"
)

// telemetryListeners renders a plain HTTP gateway and a two-host HTTPS (per-SNI)
// gateway, so "every listener" covers the single-chain and the multi-chain shapes.
func telemetryListeners(tel TelemetryOptions) []types.Resource {
	https := store.Gateway{ID: "https", Name: "osb-shared-https", Port: 443, Protocol: "HTTPS"}
	routes := []store.Route{
		{Name: "a", GatewayID: "https", ClusterName: "a", Hosts: []string{"a.example"}, PathPrefix: "/", TLSSecret: "sec-a"},
		{Name: "b", GatewayID: "https", ClusterName: "b", Hosts: []string{"b.example"}, PathPrefix: "/", TLSSecret: "sec-b"},
	}
	return BuildListenersWithTelemetry([]store.Gateway{sampleGateway(), https}, routes,
		RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{}, tel)
}

// everyHCM returns the connection manager of every filter chain of every listener.
func everyHCM(t *testing.T, res []types.Resource) []*hcmv3.HttpConnectionManager {
	t.Helper()
	var out []*hcmv3.HttpConnectionManager
	for _, r := range res {
		for _, fc := range listenerFrom(t, r).FilterChains {
			var hcm hcmv3.HttpConnectionManager
			if err := fc.Filters[0].GetTypedConfig().UnmarshalTo(&hcm); err != nil {
				t.Fatalf("unmarshal hcm: %v", err)
			}
			out = append(out, &hcm)
		}
	}
	if len(out) != 3 {
		t.Fatalf("want 3 connection managers (1 HTTP + 2 SNI chains); got %d", len(out))
	}
	return out
}

// With no collector, every listener still writes a stdout JSON access line that
// carries the x-request-id it echoes to the client, and nothing is traced.
func TestTelemetry_StdoutAccessLogOnEveryListenerWithoutCollector(t *testing.T) {
	for _, hcm := range everyHCM(t, telemetryListeners(TelemetryOptions{})) {
		if !hcm.GetAlwaysSetRequestIdInResponse() {
			t.Fatal("always_set_request_id_in_response is off: the client never sees its x-request-id")
		}
		if len(hcm.GetAccessLog()) != 1 || hcm.GetAccessLog()[0].GetName() != "envoy.access_loggers.stdout" {
			t.Fatalf("access_log = %v; want exactly the stdout logger", hcm.GetAccessLog())
		}
		var out streamv3.StdoutAccessLog
		if err := hcm.GetAccessLog()[0].GetTypedConfig().UnmarshalTo(&out); err != nil {
			t.Fatalf("unmarshal stdout access log: %v", err)
		}
		fields := out.GetLogFormat().GetJsonFormat().GetFields()
		if got := fields["request_id"].GetStringValue(); got != "%REQ(X-REQUEST-ID)%" {
			t.Fatalf("request_id = %q; want %%REQ(X-REQUEST-ID)%%", got)
		}
		if got := fields["path"].GetStringValue(); got != "%PATH(NQ)%" {
			t.Fatalf("path = %q; want the path without its query string", got)
		}
		if hcm.GetTracing() != nil {
			t.Fatal("tracing is set with no collector configured")
		}
	}
	if c := TelemetryClusters(TelemetryOptions{}); len(c) != 0 {
		t.Fatalf("collector cluster emitted with telemetry off: %v", c)
	}
}

// With a collector, every listener also ships its access record and an
// OpenTelemetry span to the otel_collector cluster, which CDS then carries.
func TestTelemetry_EveryListenerExportsToCollector(t *testing.T) {
	tel := TelemetryOptions{Enabled: true, Address: "otel.monitoring", Port: 4317, ServiceName: "edge-proxy", SamplePercent: 25}
	for _, hcm := range everyHCM(t, telemetryListeners(tel)) {
		if len(hcm.GetAccessLog()) != 2 || hcm.GetAccessLog()[1].GetName() != "envoy.access_loggers.open_telemetry" {
			t.Fatalf("access_log = %v; want stdout then open_telemetry", hcm.GetAccessLog())
		}
		var al otelalv3.OpenTelemetryAccessLogConfig
		if err := hcm.GetAccessLog()[1].GetTypedConfig().UnmarshalTo(&al); err != nil {
			t.Fatalf("unmarshal otel access log: %v", err)
		}
		if got := al.GetGrpcService().GetEnvoyGrpc().GetClusterName(); got != otelCollectorClusterName {
			t.Fatalf("otel access log exports to %q; want %q", got, otelCollectorClusterName)
		}
		var rid string
		for _, kv := range al.GetAttributes().GetValues() {
			if kv.GetKey() == "request_id" {
				rid = kv.GetValue().GetStringValue()
			}
		}
		if rid != "%REQ(X-REQUEST-ID)%" {
			t.Fatalf("otel access log request_id = %q; want %%REQ(X-REQUEST-ID)%%", rid)
		}

		tr := hcm.GetTracing()
		if tr.GetProvider().GetName() != "envoy.tracers.opentelemetry" {
			t.Fatalf("tracer = %q; want envoy.tracers.opentelemetry", tr.GetProvider().GetName())
		}
		if tr.GetRandomSampling().GetValue() != 25 {
			t.Fatalf("random_sampling = %v; want 25", tr.GetRandomSampling().GetValue())
		}
		var ot tracev3.OpenTelemetryConfig
		if err := tr.GetProvider().GetTypedConfig().UnmarshalTo(&ot); err != nil {
			t.Fatalf("unmarshal otel tracer: %v", err)
		}
		if ot.GetGrpcService().GetEnvoyGrpc().GetClusterName() != otelCollectorClusterName || ot.GetServiceName() != "edge-proxy" {
			t.Fatalf("tracer exports to %q as %q; want %q as edge-proxy",
				ot.GetGrpcService().GetEnvoyGrpc().GetClusterName(), ot.GetServiceName(), otelCollectorClusterName)
		}
	}

	cs := TelemetryClusters(tel)
	if len(cs) != 1 {
		t.Fatalf("want 1 collector cluster; got %d", len(cs))
	}
	c := cs[0].(*clusterv3.Cluster)
	sa := c.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress()
	if c.GetName() != otelCollectorClusterName || sa.GetAddress() != "otel.monitoring" || sa.GetPortValue() != 4317 {
		t.Fatalf("collector cluster = %s -> %s:%d; want %s -> otel.monitoring:4317",
			c.GetName(), sa.GetAddress(), sa.GetPortValue(), otelCollectorClusterName)
	}
}
