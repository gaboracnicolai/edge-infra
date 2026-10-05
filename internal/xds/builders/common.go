package builders

import (
	"fmt"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func AdsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion: corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
			Ads: &corev3.AggregatedConfigSource{},
		},
	}
}

func RouteConfigName(gatewayName string) string {
	return gatewayName + "_routes"
}

// SNIRouteConfigName names the route config one SNI filter chain of an HTTPS
// gateway reads: only that host's routes, so a request's Host cannot reach a
// route behind a different SNI (and a different client-cert requirement).
func SNIRouteConfigName(gatewayName, host string) string {
	return gatewayName + "_routes_sni_" + host
}

// mustAny packs msg deterministically. The reconciler hashes the packed bytes to
// decide whether config changed, and a map inside msg (the JSON access-log
// format is one) would otherwise serialise in a different order on every build:
// the same config would hash differently and be republished on every reconcile.
func mustAny(msg proto.Message) *anypb.Any {
	a := &anypb.Any{}
	err := anypb.MarshalFrom(a, msg, proto.MarshalOptions{Deterministic: true})
	if err != nil {
		panic(fmt.Sprintf("marshal any: %v", err))
	}
	return a
}
