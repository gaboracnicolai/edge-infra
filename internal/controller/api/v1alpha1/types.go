package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ControllerFinalizer is the finalizer string written onto edge.io CRs so the
// controller can perform cleanup before Kubernetes garbage-collects the object.
const ControllerFinalizer = "edge.io/controller"

// GatewaySpec is the desired state for a Gateway.
type GatewaySpec struct {
	// Name is the logical gateway name surfaced to Envoy.
	Name string `json:"name"`
	// Protocol is "HTTP" or "HTTPS".
	Protocol string `json:"protocol"`
	// Port is the listener port.
	Port int32 `json:"port"`
	// TLSSecretName references an SDS-managed TLS secret (required when Protocol=HTTPS).
	TLSSecretName string `json:"tlsSecretName,omitempty"`
	// NodeSelector binds the gateway to a subset of edge nodes.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// UpstreamClusterName is the default cluster name advertised by this gateway.
	UpstreamClusterName string `json:"upstreamClusterName"`
}

// GatewayStatus is the observed state for a Gateway.
type GatewayStatus struct {
	// Synced indicates whether the desired spec has been persisted to the store.
	Synced bool `json:"synced"`
	// LastSyncedAt records the most recent successful sync.
	LastSyncedAt metav1.Time `json:"lastSyncedAt,omitempty"`
	// ConnectedProxies is a best-effort count of Envoy proxies currently consuming this gateway.
	ConnectedProxies int32 `json:"connectedProxies"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Gateway is the edge.io listener resource.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GatewaySpec   `json:"spec,omitempty"`
	Status GatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayList is a list of Gateway resources.
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Gateway `json:"items"`
}

// RouteRuleSpec is the desired state for an HTTP route binding on a Gateway.
type RouteRuleSpec struct {
	// GatewayRef is the metadata.name of the parent Gateway.
	GatewayRef string `json:"gatewayRef"`
	// Hostnames is the set of HTTP host headers this rule matches.
	Hostnames []string `json:"hostnames,omitempty"`
	// PathPrefix is the URL prefix this rule matches.
	PathPrefix string `json:"pathPrefix"`
	// ClusterRef is the upstream cluster name the rule forwards to.
	ClusterRef string `json:"clusterRef"`
	// TimeoutSeconds is the per-request timeout. Defaults to 30 if zero.
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// RouteRuleStatus is the observed state for a RouteRule.
type RouteRuleStatus struct {
	// Synced indicates whether the desired spec has been persisted to the store.
	Synced bool `json:"synced"`
	// LastSyncedAt records the most recent successful sync.
	LastSyncedAt metav1.Time `json:"lastSyncedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RouteRule binds a path prefix on a Gateway to an upstream cluster.
type RouteRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RouteRuleSpec   `json:"spec,omitempty"`
	Status RouteRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RouteRuleList is a list of RouteRule resources.
type RouteRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RouteRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{}, &RouteRule{}, &RouteRuleList{})
}
