package builders

// authServiceClusterName is the internal CDS cluster name the ext_authz filter
// targets. Not configurable — it is wired end-to-end within the control plane.
const authServiceClusterName = "auth_service"

// extAuthzFilterName is the Envoy HTTP filter name for ext_authz.
const extAuthzFilterName = "envoy.filters.http.ext_authz"

// ExtAuthzOptions configures the Envoy ext_authz HTTP filter and the static
// cluster pointing at the auth-service gRPC API.
//
// FAIL-CLOSED: the emitted filter sets failure_mode_allow = false, so if the
// auth-service is unreachable Envoy DENIES the request. This is the deliberate
// opposite of the rate limiter's fail-open posture — a fail-open ext_authz
// would silently bypass auth for the whole suite.
type ExtAuthzOptions struct {
	Enabled  bool
	Address  string // auth-service DNS name
	Port     uint32
	CAFile   string // upstream TLS trust CA (presence enables TLS)
	CertFile string // upstream mTLS client cert (optional)
	KeyFile  string // upstream mTLS client key (optional)
}
