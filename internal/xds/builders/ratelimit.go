package builders

// rlsClusterName is the internal CDS cluster name for the rate-limit service.
const rlsClusterName = "ratelimit"

// rateLimitFilterName is the Envoy HTTP filter name for the global ratelimit
// filter (distinct from the per-instance local_ratelimit).
const rateLimitFilterName = "envoy.filters.http.ratelimit"

// RateLimitServiceOptions configures the Envoy global ratelimit filter, its RLS
// cluster, and the per-route descriptors.
//
// FAIL-OPEN: the emitted filter sets failure_mode_deny = false, so if the RLS
// is unreachable Envoy ALLOWS the request — the per-instance local_ratelimit
// floor still applies. This is the same posture as the floor, and the opposite
// of ext_authz: a limiter problem must never block traffic.
type RateLimitServiceOptions struct {
	Enabled  bool
	Address  string // RLS DNS name
	Port     uint32
	Domain   string // ratelimit domain (descriptor namespace)
	CAFile   string // upstream TLS trust CA (presence enables TLS)
	CertFile string // upstream mTLS client cert (optional)
	KeyFile  string // upstream mTLS client key (optional)
}
