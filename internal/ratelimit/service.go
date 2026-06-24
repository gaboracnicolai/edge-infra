package ratelimit

import (
	"context"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	commonrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	rlv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
)

// Service implements Envoy's RateLimitService (RLS). Envoy's global ratelimit
// filter calls ShouldRateLimit with the descriptors built from the route's
// rate_limit actions (x-user-id, remote_address). Each descriptor is checked
// against its own token bucket; if any is over limit the overall verdict is
// OVER_LIMIT and Envoy returns 429.
//
// Fail-open posture: the underlying Limiter degrades to an in-process bucket on
// Redis error, and the Envoy filter is configured failure_mode_deny=false, so
// neither a Redis outage nor an RLS outage can block traffic.
type Service struct {
	rlv3.UnimplementedRateLimitServiceServer
	limiter *Limiter
	rule    Rule
}

// NewService builds the RLS handler. rule is applied per descriptor (so the
// per-user and per-IP descriptors each get their own bucket of this size).
func NewService(limiter *Limiter, rule Rule) *Service {
	return &Service{limiter: limiter, rule: rule}
}

// ShouldRateLimit checks every descriptor and returns OVER_LIMIT (with a
// Retry-After header) if any bucket is exhausted, else OK.
func (s *Service) ShouldRateLimit(ctx context.Context, req *rlv3.RateLimitRequest) (*rlv3.RateLimitResponse, error) {
	overall := rlv3.RateLimitResponse_OK
	retryAfter := 0
	for _, d := range req.GetDescriptors() {
		res := s.limiter.Check(ctx, req.GetDomain()+"|"+descriptorKey(d), s.rule)
		if !res.Allowed {
			overall = rlv3.RateLimitResponse_OVER_LIMIT
			if res.RetryAfterSec > retryAfter {
				retryAfter = res.RetryAfterSec
			}
		}
	}

	resp := &rlv3.RateLimitResponse{OverallCode: overall}
	if overall == rlv3.RateLimitResponse_OVER_LIMIT {
		resp.ResponseHeadersToAdd = []*corev3.HeaderValue{{
			Key:   "Retry-After",
			Value: strconv.Itoa(retryAfter),
		}}
	}
	return resp, nil
}

// descriptorKey flattens a descriptor's entries into a stable bucket key so the
// same (user / IP) descriptor maps to the same bucket across instances.
func descriptorKey(d *commonrlv3.RateLimitDescriptor) string {
	parts := make([]string, 0, len(d.GetEntries()))
	for _, e := range d.GetEntries() {
		parts = append(parts, e.GetKey()+"="+e.GetValue())
	}
	return strings.Join(parts, ",")
}
