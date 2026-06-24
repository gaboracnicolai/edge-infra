package ratelimit

import (
	"context"
	"testing"

	commonrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	rlv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
)

func descriptor(k, v string) *commonrlv3.RateLimitDescriptor {
	return &commonrlv3.RateLimitDescriptor{
		Entries: []*commonrlv3.RateLimitDescriptor_Entry{{Key: k, Value: v}},
	}
}

func TestService_OverLimitAfterCapacity(t *testing.T) {
	svc := NewService(New(nil), Rule{Capacity: 2, RatePerSec: 0.001})
	req := &rlv3.RateLimitRequest{
		Domain:      "edge",
		Descriptors: []*commonrlv3.RateLimitDescriptor{descriptor("user_id", "u1")},
	}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		resp, _ := svc.ShouldRateLimit(ctx, req)
		if resp.GetOverallCode() != rlv3.RateLimitResponse_OK {
			t.Fatalf("request %d should be OK within capacity", i+1)
		}
	}
	resp, _ := svc.ShouldRateLimit(ctx, req)
	if resp.GetOverallCode() != rlv3.RateLimitResponse_OVER_LIMIT {
		t.Fatal("3rd request must be OVER_LIMIT")
	}
	hasRetry := false
	for _, h := range resp.GetResponseHeadersToAdd() {
		if h.GetKey() == "Retry-After" {
			hasRetry = true
		}
	}
	if !hasRetry {
		t.Error("OVER_LIMIT response must include a Retry-After header")
	}
}

func TestService_PerDescriptorBuckets(t *testing.T) {
	svc := NewService(New(nil), Rule{Capacity: 1, RatePerSec: 0.001})
	ctx := context.Background()
	mk := func(v string) *rlv3.RateLimitRequest {
		return &rlv3.RateLimitRequest{
			Domain:      "edge",
			Descriptors: []*commonrlv3.RateLimitDescriptor{descriptor("user_id", v)},
		}
	}
	if r, _ := svc.ShouldRateLimit(ctx, mk("a")); r.GetOverallCode() != rlv3.RateLimitResponse_OK {
		t.Fatal("user a first request should be OK")
	}
	if r, _ := svc.ShouldRateLimit(ctx, mk("b")); r.GetOverallCode() != rlv3.RateLimitResponse_OK {
		t.Fatal("user b must have its own bucket, not share user a's")
	}
}
