package ratelimit

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestLimiter_TripsAfterCapacity(t *testing.T) {
	l := New(nil) // in-process
	rule := Rule{Capacity: 3, RatePerSec: 0.001} // negligible refill during the test
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if r := l.Check(ctx, "user-1", rule); !r.Allowed {
			t.Fatalf("request %d should be allowed within capacity", i+1)
		}
	}
	r := l.Check(ctx, "user-1", rule)
	if r.Allowed {
		t.Fatal("4th request must be denied (capacity exhausted)")
	}
	if r.RetryAfterSec < 1 {
		t.Errorf("denied result must carry Retry-After >= 1, got %d", r.RetryAfterSec)
	}
}

func TestLimiter_SeparateKeysSeparateBuckets(t *testing.T) {
	l := New(nil)
	rule := Rule{Capacity: 1, RatePerSec: 0.001}
	ctx := context.Background()
	if !l.Check(ctx, "user-a", rule).Allowed {
		t.Fatal("user-a first request should pass")
	}
	if !l.Check(ctx, "user-b", rule).Allowed {
		t.Fatal("user-b must have its own bucket, not share user-a's")
	}
}

func TestLimiter_NoRuleAllowsAll(t *testing.T) {
	l := New(nil)
	for i := 0; i < 100; i++ {
		if !l.Check(context.Background(), "x", Rule{}).Allowed {
			t.Fatal("a zero rule must impose no limit")
		}
	}
}

// TestLimiter_RedisDownDegradesToLocalNotOpen points the limiter at a dead
// Redis and asserts it still limits via the in-process bucket — it neither
// errors, nor blocks everything, nor lets everything through (fail-open would
// be a bug here: the shared layer degrades to local, it does not disappear).
func TestLimiter_RedisDownDegradesToLocalNotOpen(t *testing.T) {
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // connection refused
	defer dead.Close()
	l := New(dead)
	rule := Rule{Capacity: 2, RatePerSec: 0.001}
	ctx := context.Background()

	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Check(ctx, "user-9", rule).Allowed {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("with Redis down the in-process bucket must still cap at capacity (2); allowed=%d", allowed)
	}
}
