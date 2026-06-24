// Package ratelimit is a Redis-backed token-bucket limiter that degrades to an
// in-process bucket when Redis is unavailable. It mirrors the Lens
// internal/ratelimit design (token bucket + in-memory fallback): the shared
// (Redis) layer only further-restricts, and a Redis outage degrades to local
// limiting rather than blocking — it never errors and never 503s the caller.
package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule is a token-bucket limit: Capacity tokens that refill at RatePerSec.
type Rule struct {
	Capacity   float64
	RatePerSec float64
}

// Result is the verdict for one Check.
type Result struct {
	Allowed       bool
	RetryAfterSec int
}

// redisTimeout bounds every Redis call so a slow/hung Redis degrades quickly to
// the in-memory bucket instead of adding latency to the request path.
const redisTimeout = 50 * time.Millisecond

// bucketScript implements the token-bucket algorithm atomically in Redis,
// ported from Lens internal/ratelimit/tokenbucket.go. KEYS[1] holds the bucket
// hash (tokens, last-millis). ARGV: capacity, refill_per_sec, cost, now_ms.
// Returns { allowed (0|1), remaining (float string), reset_ms }.
var bucketScript = redis.NewScript(`
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local cost     = tonumber(ARGV[3])
local now      = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local tokens = tonumber(data[1])
local last   = tonumber(data[2])
if tokens == nil then
    tokens = capacity
    last   = now
end

local elapsed = (now - last) / 1000.0
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

redis.call('HMSET', KEYS[1], 'tokens', tokens, 'last', now)
local ttl_s = math.ceil(2 * capacity / math.max(rate, 0.001))
redis.call('EXPIRE', KEYS[1], ttl_s)

return { allowed, tostring(tokens), now }
`)

// Limiter is the shared limiter. When rdb is nil (or every Redis call fails) it
// uses the in-process fallback, so a Redis outage degrades to local limiting.
type Limiter struct {
	rdb      *redis.Client
	fallback *inMemory
}

// New builds a Limiter. A nil rdb means "always in-process" (single-instance).
func New(rdb *redis.Client) *Limiter {
	return &Limiter{rdb: rdb, fallback: newInMemory()}
}

// Check consumes one token from the bucket identified by key under rule. On any
// Redis error it falls back to the in-process bucket — degrade to local, never
// fail open and never block.
func (l *Limiter) Check(ctx context.Context, key string, rule Rule) Result {
	if rule.Capacity <= 0 || rule.RatePerSec <= 0 {
		return Result{Allowed: true} // no limit configured
	}
	if l.rdb != nil {
		if res, err := l.checkRedis(ctx, key, rule); err == nil {
			return res
		}
		// fall through to the in-process bucket on any Redis error
	}
	return l.fallback.check(key, rule)
}

func (l *Limiter) checkRedis(ctx context.Context, key string, rule Rule) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, redisTimeout)
	defer cancel()

	raw, err := bucketScript.Run(ctx, l.rdb, []string{"rl:" + key},
		rule.Capacity, rule.RatePerSec, 1.0, time.Now().UnixMilli()).Result()
	if err != nil {
		return Result{}, err
	}
	arr, ok := raw.([]interface{})
	if !ok || len(arr) < 2 {
		return Result{}, fmt.Errorf("ratelimit: unexpected script result %v", raw)
	}
	allowedN, _ := arr[0].(int64)
	var tokens float64
	if s, ok := arr[1].(string); ok {
		_, _ = fmt.Sscanf(s, "%f", &tokens)
	}
	return verdict(allowedN == 1, tokens, rule), nil
}

// verdict turns an allowed flag + remaining tokens into a Result, computing
// Retry-After as the time to refill enough for one more token.
func verdict(allowed bool, tokens float64, rule Rule) Result {
	if allowed {
		return Result{Allowed: true}
	}
	retry := 1
	if rule.RatePerSec > 0 {
		need := 1.0 - tokens
		if need < 0 {
			need = 0
		}
		retry = int(need/rule.RatePerSec) + 1
	}
	return Result{Allowed: false, RetryAfterSec: retry}
}

// ─── in-process fallback ─────────────────────────────────────────────

type localBucket struct {
	tokens float64
	last   time.Time
}

type inMemory struct {
	mu      sync.Mutex
	buckets map[string]*localBucket
}

func newInMemory() *inMemory {
	return &inMemory{buckets: map[string]*localBucket{}}
}

func (m *inMemory) check(key string, rule Rule) Result {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.buckets[key]
	if !ok {
		b = &localBucket{tokens: rule.Capacity, last: now}
		m.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = b.tokens + elapsed*rule.RatePerSec
		if b.tokens > rule.Capacity {
			b.tokens = rule.Capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return Result{Allowed: true}
	}
	return verdict(false, b.tokens, rule)
}
