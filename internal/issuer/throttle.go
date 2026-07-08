package issuer

import (
	"sync"
	"time"
)

// Throttle is an in-memory per-key failed-login limiter. After maxFailures
// consecutive failures for a key it locks the key with exponential backoff,
// gating the expensive argon2 verify (a 64 MiB DoS amplifier) BEFORE it runs.
//
// Keyed on (client IP + account): one attacker IP can't lock OTHER accounts, and
// an account is never locked for its own legitimate IP by an attacker elsewhere.
// Backoff (not a permanent lock) means a legitimate user is never locked out for
// good — the window always expires.
type Throttle struct {
	mu          sync.Mutex
	state       map[string]*attemptState
	maxFailures int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	now         func() time.Time
}

type attemptState struct {
	failures    int
	lockedUntil time.Time
}

// NewThrottle builds a limiter that locks a key after maxFailures failures, for
// base backoff doubling per excess failure, capped at max.
func NewThrottle(maxFailures int, base, max time.Duration) *Throttle {
	return &Throttle{
		state:       map[string]*attemptState{},
		maxFailures: maxFailures,
		baseBackoff: base,
		maxBackoff:  max,
		now:         time.Now,
	}
}

// Allow reports whether an attempt for key may proceed; when locked, it also
// returns the remaining lockout duration (for a Retry-After hint).
func (t *Throttle) Allow(key string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state[key]
	if st == nil {
		return true, 0
	}
	if wait := st.lockedUntil.Sub(t.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail records a failed attempt for key, locking it once past the threshold with
// exponential backoff (capped). Backoff never becomes permanent.
func (t *Throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state[key]
	if st == nil {
		st = &attemptState{}
		t.state[key] = st
	}
	st.failures++
	if st.failures >= t.maxFailures {
		backoff := t.maxBackoff
		if excess := st.failures - t.maxFailures; excess < 20 {
			backoff = t.baseBackoff << uint(excess)
			if backoff > t.maxBackoff {
				backoff = t.maxBackoff
			}
		}
		st.lockedUntil = t.now().Add(backoff)
	}
}

// Reset clears a key's failures — call on a successful login.
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.state, key)
}
