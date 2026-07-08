package issuer

import (
	"net/http"
	"testing"
)

// SEC-1: /login runs argon2id (64 MiB) on EVERY request — even for unknown users (dummy-hash) — with
// no rate-limit, lockout, or attempt-counting. That is a brute-force enabler AND a DoS amplifier: an
// attacker forces unlimited expensive argon2id computations. RED (today): rapid repeated attempts are
// all accepted (401), never throttled (429). GREEN (post-fix): the throttle trips at the ceiling.
func TestLoginThrottle_TripsAtCeiling(t *testing.T) {
	store := &fakeStore{login: &Login{ID: "u1", Email: "a@b.com", PasswordHash: mustHash(t, "right")}}
	srv := testServer(t, store)

	got429 := false
	for i := 0; i < 15; i++ {
		rec := doLogin(t, srv, "a@b.com", "wrong")
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Errorf("fired 15 rapid wrong-password attempts, NEVER got 429 — no brute-force/DoS throttle on /login (every attempt ran argon2id 64 MiB)")
	}
}

// The throttle must not leak user existence: a throttled KNOWN account and a throttled UNKNOWN account
// return the same status (429) — no oracle.
func TestLoginThrottle_NoExistenceOracle(t *testing.T) {
	store := &fakeStore{login: &Login{ID: "u1", Email: "known@b.com", PasswordHash: mustHash(t, "right")}}
	srv := testServer(t, store)

	trip := func(email string) int {
		last := 0
		for i := 0; i < 15; i++ {
			last = doLogin(t, srv, email, "wrong").Code
			if last == http.StatusTooManyRequests {
				break
			}
		}
		return last
	}
	known := trip("known@b.com")
	unknown := trip("ghost@b.com")
	if known != http.StatusTooManyRequests || unknown != http.StatusTooManyRequests {
		t.Errorf("throttle did not trip for both known (%d) and unknown (%d) — want both 429", known, unknown)
	}
}
