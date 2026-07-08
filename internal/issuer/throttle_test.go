package issuer

import (
	"testing"
	"time"
)

func TestThrottle_LocksAfterMaxFailures(t *testing.T) {
	th := NewThrottle(3, time.Second, time.Minute)
	key := "1.2.3.4|a@b.com"
	for i := 0; i < 3; i++ {
		if ok, _ := th.Allow(key); !ok {
			t.Fatalf("attempt %d should be allowed (under the limit)", i)
		}
		th.Fail(key)
	}
	ok, retry := th.Allow(key)
	if ok {
		t.Error("after maxFailures the key must be locked")
	}
	if retry <= 0 {
		t.Error("a locked key must report a positive Retry-After")
	}
}

func TestThrottle_ResetClearsLock(t *testing.T) {
	th := NewThrottle(3, time.Second, time.Minute)
	key := "1.2.3.4|a@b.com"
	for i := 0; i < 3; i++ {
		th.Fail(key)
	}
	th.Reset(key)
	if ok, _ := th.Allow(key); !ok {
		t.Error("Reset (a successful login) must clear the lock")
	}
}

// The lock is per-(IP+account): an attacker can neither lock a victim's own IP
// nor lock every account from one IP.
func TestThrottle_PerKeyIsolation(t *testing.T) {
	th := NewThrottle(3, time.Second, time.Minute)
	for i := 0; i < 5; i++ {
		th.Fail("1.2.3.4|victim@b.com")
	}
	if ok, _ := th.Allow("9.9.9.9|victim@b.com"); !ok {
		t.Error("a different IP for the same account must NOT be locked (no victim lockout)")
	}
	if ok, _ := th.Allow("1.2.3.4|other@b.com"); !ok {
		t.Error("the same IP for a different account must NOT be locked (can't lock every user)")
	}
}

// Backoff expires — a legitimate user is never permanently locked out.
func TestThrottle_LockExpiresAfterBackoff(t *testing.T) {
	th := NewThrottle(3, time.Second, time.Minute)
	clock := time.Unix(1_700_000_000, 0)
	th.now = func() time.Time { return clock }
	key := "1.2.3.4|a@b.com"
	for i := 0; i < 3; i++ {
		th.Fail(key)
	}
	if ok, _ := th.Allow(key); ok {
		t.Fatal("must be locked immediately after the threshold")
	}
	clock = clock.Add(2 * time.Second) // past the 1s base backoff
	if ok, _ := th.Allow(key); !ok {
		t.Error("the lock must expire after the backoff window")
	}
}
