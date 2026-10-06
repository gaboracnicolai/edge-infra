package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A licence issued with a key from keygen verifies against the public key keygen
// printed, and stops verifying once it has expired.
func TestKeygenIssueVerify(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	key := filepath.Join(t.TempDir(), "talyvor-licence.key")

	var pub, tok, out bytes.Buffer
	if err := run([]string{"keygen", "-out", key}, nil, &pub, now); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"issue", "-key", key, "-licensee", "Acme Ltd", "-expires", "2027-10-06"}, nil, &tok, now); err != nil {
		t.Fatal(err)
	}
	verify := []string{"verify", "-pub", strings.TrimSpace(pub.String())}
	if err := run(verify, strings.NewReader(tok.String()), &out, now); err != nil {
		t.Fatalf("verify: %v (%s)", err, out.String())
	}
	if got := out.String(); !strings.HasPrefix(got, `valid: lic_`) || !strings.Contains(got, `licensee "Acme Ltd", plan enterprise, expires 2027-10-06T00:00:00Z`) {
		t.Fatalf("verify said %q", got)
	}

	out.Reset()
	later := time.Date(2027, 10, 6, 0, 0, 0, 0, time.UTC)
	if err := run(verify, strings.NewReader(tok.String()), &out, later); err == nil || !strings.HasPrefix(out.String(), "expired: ") {
		t.Fatalf("at its expiry verify said %q, err %v", out.String(), err)
	}
}
