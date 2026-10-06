package licence

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mint(t *testing.T, key ed25519.PrivateKey, expires time.Time) string {
	t.Helper()
	tok, err := Sign(Licence{ID: "lic_test", Licensee: "Acme Ltd", Plan: "enterprise",
		IssuedAt: now.AddDate(-1, 0, 0), ExpiresAt: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCheck(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, otherPriv := newKey(t)
	valid := mint(t, priv, now.Add(24*time.Hour))
	parts := strings.Split(valid, ".")
	forged := mint(t, otherPriv, now.Add(24*time.Hour))
	// A year added to the expiry, under the genuine signature: an edited licence.
	tampered := parts[0] + "." + strings.Split(mint(t, otherPriv, now.AddDate(1, 0, 0)), ".")[1] + "." + parts[2]

	for _, tc := range []struct {
		name  string
		token string
		keys  []ed25519.PublicKey
		want  State
	}{
		{"signed and unexpired", valid, []ed25519.PublicKey{pub}, Valid},
		{"past its expiry", mint(t, priv, now.Add(-time.Second)), []ed25519.PublicKey{pub}, Expired},
		{"expiring this instant", mint(t, priv, now), []ed25519.PublicKey{pub}, Expired},
		{"payload edited", tampered, []ed25519.PublicKey{pub}, Invalid},
		{"signed by a key not trusted", forged, []ed25519.PublicKey{pub}, Invalid},
		{"no key trusted", valid, nil, Invalid},
		{"one of several keys", valid, []ed25519.PublicKey{otherPub, pub}, Valid},
		{"not a licence", "hello", []ed25519.PublicKey{pub}, Invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Check(tc.token, tc.keys, now)
			if s.State != tc.want {
				t.Fatalf("state %s (err %v), want %s", s.State, s.Err, tc.want)
			}
			if (s.Licence != nil) != (tc.want == Valid || tc.want == Expired) {
				t.Fatalf("licence %v for state %s", s.Licence, s.State)
			}
		})
	}

	if s := CheckFile(filepath.Join(t.TempDir(), "licence"), []ed25519.PublicKey{pub}, now); s.State != Missing {
		t.Fatalf("no file: state %s, want missing", s.State)
	}
}

// TestMetric is the DONE line's metric: 1 for a valid licence, 0 once it has
// expired, with its expiry exported either way.
func TestMetric(t *testing.T) {
	pub, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "licence")
	expires := now.Add(time.Hour)
	if err := os.WriteFile(path, []byte(mint(t, priv, expires)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := NewWatcher(path, []ed25519.PublicKey{pub}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	want := func(valid string) string {
		return `
# HELP edge_licence_expiry_timestamp_seconds Unix time the installed Talyvor Edge licence expires; 0 when no trusted licence can be read.
# TYPE edge_licence_expiry_timestamp_seconds gauge
edge_licence_expiry_timestamp_seconds 1.7912916e+09
# HELP edge_licence_valid 1 while the installed Talyvor Edge licence is signed by a trusted key and unexpired, otherwise 0. Advisory: no traffic depends on it.
# TYPE edge_licence_valid gauge
edge_licence_valid ` + valid + "\n"
	}

	w.now = func() time.Time { return now }
	if err := testutil.CollectAndCompare(w, strings.NewReader(want("1"))); err != nil {
		t.Fatalf("valid licence: %v", err)
	}
	w.now = func() time.Time { return expires.Add(time.Second) }
	if err := testutil.CollectAndCompare(w, strings.NewReader(want("0"))); err != nil {
		t.Fatalf("expired licence: %v", err)
	}
}
