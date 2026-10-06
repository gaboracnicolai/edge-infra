package keycrypt

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// Seal must produce a MARKED value that is not the plaintext.
func TestSeal_ProducesMarkedCiphertext(t *testing.T) {
	kek := testKEK(t)
	out, err := Seal(kek, "-----BEGIN PRIVATE KEY-----secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, Marker) {
		t.Errorf("sealed value must carry the %q marker; got %q", Marker, out)
	}
	if out == "-----BEGIN PRIVATE KEY-----secret" {
		t.Error("sealed value must not equal the plaintext")
	}
}

// Seal then Open round-trips to the original plaintext.
func TestRoundTrip(t *testing.T) {
	kek := testKEK(t)
	pt := "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----"
	sealed, err := Seal(kek, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(kek, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != pt {
		t.Errorf("round-trip mismatch: got %q want %q", got, pt)
	}
}

// A marked value opened with the WRONG KEK errors loudly — never returns garbage.
func TestOpen_WrongKEK_Errors(t *testing.T) {
	sealed, err := Seal(testKEK(t), "topsecret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testKEK(t), sealed); err == nil {
		t.Error("opening with the wrong KEK must error, not return garbage")
	}
}

// An unmarked value is plaintext (pre-encryption backward-compat) — passthrough.
func TestOpen_PlaintextPassthrough(t *testing.T) {
	got, err := Open(testKEK(t), "-----BEGIN CERTIFICATE-----plain")
	if err != nil {
		t.Fatal(err)
	}
	if got != "-----BEGIN CERTIFICATE-----plain" {
		t.Errorf("unmarked value must pass through unchanged; got %q", got)
	}
}

// A marked value with no KEK errors (fail-closed) — never serves ciphertext.
func TestOpen_MarkedNoKEK_Errors(t *testing.T) {
	if _, err := Open(nil, Marker+"Zm9v"); err == nil {
		t.Error("a sealed value with no KEK configured must error")
	}
}

// A nil KEK disables encryption: Seal is passthrough.
func TestSeal_NilKEK_Passthrough(t *testing.T) {
	out, err := Seal(nil, "plain")
	if err != nil || out != "plain" {
		t.Errorf("nil KEK must pass through; got %q err %v", out, err)
	}
}

func TestParseKEK(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if k, err := ParseKEK(valid); err != nil || len(k) != 32 {
		t.Errorf("valid 32-byte KEK: got len %d err %v", len(k), err)
	}
	if k, err := ParseKEK(""); err != nil || k != nil {
		t.Error("empty KEK must parse to nil (disabled)")
	}
	if _, err := ParseKEK(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Error("a 16-byte KEK must be rejected (need 32)")
	}
	if _, err := ParseKEK("not base64!!!"); err == nil {
		t.Error("non-base64 KEK must be rejected")
	}
}

// v1FixtureKEK sealed v1Fixture with the pre-rotation sealer (enc:v1, no key id).
var (
	v1FixtureKEK       = []byte("0123456789abcdef0123456789abcdef")
	v1Fixture          = "enc:v1:UzZAq65Hx9R/bzazNQnF0Qysknh12p2zxcRVjbCmlj+aM2gE4PsjIp5iZWDNw+WY9jGHzb9YpuDmbUByOpnf3iOVBiVILuyeGGrt5vYWuApUbprYLqZg"
	v1FixturePlaintext = "-----BEGIN TEST KEY-----\nv1 fixture\n-----END TEST KEY-----\n"
)

// Seal writes enc:v2 naming the KEK it used.
func TestSeal_WritesV2WithKeyID(t *testing.T) {
	kek := testKEK(t)
	out, err := Seal(kek, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if want := MarkerV2 + KeyID(kek) + ":"; !strings.HasPrefix(out, want) {
		t.Errorf("sealed value must start %q; got %q", want, out)
	}
}

// A rotation: values sealed under the old KEK (v1 and v2) open under a keyring
// holding it as previous; re-sealed, they are current; and once the old KEK is
// dropped they still open, while a keyring of the old KEK alone cannot.
func TestKeyring_Rotation(t *testing.T) {
	oldK, newK := v1FixtureKEK, testKEK(t)
	oldV2, err := Seal(oldK, "v2 under the old KEK")
	if err != nil {
		t.Fatal(err)
	}
	during := NewKeyring(newK, oldK)
	after := NewKeyring(newK)
	for _, c := range []struct{ sealed, want string }{
		{v1Fixture, v1FixturePlaintext},
		{oldV2, "v2 under the old KEK"},
	} {
		if during.IsCurrent(c.sealed) {
			t.Errorf("%.12q is under the old KEK, not current", c.sealed)
		}
		pt, err := during.Open(c.sealed)
		if err != nil || pt != c.want {
			t.Fatalf("open under (new, old): got %q, %v; want %q", pt, err, c.want)
		}
		resealed, err := during.Seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		if !during.IsCurrent(resealed) {
			t.Errorf("re-sealed value %.30q must be current", resealed)
		}
		if pt, err := after.Open(resealed); err != nil || pt != c.want {
			t.Errorf("after dropping the old KEK: got %q, %v; want %q", pt, err, c.want)
		}
		if _, err := NewKeyring(oldK).Open(resealed); err == nil {
			t.Error("the retired KEK alone must not open a re-sealed value")
		}
	}
	if _, err := after.Open(oldV2); err == nil || !strings.Contains(err.Error(), KeyID(oldK)) {
		t.Errorf("a value under a dropped KEK must fail naming it; got %v", err)
	}
}

// The key id is bound into the ciphertext: relabelling a value to another
// held KEK's id fails to open rather than decrypting under the wrong key.
func TestKeyring_RelabelledKeyIDFails(t *testing.T) {
	a, b := testKEK(t), testKEK(t)
	sealed, err := Seal(a, "secret")
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(sealed, KeyID(a), KeyID(b), 1)
	if _, err := NewKeyring(a, b).Open(forged); err == nil {
		t.Error("a relabelled key id must not open")
	}
}

func TestParseKeyring(t *testing.T) {
	k1 := base64.StdEncoding.EncodeToString(v1FixtureKEK)
	k2 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	r, err := ParseKeyring(k2, " "+k1+" ,")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := r.Open(v1Fixture); err != nil || pt != v1FixturePlaintext {
		t.Errorf("a previous KEK from the list must open; got %q, %v", pt, err)
	}
	if r, err := ParseKeyring("", ""); err != nil || r != nil {
		t.Errorf("no KEKs must be nil (disabled); got %v, %v", r, err)
	}
	if _, err := ParseKeyring("", k1); err == nil {
		t.Error("previous KEKs without a current one must be rejected")
	}
	if _, err := ParseKeyring(k2, "short"); err == nil {
		t.Error("a malformed previous KEK must be rejected")
	}
}
