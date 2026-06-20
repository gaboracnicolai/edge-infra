package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T, dir, kid string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadKeySetFromDir(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "k1")
	writeTestKey(t, dir, "k2")

	ks, err := LoadKeySet(dir, "k1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	kid, key := ks.Signer()
	if kid != "k1" || key == nil {
		t.Fatalf("active signer wrong: kid=%q key=%v", kid, key)
	}
	if got := len(ks.JWKS().Keys); got != 2 {
		t.Fatalf("JWKS should publish both keys, got %d", got)
	}
}

func TestLoadKeySetMissingActiveKID(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "k1")
	if _, err := LoadKeySet(dir, "nonexistent"); err == nil {
		t.Fatal("expected error when active kid has no key file")
	}
}

func TestLoadKeySetEmptyDir(t *testing.T) {
	if _, err := LoadKeySet(t.TempDir(), "k1"); err == nil {
		t.Fatal("expected error on empty keys dir (fail closed)")
	}
}

func TestJWKSContainsPublicKey(t *testing.T) {
	ks, priv := testKeySet(t)
	set := ks.JWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kid != "test-kid" || k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Fatalf("jwk metadata wrong: %+v", k)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if new(big.Int).SetBytes(nBytes).Cmp(priv.N) != 0 {
		t.Fatal("published modulus does not match the key")
	}
}
