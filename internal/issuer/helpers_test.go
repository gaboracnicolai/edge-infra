package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// testKeySet builds an in-memory KeySet with one freshly generated RSA key,
// active kid "test-kid". White-box (same package) so it can poke the
// unexported fields directly without touching the filesystem.
func testKeySet(t *testing.T) (*KeySet, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &KeySet{
		keys:      map[string]*rsa.PrivateKey{"test-kid": priv},
		activeKID: "test-kid",
	}, priv
}
