package issuer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KeySet holds the RSA signing keys loaded from the mounted Secret directory,
// keyed by kid. One key is "active" (used to sign); every key's public half is
// published in the JWKS so a key can be rotated in (as the next active) while
// the auth-service's background JWKS refresh catches up.
type KeySet struct {
	keys      map[string]*rsa.PrivateKey
	activeKID string
}

// LoadKeySet reads every <kid>.pem private key from dir and marks activeKID as
// the signer. It fails closed: an empty dir, an unparseable key, or an
// activeKID with no matching file is an error (the issuer must not start
// without a usable signing key).
func LoadKeySet(dir, activeKID string) (*KeySet, error) {
	if activeKID == "" {
		return nil, fmt.Errorf("active kid must be set")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read keys dir %s: %w", dir, err)
	}

	keys := make(map[string]*rsa.PrivateKey)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		kid := strings.TrimSuffix(e.Name(), ".pem")
		path := filepath.Join(dir, e.Name())
		key, err := parseRSAPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", kid, err)
		}
		keys[kid] = key
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no .pem signing keys found in %s", dir)
	}
	if _, ok := keys[activeKID]; !ok {
		return nil, fmt.Errorf("active kid %q has no matching key in %s", activeKID, dir)
	}
	return &KeySet{keys: keys, activeKID: activeKID}, nil
}

func parseRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	// Accept PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY").
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return key, nil
}

// Signer returns the active kid and its private key for signing.
func (ks *KeySet) Signer() (string, *rsa.PrivateKey) {
	return ks.activeKID, ks.keys[ks.activeKID]
}

// JWK is one RSA public key in JWKS form (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS builds the public key set for every loaded key, sorted by kid for a
// stable response.
func (ks *KeySet) JWKS() JWKS {
	kids := make([]string, 0, len(ks.keys))
	for kid := range ks.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)

	out := JWKS{Keys: make([]JWK, 0, len(kids))}
	for _, kid := range kids {
		pub := &ks.keys[kid].PublicKey
		out.Keys = append(out.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return out
}
