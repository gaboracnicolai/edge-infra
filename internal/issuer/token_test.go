package issuer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestMintRoundTrip mints a token and verifies it the same way the
// auth-service does: RS256, kid in header, signature against the public key,
// and the exact claim shape (aud as an array).
func TestMintRoundTrip(t *testing.T) {
	ks, priv := testKeySet(t)
	m := NewMinter(ks, "https://issuer.example.com", "edge.example.com", time.Hour)

	tokenStr, err := m.Mint(time.Now(), "user-123", "ada@example.com", []string{"eng", "platform"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	parsed, err := jwt.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		if tok.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected alg %s", tok.Method.Alg())
		}
		if tok.Header["kid"] != "test-kid" {
			return nil, fmt.Errorf("unexpected kid %v", tok.Header["kid"])
		}
		return &priv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token invalid: %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["email"] != "ada@example.com" {
		t.Errorf("email = %v", claims["email"])
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Errorf("iss = %v", claims["iss"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "edge.example.com" {
		t.Errorf("aud must be a single-element array, got %v", claims["aud"])
	}
	teams, ok := claims["teams"].([]any)
	if !ok || len(teams) != 2 {
		t.Errorf("teams = %v", claims["teams"])
	}
}

func TestMintOmitsEmptyEmailAndTeams(t *testing.T) {
	ks, _ := testKeySet(t)
	m := NewMinter(ks, "iss", "aud", time.Hour)

	tokenStr, err := m.Mint(time.Now(), "u1", "", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(tokenStr, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["email"]; ok {
		t.Error("email must be omitted when empty")
	}
	if _, ok := raw["teams"]; ok {
		t.Error("teams must be omitted when empty")
	}
}
