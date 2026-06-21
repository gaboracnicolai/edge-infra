package issuer

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Minter signs RS256 JWTs whose claims match exactly what the auth-service
// validates: sub, email, teams, iss, aud (array), iat, exp.
type Minter struct {
	keys     *KeySet
	issuer   string
	audience string
	ttl      time.Duration
}

// NewMinter builds a Minter. issuer must equal the auth-service's JWT_ISSUER
// and audience its JWT_AUDIENCE, or the tokens will be rejected downstream.
func NewMinter(keys *KeySet, issuer, audience string, ttl time.Duration) *Minter {
	return &Minter{keys: keys, issuer: issuer, audience: audience, ttl: ttl}
}

// Mint returns a signed JWT for the given identity. email and teams are
// omitted from the token when empty (the auth-service treats both as
// optional). The token header carries the active kid so the auth-service can
// resolve the verifying key from the JWKS.
func (m *Minter) Mint(now time.Time, userID, email string, teams []string) (string, error) {
	kid, key := m.keys.Signer()
	if key == nil {
		return "", errors.New("no active signing key")
	}

	// MapClaims (not RegisteredClaims) so aud is always a JSON array and the
	// claim shape is explicit — the Rust side decodes aud as Vec<String>.
	claims := jwt.MapClaims{
		"sub": userID,
		"iss": m.issuer,
		"aud": []string{m.audience},
		"iat": now.Unix(),
		"exp": now.Add(m.ttl).Unix(),
	}
	if email != "" {
		claims["email"] = email
	}
	if len(teams) > 0 {
		claims["teams"] = teams
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}

// TTL is the token lifetime, exposed so the /login response can report
// expires_in without the handler reaching into the Minter's internals.
func (m *Minter) TTL() time.Duration { return m.ttl }
