// Package licence reads a Talyvor Edge licence: a token Talyvor signs with
// Ed25519 naming who may run Edge, under which plan, and until when.
//
// The check is offline — it needs only the token and Talyvor's public key, never
// the network — and it is advisory. An expired, missing or unverifiable licence
// is reported (a log line and the edge_licence_valid metric), and nothing else
// changes: no route, listener or certificate depends on it, so traffic is never
// dropped for a licence. docs/licence.md is the operator's guide.
//
// A token is three dot-separated parts:
//
//	talyvor-edge-licence-v1.<payload>.<signature>
//
// payload is the base64url (unpadded) JSON of Licence; signature is the
// base64url Ed25519 signature over the first two parts as written, prefix and
// dot included, so a token cannot be replayed under another format.
package licence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Prefix is a token's first part.
const Prefix = "talyvor-edge-licence-v1"

// TalyvorKeys are the public keys Talyvor signs Edge licences with (base64, the
// raw 32 bytes), trusted by every build. Add Talyvor's with `licence keygen`;
// its private half never enters this repository.
var TalyvorKeys = []string{}

// Licence is what a token's payload says.
type Licence struct {
	ID        string    `json:"id"`
	Licensee  string    `json:"licensee"`
	Plan      string    `json:"plan"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// State is the result of checking an installed licence.
type State string

const (
	Valid   State = "valid"   // signed by a trusted key and not yet expired
	Expired State = "expired" // signed by a trusted key, past its expires_at
	Invalid State = "invalid" // unreadable, or not signed by a trusted key
	Missing State = "missing" // no licence installed
)

// Status is one check of the installed licence. Licence is set for Valid and
// Expired; Err says why for Invalid and Missing.
type Status struct {
	State   State
	Licence *Licence
	Err     error
}

// Sign returns l as a token signed by key.
func Sign(l Licence, key ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	signed := Prefix + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(key, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify returns the licence in token if one of keys signed it. It does not
// look at the expiry: Check does.
func Verify(token string, keys []ed25519.PublicKey) (*Licence, error) {
	token = strings.TrimSpace(token)
	cut := strings.LastIndexByte(token, '.')
	if cut < 0 || !strings.HasPrefix(token, Prefix+".") {
		return nil, errors.New("not a Talyvor Edge licence")
	}
	signed := token[:cut]
	sig, err := base64.RawURLEncoding.DecodeString(token[cut+1:])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("the licence's signature is malformed")
	}
	if len(keys) == 0 {
		return nil, errors.New("no licence key is trusted")
	}
	trusted := false
	for _, k := range keys {
		if ed25519.Verify(k, []byte(signed), sig) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, errors.New("the licence is not signed by a trusted key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(signed[len(Prefix)+1:])
	if err != nil {
		return nil, errors.New("the licence's payload is malformed")
	}
	var l Licence
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("the licence's payload is malformed: %w", err)
	}
	if l.ExpiresAt.IsZero() {
		return nil, errors.New("the licence has no expiry")
	}
	return &l, nil
}

// Check verifies token and compares its expiry with now.
func Check(token string, keys []ed25519.PublicKey, now time.Time) Status {
	l, err := Verify(token, keys)
	if err != nil {
		return Status{State: Invalid, Err: err}
	}
	if !now.Before(l.ExpiresAt) {
		return Status{State: Expired, Licence: l}
	}
	return Status{State: Valid, Licence: l}
}

// CheckFile checks the licence installed at path. A path with no file is
// Missing; so is an empty file.
func CheckFile(path string, keys []ed25519.PublicKey, now time.Time) Status {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(b)) == 0) {
		return Status{State: Missing, Err: fmt.Errorf("no licence at %s", path)}
	}
	if err != nil {
		return Status{State: Invalid, Err: err}
	}
	return Check(string(b), keys, now)
}

// ParsePublicKey reads a public key written as base64 of its raw 32 bytes, as
// `licence keygen` prints it.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a licence public key is base64 of %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// TrustedKeys returns TalyvorKeys and the comma-separated keys in extra. A key
// that cannot be read is left out and named in the error; the rest are returned
// either way, because a licence problem must never stop Edge from starting.
func TrustedKeys(extra string) ([]ed25519.PublicKey, error) {
	all := append([]string{}, TalyvorKeys...)
	for _, s := range strings.Split(extra, ",") {
		if strings.TrimSpace(s) != "" {
			all = append(all, s)
		}
	}
	keys := make([]ed25519.PublicKey, 0, len(all))
	var errs []error
	for i, s := range all {
		k, err := ParsePublicKey(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("key %d: %w", i+1, err))
			continue
		}
		keys = append(keys, k)
	}
	return keys, errors.Join(errs...)
}
