// Package keycrypt seals/opens secret key material at rest with AES-256-GCM
// under a key-encryption key (KEK) supplied out-of-band (env). A versioned
// marker lets Open pass PLAINTEXT through (backward-compat for pre-encryption
// rows). A nil KEK disables encryption (Seal/Open are passthrough).
//
// Two sealed formats:
//
//	enc:v1:<base64(nonce||ciphertext)>        legacy, read-only. It names no
//	                                          key, so Open tries every KEK held.
//	enc:v2:<kid>:<base64(nonce||ciphertext)>  what Seal writes. kid names the
//	                                          KEK, and "enc:v2:<kid>:" is the GCM
//	                                          additional data, so a value
//	                                          relabelled to another kid fails.
//
// KEK rotation: a Keyring seals under its current KEK and opens under the
// current one or any previous one. Re-seal every value that is not IsCurrent,
// and the previous KEK can then be dropped.
package keycrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MarkerV1 prefixes a legacy sealed value (no key id). Open still reads it.
const MarkerV1 = "enc:v1:"

// MarkerV2 prefixes a value sealed under a named KEK: "enc:v2:<kid>:...".
const MarkerV2 = "enc:v2:"

// Marker prefixes what Seal writes today. Open treats an unmarked value as
// plaintext.
const Marker = MarkerV2

// ParseKEK decodes a base64 32-byte AES-256 key. Empty input → nil (encryption
// disabled).
func ParseKEK(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("KEK is not valid base64: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("KEK must decode to 32 bytes (AES-256); got %d", len(k))
	}
	return k, nil
}

// KeyID names a KEK without revealing it: the first 8 bytes of
// HMAC-SHA256(kek, "edge-infra keycrypt kid"), hex.
func KeyID(kek []byte) string {
	m := hmac.New(sha256.New, kek)
	m.Write([]byte("edge-infra keycrypt kid"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

type namedKEK struct {
	id  string
	kek []byte
}

// Keyring holds the current KEK, which seals, and any previous KEKs, which
// only open. A nil *Keyring is encryption disabled.
type Keyring struct {
	current  namedKEK
	previous []namedKEK
}

// NewKeyring builds a keyring sealing under current and opening under current
// and every previous KEK. A nil current returns nil (encryption disabled).
func NewKeyring(current []byte, previous ...[]byte) *Keyring {
	if current == nil {
		return nil
	}
	r := &Keyring{current: namedKEK{KeyID(current), current}}
	seen := map[string]bool{r.current.id: true}
	for _, p := range previous {
		if p == nil || seen[KeyID(p)] {
			continue
		}
		seen[KeyID(p)] = true
		r.previous = append(r.previous, namedKEK{KeyID(p), p})
	}
	return r
}

// ParseKeyring parses the current KEK (base64) and a comma-separated list of
// previous KEKs (base64, may be empty). Previous KEKs without a current one is
// a misconfiguration, not "encryption disabled".
func ParseKeyring(currentB64, previousB64 string) (*Keyring, error) {
	cur, err := ParseKEK(currentB64)
	if err != nil {
		return nil, err
	}
	var prev [][]byte
	for i, p := range strings.Split(previousB64, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		k, err := ParseKEK(p)
		if err != nil {
			return nil, fmt.Errorf("previous KEK %d: %w", i+1, err)
		}
		prev = append(prev, k)
	}
	if cur == nil && len(prev) > 0 {
		return nil, errors.New("previous KEKs given without a current KEK")
	}
	return NewKeyring(cur, prev...), nil
}

// KeyID names the KEK this keyring seals under ("" when encryption is off).
func (r *Keyring) KeyID() string {
	if r == nil {
		return ""
	}
	return r.current.id
}

// IsCurrent reports whether value is already sealed under the current KEK, so
// a re-seal can skip it.
func (r *Keyring) IsCurrent(value string) bool {
	return r != nil && strings.HasPrefix(value, MarkerV2+r.current.id+":")
}

// Seal encrypts plaintext under the current KEK →
// "enc:v2:<kid>:<base64(nonce||ciphertext)>". A nil keyring returns plaintext
// unchanged (encryption disabled).
func (r *Keyring) Seal(plaintext string) (string, error) {
	if r == nil {
		return plaintext, nil
	}
	gcm, err := newGCM(r.current.kek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	prefix := MarkerV2 + r.current.id + ":"
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(prefix))
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal, for either format. An unmarked value is returned as-is
// (plaintext). A marked value needs a KEK this keyring holds and authentic
// ciphertext, else a LOUD error — never returns garbage.
func (r *Keyring) Open(value string) (string, error) {
	switch {
	case strings.HasPrefix(value, MarkerV2):
		if r == nil {
			return "", errors.New("encrypted secret present but no KEK configured")
		}
		kid, body, ok := strings.Cut(value[len(MarkerV2):], ":")
		if !ok {
			return "", errors.New("sealed secret has no key id")
		}
		k, ok := r.find(kid)
		if !ok {
			return "", fmt.Errorf("secret sealed under KEK %s, which is not held (current KEK %s)", kid, r.current.id)
		}
		return open(k.kek, body, []byte(MarkerV2+kid+":"))
	case strings.HasPrefix(value, MarkerV1):
		if r == nil {
			return "", errors.New("encrypted secret present but no KEK configured")
		}
		var err error
		for _, k := range append([]namedKEK{r.current}, r.previous...) {
			var pt string
			if pt, err = open(k.kek, value[len(MarkerV1):], nil); err == nil {
				return pt, nil
			}
		}
		return "", err
	default:
		return value, nil // plaintext — pre-encryption rows
	}
}

func (r *Keyring) find(kid string) (namedKEK, bool) {
	if r.current.id == kid {
		return r.current, true
	}
	for _, k := range r.previous {
		if k.id == kid {
			return k, true
		}
	}
	return namedKEK{}, false
}

// Seal encrypts plaintext under kek (see Keyring.Seal). A nil KEK returns
// plaintext unchanged (encryption disabled).
func Seal(kek []byte, plaintext string) (string, error) {
	return NewKeyring(kek).Seal(plaintext)
}

// Open reverses Seal under a single KEK (see Keyring.Open).
func Open(kek []byte, value string) (string, error) {
	return NewKeyring(kek).Open(value)
}

// open decrypts base64(nonce||ciphertext) under kek with the given additional
// data (nil for v1).
func open(kek []byte, b64 string, aad []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode sealed secret: %w", err)
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("sealed secret too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt secret (wrong KEK or corrupt ciphertext): %w", err)
	}
	return string(pt), nil
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
