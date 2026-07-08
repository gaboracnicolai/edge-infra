// Package keycrypt seals/opens secret key material at rest with AES-256-GCM
// under a key-encryption key (KEK) supplied out-of-band (env). A versioned
// marker ("enc:v1:") lets Open pass PLAINTEXT through (backward-compat for
// pre-encryption rows) and leaves room for a future rotation scheme (v2). A nil
// KEK disables encryption (Seal/Open are passthrough). KEK rotation itself is a
// deliberate follow-up.
package keycrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Marker prefixes a sealed value. Open treats an unmarked value as plaintext.
const Marker = "enc:v1:"

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

// Seal encrypts plaintext under the KEK → "enc:v1:<base64(nonce||ciphertext)>".
// A nil KEK returns plaintext unchanged (encryption disabled).
func Seal(kek []byte, plaintext string) (string, error) {
	if kek == nil {
		return plaintext, nil
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return Marker + base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal. An unmarked value is returned as-is (plaintext). A marked
// value requires a KEK and authentic ciphertext, else a LOUD error — never
// returns garbage.
func Open(kek []byte, value string) (string, error) {
	if !strings.HasPrefix(value, Marker) {
		return value, nil // plaintext — pre-encryption rows
	}
	if kek == nil {
		return "", errors.New("encrypted secret present but no KEK configured")
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(Marker):])
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
	pt, err := gcm.Open(nil, nonce, ct, nil)
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
