// Command licence makes and checks Talyvor Edge licences (docs/licence.md).
//
//	licence keygen -out talyvor-licence.key
//	licence issue  -key talyvor-licence.key -licensee "Acme Ltd" -expires 2027-10-06 > licence.txt
//	licence verify -pub <public key> < licence.txt
//
// keygen and issue are Talyvor's: the key file is the private half of the key
// Edge trusts, and never leaves the machine that issues licences. verify is for
// anyone, and like Edge itself it needs no network.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/edge-infra/control-plane/internal/licence"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "licence:", err)
		os.Exit(1)
	}
}

const usage = "usage: licence keygen|issue|verify [flags] (licence <command> -h for its flags)"

func run(args []string, stdin io.Reader, stdout io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout)
	case "issue":
		return issue(args[1:], stdout, now)
	case "verify":
		return verify(args[1:], stdin, stdout, now)
	default:
		return errors.New(usage)
	}
}

// keygen writes a new private key (base64 of its 32-byte seed) to -out, readable
// by its owner only, and prints the public key to trust.
func keygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "file to write the private key to (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func issue(args []string, stdout io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	keyFile := fs.String("key", "", "private key file from keygen")
	licensee := fs.String("licensee", "", "who the licence is for")
	plan := fs.String("plan", "enterprise", "the plan it is sold under")
	expires := fs.String("expires", "", "expiry, as 2027-10-06 (midnight UTC) or RFC 3339")
	id := fs.String("id", "", "licence id (default: a new lic_… id)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || strings.TrimSpace(*licensee) == "" || *expires == "" {
		return errors.New("issue: -key, -licensee and -expires are required")
	}
	exp, err := parseExpiry(*expires)
	if err != nil {
		return err
	}
	if !exp.After(now) {
		return fmt.Errorf("issue: -expires %s is not in the future", exp.Format(time.RFC3339))
	}
	key, err := readPrivateKey(*keyFile)
	if err != nil {
		return err
	}
	if *id == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		*id = "lic_" + hex.EncodeToString(b)
	}
	tok, err := licence.Sign(licence.Licence{
		ID:        *id,
		Licensee:  strings.TrimSpace(*licensee),
		Plan:      *plan,
		IssuedAt:  now.UTC().Truncate(time.Second),
		ExpiresAt: exp,
	}, key)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, tok)
	return nil
}

// verify reads a licence from stdin and says what it is. It fails unless the
// licence is valid now.
func verify(args []string, stdin io.Reader, stdout io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pub := fs.String("pub", "", "public keys to trust beside the built-in ones, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := licence.TrustedKeys(*pub)
	if err != nil {
		return err
	}
	tok, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	s := licence.Check(string(tok), keys, now)
	if s.Licence != nil {
		fmt.Fprintf(stdout, "%s: %s, licensee %q, plan %s, expires %s\n",
			s.State, s.Licence.ID, s.Licence.Licensee, s.Licence.Plan, s.Licence.ExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Fprintf(stdout, "%s: %v\n", s.State, s.Err)
	}
	if s.State != licence.Valid {
		return fmt.Errorf("the licence is %s", s.State)
	}
	return nil
}

func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("-expires %q: want 2027-10-06 or RFC 3339", s)
	}
	return t.UTC(), nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a key from licence keygen", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
