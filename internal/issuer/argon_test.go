package issuer

import (
	"errors"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword(h, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("expected match, ok=%v err=%v", ok, err)
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	h, _ := HashPassword("right")
	ok, err := VerifyPassword(h, "wrong")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatal("wrong password must not verify")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	ok, err := VerifyPassword("not-a-phc-string", "x")
	if ok {
		t.Fatal("malformed hash must not verify")
	}
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("want ErrInvalidHash, got %v", err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("identical passwords must produce different hashes (salted)")
	}
}
