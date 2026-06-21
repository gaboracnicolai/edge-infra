package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeStore is an in-memory LoginStore for handler tests.
type fakeStore struct {
	login *Login
	err   error
}

func (f *fakeStore) GetLogin(_ context.Context, email string) (*Login, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.login == nil || f.login.Email != email {
		return nil, ErrUserNotFound
	}
	return f.login, nil
}

func (f *fakeStore) Ping(context.Context) error { return nil }

func testServer(t *testing.T, store LoginStore) *Server {
	t.Helper()
	ks, _ := testKeySet(t)
	m := NewMinter(ks, "iss", "aud", time.Hour)
	return NewServer(store, m, ks, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func doLogin(t *testing.T, srv *Server, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(loginRequest{Email: email, Password: password})
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestLoginWrongPasswordDenied(t *testing.T) {
	store := &fakeStore{login: &Login{ID: "u1", Email: "a@b.com", PasswordHash: mustHash(t, "right")}}
	rec := doLogin(t, testServer(t, store), "a@b.com", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password must be 401, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestLoginDisabledUserDenied(t *testing.T) {
	store := &fakeStore{login: &Login{ID: "u1", Email: "a@b.com", PasswordHash: mustHash(t, "right"), Disabled: true}}
	rec := doLogin(t, testServer(t, store), "a@b.com", "right")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user must be 401, got %d (%s)", rec.Code, rec.Body)
	}
}

func TestLoginUnknownUserDenied(t *testing.T) {
	rec := doLogin(t, testServer(t, &fakeStore{}), "ghost@b.com", "x")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user must be 401, got %d", rec.Code)
	}
}

func TestLoginValidCredentialsMintsToken(t *testing.T) {
	store := &fakeStore{login: &Login{ID: "u1", Email: "a@b.com", PasswordHash: mustHash(t, "right"), Teams: []string{"eng"}}}
	rec := doLogin(t, testServer(t, store), "a@b.com", "right")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid login must be 200, got %d (%s)", rec.Code, rec.Body)
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" || resp.TokenType != "Bearer" {
		t.Fatalf("response missing token: %+v", resp)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := testServer(t, &fakeStore{})
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks must be 200, got %d", rec.Code)
	}
	var set JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 jwk, got %d", len(set.Keys))
	}
}

func TestHealthzOK(t *testing.T) {
	srv := testServer(t, &fakeStore{})
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz must be 200, got %d", rec.Code)
	}
}
