package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

// clientIP is the remote host of the request, used (with the account) as the
// brute-force throttle key. RemoteAddr only — the issuer is not fronted by an
// untrusted proxy for /login, so X-Forwarded-For is deliberately NOT trusted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LoginStore is the store surface the HTTP layer needs. An interface so the
// handlers can be tested against a fake without a database.
type LoginStore interface {
	GetLogin(ctx context.Context, email string) (*Login, error)
	Ping(ctx context.Context) error
}

// Server wires the issuer's HTTP endpoints.
type Server struct {
	store  LoginStore
	minter *Minter
	keys   *KeySet
	log    *slog.Logger
	// dummyHash equalizes verification time for unknown users so a caller
	// cannot distinguish "no such user" from "wrong password" by timing.
	dummyHash string
	// throttle gates repeated failed logins per (client IP + account) before the
	// expensive argon2 verify runs.
	throttle *Throttle
}

// NewServer constructs the HTTP server.
func NewServer(store LoginStore, minter *Minter, keys *KeySet, log *slog.Logger) *Server {
	dummy, _ := HashPassword("unused-timing-equalizer")
	// 5 consecutive failures per (IP+account) → lock, 1s doubling up to 15m.
	throttle := NewThrottle(5, time.Second, 15*time.Minute)
	return &Server{store: store, minter: minter, keys: keys, log: log, dummyHash: dummy, throttle: throttle}
}

// Routes returns the mux. Method-qualified patterns require Go 1.22+.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Brute-force gate: throttle repeated failures per (client IP + account)
	// BEFORE the expensive argon2 verify (a 64 MiB DoS amplifier) — and before
	// the DB lookup. Keyed so an attacker can neither lock other accounts nor
	// lock a victim's own IP.
	key := clientIP(r) + "|" + req.Email
	if ok, retry := s.throttle.Allow(key); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}

	login, err := s.store.GetLogin(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Verify against a throwaway hash so an unknown email takes the
			// same time as a known one — no user-enumeration oracle.
			_, _ = VerifyPassword(s.dummyHash, req.Password)
			s.throttle.Fail(key)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		// An infrastructure error is not an auth failure — do not count it.
		s.log.Error("login lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Fail closed: a disabled account or any password mismatch is denied with
	// the same generic message, so the response never reveals which check
	// failed.
	if login.Disabled {
		s.throttle.Fail(key)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok, err := VerifyPassword(login.PasswordHash, req.Password)
	if err != nil || !ok {
		s.throttle.Fail(key)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := s.minter.Mint(time.Now(), login.ID, login.Email, login.Teams)
	if err != nil {
		s.log.Error("mint failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.throttle.Reset(key) // a successful login clears this key's failure count
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.minter.TTL().Seconds()),
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.keys.JWKS())
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
