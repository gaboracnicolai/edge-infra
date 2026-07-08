package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edge-infra/control-plane/internal/ratelimit"
)

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
	// SEC-1: /login throttle. Checked BEFORE the expensive argon2id verify, so an attacker cannot
	// force unlimited 64-MiB hashes (DoS amplifier) or brute-force at speed. perIP bounds broad abuse
	// from one source; perAccount bounds targeted brute-force and is robust to IP rotation.
	limiter    *ratelimit.Limiter
	perIP      ratelimit.Rule
	perAccount ratelimit.Rule
}

// NewServer constructs the HTTP server with an in-memory login throttle installed by default (so the
// service is protected out of the box, no external dependency). Use WithThrottle to supply a
// Redis-backed limiter (distributed across replicas) and/or custom ceilings.
func NewServer(store LoginStore, minter *Minter, keys *KeySet, log *slog.Logger) *Server {
	dummy, _ := HashPassword("unused-timing-equalizer")
	return &Server{
		store: store, minter: minter, keys: keys, log: log, dummyHash: dummy,
		limiter:    ratelimit.New(nil), // in-memory; WithThrottle swaps in Redis for multi-replica
		perIP:      ratelimit.Rule{Capacity: 10, RatePerSec: 0.5},
		perAccount: ratelimit.Rule{Capacity: 5, RatePerSec: 0.1},
	}
}

// WithThrottle overrides the login throttle — pass a Redis-backed ratelimit.Limiter for a shared
// per-account/per-IP counter across replicas, and/or custom ceilings. A nil limiter disables throttling.
func (s *Server) WithThrottle(l *ratelimit.Limiter, perIP, perAccount ratelimit.Rule) *Server {
	s.limiter, s.perIP, s.perAccount = l, perIP, perAccount
	return s
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

	// SEC-1: throttle BEFORE any argon2id verify or store lookup. per-IP + per-account; the response
	// is an identical 429 whether the account exists or not (no user-enumeration oracle).
	if s.limiter != nil {
		acct := strings.ToLower(strings.TrimSpace(req.Email))
		ipRes := s.limiter.Check(r.Context(), "login:ip:"+clientIP(r), s.perIP)
		acctRes := s.limiter.Check(r.Context(), "login:acct:"+acct, s.perAccount)
		if !ipRes.Allowed || !acctRes.Allowed {
			retry := ipRes.RetryAfterSec
			if acctRes.RetryAfterSec > retry {
				retry = acctRes.RetryAfterSec
			}
			if retry > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
			}
			writeError(w, http.StatusTooManyRequests, "too many attempts")
			return
		}
	}

	login, err := s.store.GetLogin(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Verify against a throwaway hash so an unknown email takes the
			// same time as a known one — no user-enumeration oracle.
			_, _ = VerifyPassword(s.dummyHash, req.Password)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		s.log.Error("login lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Fail closed: a disabled account or any password mismatch is denied with
	// the same generic message, so the response never reveals which check
	// failed.
	if login.Disabled {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok, err := VerifyPassword(login.PasswordHash, req.Password)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := s.minter.Mint(time.Now(), login.ID, login.Email, login.Teams)
	if err != nil {
		s.log.Error("mint failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
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

// clientIP returns the throttle key's IP. Behind the edge proxy (envoy) the real client is the first
// X-Forwarded-For entry; otherwise the transport peer. XFF is only trustworthy behind a proxy that
// overwrites it (the issuer's deployment) — and the per-account throttle backstops XFF spoofing.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
