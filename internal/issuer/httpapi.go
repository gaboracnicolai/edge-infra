package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
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
}

// NewServer constructs the HTTP server.
func NewServer(store LoginStore, minter *Minter, keys *KeySet, log *slog.Logger) *Server {
	dummy, _ := HashPassword("unused-timing-equalizer")
	return &Server{store: store, minter: minter, keys: keys, log: log, dummyHash: dummy}
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

	login, err := s.store.GetLogin(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		s.log.Error("login lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// NOTE: credential verification (disabled check + password verify) is
	// intentionally absent in this commit so the fail-closed tests prove the
	// hole. The next commit inserts it here.

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

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
