package secrets

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Server wires the edge-secrets HTTP endpoints. Every mutating/metadata route is
// gated on operator auth; healthz/readyz are unauthenticated liveness probes.
type Server struct {
	store    SecretStore
	adminKey string // constant-time fallback; "" disables the key path
	log      *slog.Logger
}

// NewServer constructs the HTTP server.
func NewServer(store SecretStore, adminKey string, log *slog.Logger) *Server {
	return &Server{store: store, adminKey: adminKey, log: log}
}

// Routes returns the mux. Method-qualified patterns require Go 1.22+.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/secrets/{name}", s.requireAuth(s.handlePut))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.requireAuth(s.handleDelete))
	mux.HandleFunc("GET /v1/secrets/{name}", s.requireAuth(s.handleGetMeta))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

// requireAuth gates a handler on operator auth. Fail-closed: unauthorized → 401.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// authorize accepts a request with a verified operator client cert (mTLS against
// the SEPARATE admin CA) OR a constant-time-valid admin key. Fail-closed.
func (s *Server) authorize(r *http.Request) bool {
	// Primary: a verified operator client cert. VerifiedChains is non-empty only
	// when the presented cert chained to the admin CA (the TLS layer already
	// rejected anything else, incl. a data-plane proxy cert).
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		return true
	}
	// Fallback: constant-time admin key.
	return constantTimeMatch(r.Header.Get("X-Admin-Key"), s.adminKey)
}

type putSecretRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validSecretName(name) {
		writeError(w, http.StatusBadRequest, "invalid secret name")
		return
	}
	var req putSecretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateKeyPair(req.CertPEM, req.KeyPEM); err != nil {
		// Never echo the material or a detailed parse error.
		writeError(w, http.StatusBadRequest, "invalid cert/key pair")
		return
	}
	if err := s.store.Upsert(r.Context(), name, req.CertPEM, req.KeyPEM); err != nil {
		s.log.Error("secret upsert failed", "name", name, "err", err) // never the material
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.log.Info("secret upserted", "name", name)
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "ok"})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	deleted, err := s.store.Delete(r.Context(), name)
	if err != nil {
		s.log.Error("secret delete failed", "name", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.log.Info("secret deleted", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetMeta(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	meta, err := s.store.GetMeta(r.Context(), name)
	if errors.Is(err, ErrSecretNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.log.Error("secret meta failed", "name", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Metadata ONLY — never cert/key bytes.
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        meta.Name,
		"fingerprint": meta.Fingerprint,
		"not_after":   meta.NotAfter.UTC().Format(time.RFC3339),
	})
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

// constantTimeMatch compares a presented admin key against the configured one in
// constant time. Empty configured key ⇒ the key path is disabled.
func constantTimeMatch(provided, configured string) bool {
	if configured == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(configured)) == 1
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
