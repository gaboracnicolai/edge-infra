package issuer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// SSOConfig configures sign-in through the customer's own OIDC identity
// provider (Okta, Entra ID, Google, Keycloak, Dex, ...). The issuer is the
// OIDC client; the IdP vouches for an email, and the issuer mints its usual
// gateway token for the user that email names — so the auth-service keeps
// trusting exactly one issuer, this one.
type SSOConfig struct {
	Issuer       string // ISSUER_OIDC_ISSUER — the IdP's issuer URL (https)
	ClientID     string // ISSUER_OIDC_CLIENT_ID
	ClientSecret string // ISSUER_OIDC_CLIENT_SECRET
	RedirectURL  string // ISSUER_OIDC_REDIRECT_URL — this issuer's /sso/callback as the browser reaches it
	CAFile       string // ISSUER_OIDC_CA_FILE — optional PEM CA the IdP's TLS certificate chains to
}

// SSOStore looks a user up for OIDC sign-in. Only a user that already exists
// (provisioned over SCIM, or added by an operator) and is not disabled may
// sign in: the IdP proves who someone is, the user store says they may enter.
type SSOStore interface {
	GetLoginByEmail(ctx context.Context, email string) (*Login, error)
}

const (
	ssoCookie   = "edge_sso"
	ssoStateTTL = 10 * time.Minute
)

type ssoHandler struct {
	cfg      SSOConfig
	client   *http.Client
	store    SSOStore
	minter   *Minter
	log      *slog.Logger
	stateKey []byte

	mu       sync.Mutex
	provider *oidc.Provider // discovered on first use, so an IdP outage never stops the issuer booting
}

func newSSOHandler(cfg SSOConfig, store SSOStore, minter *Minter, log *slog.Logger) (*ssoHandler, error) {
	client, err := httpClientTrusting(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	// The state cookie is HMAC'd with a key only this issuer knows, derived
	// from the client secret, so every replica can check every other's cookie.
	key := sha256.Sum256([]byte("edge-issuer sso state\x00" + cfg.ClientSecret))
	return &ssoHandler{cfg: cfg, client: client, store: store, minter: minter, log: log, stateKey: key[:]}, nil
}

func httpClientTrusting(caFile string) (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if caFile == "" {
		return client, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_OIDC_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ISSUER_OIDC_CA_FILE %s holds no PEM certificate", caFile)
	}
	client.Transport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return client, nil
}

func (h *ssoHandler) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sso/login", h.login)
	mux.HandleFunc("GET /sso/callback", h.callback)
}

func (h *ssoHandler) oauth() (*oidc.Provider, *oauth2.Config, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.provider == nil {
		p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), h.client), h.cfg.Issuer)
		if err != nil {
			return nil, nil, err
		}
		h.provider = p
	}
	return h.provider, &oauth2.Config{
		ClientID:     h.cfg.ClientID,
		ClientSecret: h.cfg.ClientSecret,
		RedirectURL:  h.cfg.RedirectURL,
		Endpoint:     h.provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}, nil
}

// ssoState is what the browser carries from /sso/login to /sso/callback:
// the CSRF state, the ID-token nonce and the PKCE verifier.
type ssoState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

func (h *ssoHandler) login(w http.ResponseWriter, r *http.Request) {
	_, conf, err := h.oauth()
	if err != nil {
		h.log.Error("oidc discovery failed", "issuer", h.cfg.Issuer, "err", err)
		writeError(w, http.StatusServiceUnavailable, "identity provider unavailable")
		return
	}
	st := ssoState{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Exp:      time.Now().Add(ssoStateTTL).Unix(),
	}
	http.SetCookie(w, &http.Cookie{
		Name: ssoCookie, Value: h.seal(st), Path: "/sso/",
		MaxAge: int(ssoStateTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, conf.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func (h *ssoHandler) callback(w http.ResponseWriter, r *http.Request) {
	st, ok := h.stateFrom(r)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/sso/", MaxAge: -1, HttpOnly: true, Secure: true})
	q := r.URL.Query()
	if !ok || q.Get("state") == "" || !hmac.Equal([]byte(q.Get("state")), []byte(st.State)) {
		writeError(w, http.StatusBadRequest, "sign-in expired or was not started here; start again at /sso/login")
		return
	}
	if e := q.Get("error"); e != "" {
		h.log.Info("identity provider refused sign-in", "error", e)
		writeError(w, http.StatusForbidden, "the identity provider refused sign-in")
		return
	}

	provider, conf, err := h.oauth()
	if err != nil {
		h.log.Error("oidc discovery failed", "issuer", h.cfg.Issuer, "err", err)
		writeError(w, http.StatusServiceUnavailable, "identity provider unavailable")
		return
	}
	ctx := oidc.ClientContext(r.Context(), h.client)
	tok, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		h.log.Warn("oidc code exchange failed", "err", err)
		writeError(w, http.StatusUnauthorized, "sign-in failed")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&oidc.Config{ClientID: h.cfg.ClientID}).Verify(ctx, raw)
	if err != nil || !hmac.Equal([]byte(idt.Nonce), []byte(st.Nonce)) {
		h.log.Warn("oidc id_token rejected", "err", err)
		writeError(w, http.StatusUnauthorized, "sign-in failed")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil || claims.Email == "" ||
		(claims.EmailVerified != nil && !*claims.EmailVerified) {
		writeError(w, http.StatusForbidden, "the identity provider did not vouch for an email address")
		return
	}

	login, err := h.store.GetLoginByEmail(r.Context(), claims.Email)
	if errors.Is(err, ErrUserNotFound) || (err == nil && login.Disabled) {
		h.log.Info("oidc sign-in refused: not provisioned or disabled", "sub", idt.Subject)
		writeError(w, http.StatusForbidden, "this account is not provisioned for sign-in")
		return
	}
	if err != nil {
		h.log.Error("sso lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, err := h.minter.Mint(time.Now(), login.ID, login.Email, login.Teams)
	if err != nil {
		h.log.Error("mint failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.log.Info("oidc sign-in", "user_id", login.ID)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.minter.TTL().Seconds()),
	})
}

func (h *ssoHandler) seal(st ssoState) string {
	body, _ := json.Marshal(st)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + base64.RawURLEncoding.EncodeToString(h.mac(payload))
}

func (h *ssoHandler) stateFrom(r *http.Request) (ssoState, bool) {
	var st ssoState
	c, err := r.Cookie(ssoCookie)
	if err != nil {
		return st, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return st, false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, h.mac(payload)) {
		return st, false
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(body, &st) != nil || time.Now().Unix() > st.Exp {
		return st, false
	}
	return st, true
}

func (h *ssoHandler) mac(payload string) []byte {
	m := hmac.New(sha256.New, h.stateKey)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
