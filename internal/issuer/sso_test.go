package issuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// memUsers is an in-memory SCIMStore + SSOStore, for the handler test.
type memUsers struct {
	mu    sync.Mutex
	users map[string]*SCIMUser
	n     int
}

func (m *memUsers) ListSCIMUsers(_ context.Context, attr, value string, _, _ int) ([]SCIMUser, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SCIMUser
	for _, u := range m.users {
		if attr == "" || (attr == "userName" && strings.EqualFold(u.UserName, value)) {
			out = append(out, *u)
		}
	}
	return out, len(out), nil
}

func (m *memUsers) GetSCIMUser(_ context.Context, id string) (*SCIMUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, ErrUserNotFound
}

func (m *memUsers) CreateSCIMUser(_ context.Context, u SCIMUser) (*SCIMUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.users {
		if strings.EqualFold(x.UserName, u.UserName) {
			return nil, ErrUserExists
		}
	}
	m.n++
	u.ID = "u" + string(rune('0'+m.n))
	u.UserName = strings.ToLower(u.UserName)
	m.users[u.ID] = &u
	c := u
	return &c, nil
}

func (m *memUsers) ReplaceSCIMUser(_ context.Context, id string, u SCIMUser) (*SCIMUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return nil, ErrUserNotFound
	}
	u.ID = id
	m.users[id] = &u
	c := u
	return &c, nil
}

func (m *memUsers) DeleteSCIMUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, id)
	return nil
}

func (m *memUsers) GetLoginByEmail(_ context.Context, email string) (*Login, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if strings.EqualFold(u.UserName, email) {
			return &Login{ID: u.ID, Email: u.UserName, Disabled: !u.Active}, nil
		}
	}
	return nil, ErrUserNotFound
}

// fakeIdP is a minimal OIDC provider: discovery, JWKS, an /auth endpoint that
// signs whoever is set in email straight in, and a PKCE-checking /token.
type fakeIdP struct {
	srv   *httptest.Server
	keys  *KeySet
	email string

	mu    sync.Mutex
	codes map[string]url.Values // code -> the /auth request it answers
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	ks, _ := testKeySet(t)
	idp := &fakeIdP{keys: ks, codes: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/auth",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, ks.JWKS()) })
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := randomToken()
		idp.mu.Lock()
		idp.codes[code] = q
		idp.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		auth, ok := idp.codes[r.PostForm.Get("code")]
		delete(idp.codes, r.PostForm.Get("code"))
		idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != auth.Get("code_challenge") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		kid, key := ks.Signer()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": idp.srv.URL, "aud": auth.Get("client_id"), "sub": "idp-" + idp.email,
			"email": idp.email, "email_verified": true, "nonce": auth.Get("nonce"),
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = kid
		idToken, _ := tok.SignedString(key)
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idToken, "expires_in": 3600})
	})
	idp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// caFile writes the IdP's self-signed certificate where ISSUER_OIDC_CA_FILE
// would point, so the issuer trusts it the way it trusts a real internal CA.
func (idp *fakeIdP) caFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "idp-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// signIn runs the browser's side of the OIDC flow and returns the callback's
// status and body.
func signIn(t *testing.T, srv *Server, idp *fakeIdP) (int, string) {
	t.Helper()
	h := srv.Routes()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sso/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/sso/login = %d %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()

	browser := idp.srv.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := browser.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))

	req := httptest.NewRequest(http.MethodGet, "/sso/callback?"+back.RawQuery, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func scimDo(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+testSCIMToken)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

const testSCIMToken = "scim-token-0123456789abcdef0123456789"

// A user the IdP provisions over SCIM signs in through OIDC and gets a gateway
// token naming them; before provisioning, and after SCIM deactivates them, the
// same IdP sign-in is refused.
func TestSCIMProvisionedUserSignsInThroughOIDC(t *testing.T) {
	idp := newFakeIdP(t)
	idp.email = "Ada@Corp.example"
	ks, _ := testKeySet(t)
	srv := NewServer(&fakeStore{}, NewMinter(ks, "iss", "aud", time.Hour), ks, slog.New(slog.NewTextHandler(io.Discard, nil)))
	users := &memUsers{users: map[string]*SCIMUser{}}
	srv.EnableSCIM(users, testSCIMToken)
	if err := srv.EnableSSO(SSOConfig{
		Issuer: idp.srv.URL, ClientID: "edge", ClientSecret: "s3cret",
		RedirectURL: "https://issuer.example/sso/callback", CAFile: idp.caFile(t),
	}, users); err != nil {
		t.Fatal(err)
	}

	if code, body := signIn(t, srv, idp); code != http.StatusForbidden {
		t.Fatalf("before SCIM: sign-in = %d %s, want 403", code, body)
	}

	if rec := scimDo(t, srv, http.MethodGet, "/scim/v2/Users", ""); rec.Code != http.StatusOK {
		t.Fatalf("SCIM list = %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SCIM without the bearer token = %d, want 401", rec.Code)
	}

	rec = scimDo(t, srv, http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"ada@corp.example","name":{"givenName":"Ada","familyName":"Lovelace"},"active":true,"externalId":"okta-1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("SCIM create = %d %s", rec.Code, rec.Body)
	}
	var created scimUserOut
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.DisplayName != "Ada Lovelace" || created.ExternalID != "okta-1" || !created.Active {
		t.Fatalf("SCIM create echoed %+v", created)
	}
	if rec := scimDo(t, srv, http.MethodPost, "/scim/v2/Users", `{"userName":"ADA@corp.example"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate SCIM create = %d, want 409", rec.Code)
	}

	code, body := signIn(t, srv, idp)
	if code != http.StatusOK {
		t.Fatalf("after SCIM: sign-in = %d %s, want 200", code, body)
	}
	var lr loginResponse
	_ = json.Unmarshal([]byte(body), &lr)
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(lr.AccessToken, claims, func(*jwt.Token) (any, error) {
		_, k := ks.Signer()
		return &k.PublicKey, nil
	}); err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims["email"] != "ada@corp.example" || claims["sub"] != created.ID {
		t.Fatalf("token names %v / %v, want ada@corp.example / %s", claims["email"], claims["sub"], created.ID)
	}

	// Entra ID deactivates with a string boolean.
	rec = scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+created.ID,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("SCIM deactivate = %d %s", rec.Code, rec.Body)
	}
	if code, body := signIn(t, srv, idp); code != http.StatusForbidden {
		t.Fatalf("after SCIM deactivate: sign-in = %d %s, want 403", code, body)
	}
}
