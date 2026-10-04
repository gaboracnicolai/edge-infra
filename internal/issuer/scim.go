package issuer

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SCIMStore is the store surface the SCIM endpoints need. An interface so the
// handlers can be tested against a fake without a database.
type SCIMStore interface {
	ListSCIMUsers(ctx context.Context, attr, value string, offset, limit int) ([]SCIMUser, int, error)
	GetSCIMUser(ctx context.Context, id string) (*SCIMUser, error)
	CreateSCIMUser(ctx context.Context, u SCIMUser) (*SCIMUser, error)
	ReplaceSCIMUser(ctx context.Context, id string, u SCIMUser) (*SCIMUser, error)
	DeleteSCIMUser(ctx context.Context, id string) error
}

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimSPCSchema   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimMaxPage     = 200
)

// scimHandler serves SCIM 2.0 (RFC 7643/7644) user provisioning, so the
// customer's IdP (Okta, Entra ID, ...) creates, updates, deactivates and
// deletes the users who may sign in. Every route needs the bearer token.
type scimHandler struct {
	store SCIMStore
	token []byte
	log   *slog.Logger
}

func (h *scimHandler) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", h.auth(h.serviceProviderConfig))
	mux.HandleFunc("GET /scim/v2/Users", h.auth(h.list))
	mux.HandleFunc("POST /scim/v2/Users", h.auth(h.create))
	mux.HandleFunc("GET /scim/v2/Users/{id}", h.auth(h.get))
	mux.HandleFunc("PUT /scim/v2/Users/{id}", h.auth(h.replace))
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", h.auth(h.patch))
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", h.auth(h.delete))
}

func (h *scimHandler) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), h.token) != 1 {
			scimError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
			return
		}
		next(w, r)
	}
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

type scimUserOut struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails"`
	Active      bool        `json:"active"`
	Meta        scimMeta    `json:"meta"`
}

type scimUserIn struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	ExternalID  string `json:"externalId"`
	Active      *bool  `json:"active"`
	Name        *struct {
		Formatted  string `json:"formatted"`
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []scimEmail `json:"emails"`
}

// toUser maps a SCIM resource onto our user. The user's email is its
// userName when that is an address, else its primary (or first) email.
func (in scimUserIn) toUser() (SCIMUser, error) {
	email := in.UserName
	if !strings.Contains(email, "@") {
		email = ""
		for _, e := range in.Emails {
			if email == "" || e.Primary {
				email = e.Value
			}
		}
	}
	email = strings.TrimSpace(email)
	if !validEmail(email) {
		return SCIMUser{}, errors.New("userName (or a primary email) must be an email address")
	}
	display := in.DisplayName
	if display == "" && in.Name != nil {
		display = in.Name.Formatted
		if display == "" {
			display = strings.TrimSpace(in.Name.GivenName + " " + in.Name.FamilyName)
		}
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	return SCIMUser{UserName: email, DisplayName: display, ExternalID: in.ExternalID, Active: active}, nil
}

func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}

func scimResource(r *http.Request, u *SCIMUser) scimUserOut {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scimUserOut{
		Schemas:     []string{scimUserSchema},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		UserName:    u.UserName,
		DisplayName: u.DisplayName,
		Emails:      []scimEmail{{Value: u.UserName, Primary: true}},
		Active:      u.Active,
		Meta: scimMeta{
			ResourceType: "User",
			Created:      u.Created.UTC().Format(time.RFC3339),
			LastModified: u.Updated.UTC().Format(time.RFC3339),
			Location:     scheme + "://" + r.Host + "/scim/v2/Users/" + u.ID,
		},
	}
}

// filterRe matches the only filters IdPs send to look a user up before they
// create one: `userName eq "x"` and `externalId eq "x"`.
var filterRe = regexp.MustCompile(`(?i)^\s*(userName|externalId)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

func (h *scimHandler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var attr, value string
	if f := q.Get("filter"); f != "" {
		m := filterRe.FindStringSubmatch(f)
		if m == nil {
			scimError(w, http.StatusBadRequest, "invalidFilter", `only 'userName eq "..."' and 'externalId eq "..."' are supported`)
			return
		}
		attr = "userName"
		if strings.EqualFold(m[1], "externalId") {
			attr = "externalId"
		}
		value = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[2])
	}
	start := 1
	if v, err := strconv.Atoi(q.Get("startIndex")); err == nil && v > 1 {
		start = v
	}
	count := 100
	if v, err := strconv.Atoi(q.Get("count")); err == nil {
		count = min(max(v, 0), scimMaxPage)
	}

	users, total, err := h.store.ListSCIMUsers(r.Context(), attr, value, start-1, count)
	if err != nil {
		h.internal(w, "scim list", err)
		return
	}
	resources := make([]scimUserOut, 0, len(users))
	for i := range users {
		resources = append(resources, scimResource(r, &users[i]))
	}
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func (h *scimHandler) get(w http.ResponseWriter, r *http.Request) {
	u, err := h.store.GetSCIMUser(r.Context(), r.PathValue("id"))
	if err != nil {
		h.storeError(w, "scim get", err)
		return
	}
	scimJSON(w, http.StatusOK, scimResource(r, u))
}

func (h *scimHandler) create(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM[scimUserIn](w, r)
	if !ok {
		return
	}
	u, err := in.toUser()
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	created, err := h.store.CreateSCIMUser(r.Context(), u)
	if err != nil {
		h.storeError(w, "scim create", err)
		return
	}
	h.log.Info("scim user created", "id", created.ID, "active", created.Active)
	scimJSON(w, http.StatusCreated, scimResource(r, created))
}

func (h *scimHandler) replace(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeSCIM[scimUserIn](w, r)
	if !ok {
		return
	}
	u, err := in.toUser()
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	h.save(w, r, r.PathValue("id"), u, "scim user replaced")
}

type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// patch applies a PatchOp. It supports the attributes this store keeps —
// active, userName, displayName, externalId — with or without a path (Okta
// sends `{"op":"replace","value":{"active":false}}`, Entra ID sends
// `{"op":"Replace","path":"active","value":"False"}`). Attributes the store
// does not keep (title, phoneNumbers, ...) are accepted and ignored, so an
// IdP that pushes its whole profile is not refused.
func (h *scimHandler) patch(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeSCIM[struct {
		Operations []scimPatchOp `json:"Operations"`
	}](w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	u, err := h.store.GetSCIMUser(r.Context(), id)
	if err != nil {
		h.storeError(w, "scim patch", err)
		return
	}
	for _, op := range body.Operations {
		if err := applyPatchOp(u, op); err != nil {
			scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
	}
	if !validEmail(u.UserName) {
		scimError(w, http.StatusBadRequest, "invalidValue", "userName must be an email address")
		return
	}
	h.save(w, r, id, *u, "scim user patched")
}

func applyPatchOp(u *SCIMUser, op scimPatchOp) error {
	switch strings.ToLower(op.Op) {
	case "add", "replace":
		if op.Path == "" {
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &attrs); err != nil {
				return errors.New("a patch without a path needs an object value")
			}
			for k, v := range attrs {
				if err := setAttr(u, k, v); err != nil {
					return err
				}
			}
			return nil
		}
		return setAttr(u, op.Path, op.Value)
	case "remove":
		switch strings.ToLower(op.Path) {
		case "displayname":
			u.DisplayName = ""
		case "externalid":
			u.ExternalID = ""
		}
		return nil
	default:
		return errors.New("unsupported patch op " + strconv.Quote(op.Op))
	}
}

func setAttr(u *SCIMUser, name string, raw json.RawMessage) error {
	switch strings.ToLower(name) {
	case "active":
		b, err := scimBool(raw)
		if err != nil {
			return err
		}
		u.Active = b
	case "username":
		return json.Unmarshal(raw, &u.UserName)
	case "displayname":
		return json.Unmarshal(raw, &u.DisplayName)
	case "externalid":
		return json.Unmarshal(raw, &u.ExternalID)
	}
	return nil
}

// scimBool reads a JSON boolean, or the string form Entra ID sends ("False").
func scimBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if b, err := strconv.ParseBool(strings.ToLower(s)); err == nil {
			return b, nil
		}
	}
	return false, errors.New("active must be a boolean")
}

func (h *scimHandler) save(w http.ResponseWriter, r *http.Request, id string, u SCIMUser, msg string) {
	saved, err := h.store.ReplaceSCIMUser(r.Context(), id, u)
	if err != nil {
		h.storeError(w, msg, err)
		return
	}
	h.log.Info(msg, "id", saved.ID, "active", saved.Active)
	scimJSON(w, http.StatusOK, scimResource(r, saved))
}

func (h *scimHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteSCIMUser(r.Context(), id); err != nil {
		h.storeError(w, "scim delete", err)
		return
	}
	h.log.Info("scim user deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *scimHandler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{scimSPCSchema},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxPage},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{
			"type": "oauthbearertoken", "name": "Bearer token",
			"description": "The token set in ISSUER_SCIM_TOKEN",
		}},
	})
}

func (h *scimHandler) storeError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, ErrUserNotFound):
		scimError(w, http.StatusNotFound, "", "no such user")
	case errors.Is(err, ErrUserExists):
		scimError(w, http.StatusConflict, "uniqueness", "a user with this userName already exists")
	default:
		h.internal(w, what, err)
	}
}

func (h *scimHandler) internal(w http.ResponseWriter, what string, err error) {
	h.log.Error(what+" failed", "err", err)
	scimError(w, http.StatusInternalServerError, "", "internal error")
}

func decodeSCIM[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&v); err != nil {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "request body is not valid SCIM JSON")
		return v, false
	}
	return v, true
}

func scimJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{
		"schemas": []string{scimErrorSchema},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	scimJSON(w, status, body)
}
