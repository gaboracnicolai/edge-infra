package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/secrets"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
)

// The Admin READ API: cmd/server's fourth listener (:18002 by default), beside
// xDS (:18000), health (:18001) and metrics (:2112). It lives HERE because two
// of its five views exist only in this process — the reconciler's per-node ACK
// state and the effective (env-derived) ext_authz flag — and because the
// co-location invariant (store.VerifyColocation) guarantees this process's one
// pool can also read the OSB tables.
//
// READ-ONLY, v1, no exceptions: every route is GET, and /admin/v1/config
// REPORTS the effective ext_authz state without offering any way to change it —
// the flip is an env var, so a UI write path would silently make the UI a
// GitOps writer.
//
// KEY-FREE: handlers only ever call the key-free readers in
// internal/store/admin_read.go — NEVER store.LoadSnapshot, which decrypts
// private keys. The admin leak-guard test (TestAdminLeakGuard_*, plus the
// response-level assertions in every endpoint test) exists to catch exactly
// that mistake.

// adminStore is the read-only, key-free store slice the admin API needs.
// *store.PostgresStore satisfies it. store.Store (the reconciler's contract,
// whose LoadSnapshot decrypts keys) is deliberately NOT embedded here.
type adminStore interface {
	LoadTopology(ctx context.Context) (*store.Topology, error)
	LoadCertificateRows(ctx context.Context) ([]store.CertificateRow, error)
	LoadProvisioning(ctx context.Context, requestLimit int) (*store.Provisioning, error)
}

// adminNodeSource is the read-only reconciler slice: connected-node ACK state
// and reconcile observability. *xds.Reconciler satisfies it.
type adminNodeSource interface {
	NodeStatuses() []xds.NodeStatus
	PublishedVersion() string
	ActiveStreams() int64
	NodesBehind() int
	LastReconcileUnix() int64
	LastReconcileDurationSeconds() float64
}

// adminConfigView is the marshal-ready effective-config report served by
// /admin/v1/config. Values only — no file paths' contents, no credentials —
// and read_only is stamped into the response so no client can mistake this
// surface for a control plane it may write to.
type adminConfigView struct {
	ReadOnly            bool               `json:"read_only"`
	NodeID              string             `json:"node_id"`
	ReconcileIntervalMS int64              `json:"reconcile_interval_ms"`
	XDS                 adminXDSView       `json:"xds"`
	ExtAuthz            adminExtAuthzView  `json:"ext_authz"`
	RateLimitLocal      adminRateLimitView `json:"rate_limit_local"`
	RateLimitService    adminRLSView       `json:"rate_limit_service"`
	HA                  adminHAView        `json:"ha"`
}

type adminXDSView struct {
	ListenAddr string `json:"listen_addr"`
	TLS        bool   `json:"tls"`
	ClientCA   bool   `json:"client_ca"`
}

type adminExtAuthzView struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	TLS     bool   `json:"tls"`
	MTLS    bool   `json:"mtls"`
}

type adminRateLimitView struct {
	Enabled        bool   `json:"enabled"`
	MaxTokens      uint32 `json:"max_tokens"`
	TokensPerFill  uint32 `json:"tokens_per_fill"`
	FillIntervalMS int64  `json:"fill_interval_ms"`
}

type adminRLSView struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Domain  string `json:"domain"`
	TLS     bool   `json:"tls"`
}

type adminHAView struct {
	RedisConfigured bool   `json:"redis_configured"`
	InstanceID      string `json:"instance_id"`
}

// newAdminConfigView projects the process config onto the admin report.
// Presence booleans, never file contents: "tls: true" says a cert path is
// configured, nothing about what is in it.
func newAdminConfigView(cfg *config.Config) adminConfigView {
	return adminConfigView{
		ReadOnly:            true,
		NodeID:              cfg.NodeID,
		ReconcileIntervalMS: cfg.ReconcileInterval.Milliseconds(),
		XDS: adminXDSView{
			ListenAddr: cfg.ListenAddr,
			TLS:        cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
			ClientCA:   cfg.TLSCAFile != "",
		},
		ExtAuthz: adminExtAuthzView{
			Enabled: cfg.ExtAuthzEnabled,
			Address: cfg.ExtAuthzAddress,
			Port:    cfg.ExtAuthzPort,
			TLS:     cfg.ExtAuthzCAFile != "",
			MTLS:    cfg.ExtAuthzCertFile != "" && cfg.ExtAuthzKeyFile != "",
		},
		RateLimitLocal: adminRateLimitView{
			Enabled:        cfg.RateLimitEnabled,
			MaxTokens:      cfg.RateLimitMaxTokens,
			TokensPerFill:  cfg.RateLimitTokensPerFill,
			FillIntervalMS: cfg.RateLimitFillInterval.Milliseconds(),
		},
		RateLimitService: adminRLSView{
			Enabled: cfg.RateLimitServiceEnabled,
			Address: cfg.RateLimitServiceAddress,
			Port:    cfg.RateLimitServicePort,
			Domain:  cfg.RateLimitServiceDomain,
			TLS:     cfg.RateLimitServiceCAFile != "",
		},
		HA: adminHAView{
			RedisConfigured: cfg.RedisAddr != "",
			InstanceID:      cfg.InstanceID,
		},
	}
}

// adminDeps carries everything the admin handlers read. log must be non-nil.
type adminDeps struct {
	store adminStore
	nodes adminNodeSource
	cfg   adminConfigView
	key   string // the configured X-Admin-Key; "" ⇒ every request is refused
	log   *slog.Logger
}

// adminProvisionRequestLimit caps how many provision_requests rows one
// response carries (newest first — recent failures are what an operator needs).
const adminProvisionRequestLimit = 100

// nodesScopeNote is stamped into every /admin/v1/nodes response. The response
// SHAPE carries the caveat, not just the docs: there is no expected-node
// registry anywhere, so a UI must never read "every listed node acked" as
// "all nodes healthy".
const nodesScopeNote = "no expected-node registry exists: entries are nodes with open xDS streams right now; " +
	"a node absent from this list is not connected — absence is not health"

// newAdminHandler builds the /admin/v1 read-only mux: GET-only routes, every
// one behind the constant-time admin key.
func newAdminHandler(d adminDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/topology", d.handleJSON("topology", func(ctx context.Context) (any, error) {
		topo, err := d.store.LoadTopology(ctx)
		if err != nil {
			return nil, err
		}
		return topologyResponseFrom(topo), nil
	}))
	mux.HandleFunc("GET /admin/v1/nodes", d.handleJSON("nodes", func(context.Context) (any, error) {
		return nodesResponseFrom(d.nodes), nil
	}))
	mux.HandleFunc("GET /admin/v1/certificates", d.handleJSON("certificates", func(ctx context.Context) (any, error) {
		rows, err := d.store.LoadCertificateRows(ctx)
		if err != nil {
			return nil, err
		}
		return certificatesResponseFrom(rows), nil
	}))
	mux.HandleFunc("GET /admin/v1/provisioning", d.handleJSON("provisioning", func(ctx context.Context) (any, error) {
		prov, err := d.store.LoadProvisioning(ctx, adminProvisionRequestLimit)
		if err != nil {
			return nil, err
		}
		return provisioningResponseFrom(prov), nil
	}))
	mux.HandleFunc("GET /admin/v1/config", d.handleJSON("config", func(context.Context) (any, error) {
		return d.cfg, nil
	}))
	return mux
}

// handleJSON wraps a loader as an authenticated GET handler. Errors are logged
// and answered generically — internals are never echoed (custodian convention).
func (d adminDeps) handleJSON(name string, load func(ctx context.Context) (any, error)) http.HandlerFunc {
	return d.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		out, err := load(r.Context())
		if err != nil {
			d.log.Error("admin read failed", "endpoint", name, "err", err)
			writeAdminError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeAdminJSON(w, http.StatusOK, out)
	})
}

// ---------------------------------------------------------------------------
// Response DTOs. Deliberately explicit — the admin wire shape is pinned HERE,
// not borrowed from store types, so a future store field (or a naive "just
// marshal the snapshot") can never widen what leaves this process. There is no
// key field anywhere below, and no mapper reads one.
// ---------------------------------------------------------------------------

type topologyResponse struct {
	Gateways  []gatewayDTO  `json:"gateways"`
	Routes    []routeDTO    `json:"routes"`
	Clusters  []clusterDTO  `json:"clusters"`
	Endpoints []endpointDTO `json:"endpoints"`
}

type gatewayDTO struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Port         uint32            `json:"port"`
	Protocol     string            `json:"protocol"`
	TLSSecret    string            `json:"tls_secret"` // a NAME reference — never material
	NodeSelector map[string]string `json:"node_selector"`
}

type routeDTO struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	GatewayID        string   `json:"gateway_id"`
	Hosts            []string `json:"hosts"`
	PathPrefix       string   `json:"path_prefix"`
	ClusterName      string   `json:"cluster_name"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	RateLimitPerUnit int      `json:"rate_limit_per_unit"`
	RateLimitUnit    string   `json:"rate_limit_unit"`
	AuthPolicy       string   `json:"auth_policy"`
	TLSSecretName    string   `json:"tls_secret_name"`       // NAME reference
	ClientCASecret   string   `json:"client_ca_secret_name"` // NAME reference
}

type clusterDTO struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	ConnectTimeoutMS     int64  `json:"connect_timeout_ms"`
	LbPolicy             string `json:"lb_policy"`
	HealthCheckPath      string `json:"health_check_path"`
	HealthCheckIntervalS int    `json:"health_check_interval_s"`
}

type endpointDTO struct {
	ID        string `json:"id"`
	ClusterID string `json:"cluster_id"`
	Address   string `json:"address"`
	Port      uint32 `json:"port"`
	Weight    uint32 `json:"weight"`
}

func topologyResponseFrom(t *store.Topology) topologyResponse {
	out := topologyResponse{
		Gateways:  make([]gatewayDTO, 0, len(t.Gateways)),
		Routes:    make([]routeDTO, 0, len(t.Routes)),
		Clusters:  make([]clusterDTO, 0, len(t.Clusters)),
		Endpoints: make([]endpointDTO, 0, len(t.Endpoints)),
	}
	for _, g := range t.Gateways {
		out.Gateways = append(out.Gateways, gatewayDTO{
			ID: g.ID, Name: g.Name, Port: g.Port, Protocol: g.Protocol,
			TLSSecret: g.TLSSecret, NodeSelector: g.NodeSelector,
		})
	}
	for _, r := range t.Routes {
		hosts := r.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		out.Routes = append(out.Routes, routeDTO{
			ID: r.ID, Name: r.Name, GatewayID: r.GatewayID, Hosts: hosts,
			PathPrefix: r.PathPrefix, ClusterName: r.ClusterName,
			TimeoutSeconds: r.TimeoutSeconds, RateLimitPerUnit: r.RateLimitPerUnit,
			RateLimitUnit: r.RateLimitUnit, AuthPolicy: r.AuthPolicy,
			TLSSecretName: r.TLSSecret, ClientCASecret: r.ClientCASecret,
		})
	}
	for _, c := range t.Clusters {
		out.Clusters = append(out.Clusters, clusterDTO{
			ID: c.ID, Name: c.Name, ConnectTimeoutMS: c.ConnectTimeout.Milliseconds(),
			LbPolicy: c.LbPolicy, HealthCheckPath: c.HealthCheckPath,
			HealthCheckIntervalS: c.HealthCheckIntervalSeconds,
		})
	}
	for _, e := range t.Endpoints {
		out.Endpoints = append(out.Endpoints, endpointDTO{
			ID: e.ID, ClusterID: e.ClusterID, Address: e.Address, Port: e.Port, Weight: e.Weight,
		})
	}
	return out
}

type nodesResponse struct {
	Scope                        string    `json:"scope"`
	Note                         string    `json:"note"`
	PublishedVersion             string    `json:"published_version"`
	ActiveStreams                int64     `json:"active_streams"`
	NodesBehind                  int       `json:"nodes_behind"`
	LastReconcileUnix            int64     `json:"last_reconcile_unix"`
	LastReconcileDurationSeconds float64   `json:"last_reconcile_duration_seconds"`
	Nodes                        []nodeDTO `json:"nodes"`
}

type nodeDTO struct {
	NodeID       string `json:"node_id"`
	AckedVersion string `json:"acked_version"`
	Behind       bool   `json:"behind"`
}

func nodesResponseFrom(src adminNodeSource) nodesResponse {
	statuses := src.NodeStatuses()
	nodes := make([]nodeDTO, 0, len(statuses))
	for _, s := range statuses {
		nodes = append(nodes, nodeDTO{NodeID: s.NodeID, AckedVersion: s.AckedVersion, Behind: s.Behind})
	}
	return nodesResponse{
		Scope:                        "connected-only",
		Note:                         nodesScopeNote,
		PublishedVersion:             src.PublishedVersion(),
		ActiveStreams:                src.ActiveStreams(),
		NodesBehind:                  src.NodesBehind(),
		LastReconcileUnix:            src.LastReconcileUnix(),
		LastReconcileDurationSeconds: src.LastReconcileDurationSeconds(),
		Nodes:                        nodes,
	}
}

type certificatesResponse struct {
	Certificates []certificateDTO `json:"certificates"`
}

type certificateDTO struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint_sha256,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	NotAfter    string `json:"not_after,omitempty"` // RFC3339 UTC — GetMeta's format
	ParseError  bool   `json:"parse_error,omitempty"`
}

func certificatesResponseFrom(rows []store.CertificateRow) certificatesResponse {
	out := certificatesResponse{Certificates: make([]certificateDTO, 0, len(rows))}
	for _, row := range rows {
		info, err := secrets.ParseCertInfo(row.CertPEM)
		if err != nil {
			// Reported, not dropped — an admin list silently missing a row is
			// how an expiry gets missed. No parse detail (custodian convention).
			out.Certificates = append(out.Certificates, certificateDTO{
				Name: row.Name, Kind: row.Kind, ParseError: true,
			})
			continue
		}
		out.Certificates = append(out.Certificates, certificateDTO{
			Name:        row.Name,
			Kind:        row.Kind,
			Fingerprint: info.Fingerprint,
			Issuer:      info.Issuer,
			NotAfter:    info.NotAfter.UTC().Format(time.RFC3339),
		})
	}
	return out
}

type provisioningResponse struct {
	Services     []serviceDTO `json:"services"`
	Requests     []requestDTO `json:"requests"`
	RequestLimit int          `json:"request_limit"`
}

type serviceDTO struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Team          string    `json:"team"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	AuthPolicy    string    `json:"auth_policy"`
	TLSSecretName string    `json:"tls_secret_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type requestDTO struct {
	ID          string     `json:"id"`
	Operation   string     `json:"operation"`
	Status      string     `json:"status"`
	Team        string     `json:"team"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func provisioningResponseFrom(p *store.Provisioning) provisioningResponse {
	out := provisioningResponse{
		Services:     make([]serviceDTO, 0, len(p.Services)),
		Requests:     make([]requestDTO, 0, len(p.Requests)),
		RequestLimit: adminProvisionRequestLimit,
	}
	for _, s := range p.Services {
		out.Services = append(out.Services, serviceDTO{
			ID: s.ID, Name: s.Name, Team: s.Team, Host: s.Host, Port: s.Port,
			Protocol: s.Protocol, AuthPolicy: s.AuthPolicy, TLSSecretName: s.TLSSecretName,
			CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
		})
	}
	for _, r := range p.Requests {
		out.Requests = append(out.Requests, requestDTO{
			ID: r.ID, Operation: r.Operation, Status: r.Status, Team: r.Team,
			Error: r.Error, CreatedAt: r.CreatedAt, CompletedAt: r.CompletedAt,
		})
	}
	return out
}

// newAdminServer builds the admin HTTP server (mirrors newHealthServer).
func newAdminServer(addr string, d adminDeps) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           newAdminHandler(d),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// runAdminServer serves until ctx is cancelled, then drains with a short
// timeout (mirrors runHealthServer/runMetricsServer).
func runAdminServer(ctx context.Context, srv *http.Server, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("admin API listening (read-only)", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requireAuth gates a handler on the constant-time X-Admin-Key match.
// Fail-closed: an empty configured key refuses everything (mirrors the
// custodian's constantTimeMatch — main.go additionally never starts this
// listener without a key).
func (d adminDeps) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !constantTimeMatch(r.Header.Get("X-Admin-Key"), d.key) {
			writeAdminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// constantTimeMatch compares a presented admin key against the configured one
// in constant time. Empty configured key ⇒ refuse (fail closed). Mirrors
// internal/secrets' constantTimeMatch — the custodian auth pattern this API
// copies.
func constantTimeMatch(provided, configured string) bool {
	if configured == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(configured)) == 1
}

func writeAdminJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeAdminJSON(w, status, map[string]string{"error": msg})
}
