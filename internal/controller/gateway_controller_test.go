package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/edge-infra/control-plane/internal/controller"
	edgev1alpha1 "github.com/edge-infra/control-plane/internal/controller/api/v1alpha1"
	"github.com/edge-infra/control-plane/internal/store"
)

var (
	testEnv    *envtest.Environment
	testCfg    *rest.Config
	testScheme = runtime.NewScheme()
	setupOnce  sync.Once
	setupErr   error
	errSkip    = errors.New("KUBEBUILDER_ASSETS not set; install with `setup-envtest use 1.30.0`")
)

func setupSuite(t *testing.T) (*rest.Config, *runtime.Scheme) {
	t.Helper()
	setupOnce.Do(func() {
		utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
		utilruntime.Must(edgev1alpha1.AddToScheme(testScheme))

		if os.Getenv("KUBEBUILDER_ASSETS") == "" {
			setupErr = errSkip
			return
		}
		crdPath, err := findCRDsDir()
		if err != nil {
			setupErr = err
			return
		}
		env := &envtest.Environment{
			CRDDirectoryPaths:     []string{crdPath},
			ErrorIfCRDPathMissing: true,
		}
		cfg, err := env.Start()
		if err != nil {
			setupErr = err
			return
		}
		testEnv = env
		testCfg = cfg
	})
	if setupErr != nil {
		t.Skipf("envtest unavailable: %v", setupErr)
	}
	return testCfg, testScheme
}

func findCRDsDir() (string, error) {
	for _, c := range []string{"../../k8s/crds", "../../../k8s/crds"} {
		p, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("k8s/crds directory not found")
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testEnv != nil {
		_ = testEnv.Stop()
	}
	os.Exit(code)
}

// recordingStore captures every Store mutation for assertions.
type recordingStore struct {
	mu              sync.Mutex
	upsertGateways  []store.Gateway
	deleteGateways  []string
	upsertRoutes    []store.Route
	deleteRoutes    [][2]string
	upsertGatewayErr error
	upsertRouteErr   error
}

func (s *recordingStore) LoadSnapshot(_ context.Context) (*store.Snapshot, error) {
	return &store.Snapshot{}, nil
}

func (s *recordingStore) UpsertGateway(_ context.Context, g store.Gateway) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upsertGatewayErr != nil {
		return s.upsertGatewayErr
	}
	s.upsertGateways = append(s.upsertGateways, g)
	return nil
}

func (s *recordingStore) DeleteGateway(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteGateways = append(s.deleteGateways, name)
	return nil
}

func (s *recordingStore) UpsertRoute(_ context.Context, r store.Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upsertRouteErr != nil {
		return s.upsertRouteErr
	}
	s.upsertRoutes = append(s.upsertRoutes, r)
	return nil
}

func (s *recordingStore) DeleteRoute(_ context.Context, gw, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRoutes = append(s.deleteRoutes, [2]string{gw, path})
	return nil
}

func (s *recordingStore) Close() {}

func (s *recordingStore) gatewayUpserts() []store.Gateway {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Gateway, len(s.upsertGateways))
	copy(out, s.upsertGateways)
	return out
}

func (s *recordingStore) gatewayDeletes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.deleteGateways))
	copy(out, s.deleteGateways)
	return out
}

func (s *recordingStore) routeUpserts() []store.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Route, len(s.upsertRoutes))
	copy(out, s.upsertRoutes)
	return out
}

type recordingTrigger struct {
	count atomic.Int32
}

func (t *recordingTrigger) TriggerNow() { t.count.Add(1) }

func (t *recordingTrigger) Count() int { return int(t.count.Load()) }

func newClient(t *testing.T, cfg *rest.Config, scheme *runtime.Scheme) client.Client {
	t.Helper()
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return c
}

func makeNamespace(t *testing.T, ctx context.Context, c client.Client, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := c.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace %s: %v", name, err)
	}
}

func reconcileUntilStable(t *testing.T, ctx context.Context, r *controller.GatewayReconciler, key types.NamespacedName) {
	t.Helper()
	for i := 0; i < 5; i++ {
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
		if res.RequeueAfter == 0 && !res.Requeue {
			return
		}
	}
}

func TestGatewayController_CreatePersistsAndTriggers(t *testing.T) {
	cfg, scheme := setupSuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newClient(t, cfg, scheme)
	ns := "gw-create"
	makeNamespace(t, ctx, c, ns)

	s := &recordingStore{}
	trig := &recordingTrigger{}
	r := &controller.GatewayReconciler{Client: c, Scheme: scheme, Store: s, Trigger: trig}

	gw := &edgev1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-http", Namespace: ns},
		Spec: edgev1alpha1.GatewaySpec{
			Name: "edge-http", Protocol: "HTTP", Port: 8080, UpstreamClusterName: "api-cluster",
		},
	}
	require.NoError(t, c.Create(ctx, gw))

	key := types.NamespacedName{Name: gw.Name, Namespace: ns}
	reconcileUntilStable(t, ctx, r, key)

	upserts := s.gatewayUpserts()
	require.NotEmpty(t, upserts, "UpsertGateway should have been called")
	assert.Equal(t, "edge-http", upserts[len(upserts)-1].Name)
	assert.Equal(t, uint32(8080), upserts[len(upserts)-1].Port)
	assert.GreaterOrEqual(t, trig.Count(), 1)

	var fetched edgev1alpha1.Gateway
	require.NoError(t, c.Get(ctx, key, &fetched))
	assert.True(t, fetched.Status.Synced)
	assert.Contains(t, fetched.Finalizers, edgev1alpha1.ControllerFinalizer)
}

func TestGatewayController_UpdateReupserts(t *testing.T) {
	cfg, scheme := setupSuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newClient(t, cfg, scheme)
	ns := "gw-update"
	makeNamespace(t, ctx, c, ns)

	s := &recordingStore{}
	trig := &recordingTrigger{}
	r := &controller.GatewayReconciler{Client: c, Scheme: scheme, Store: s, Trigger: trig}

	gw := &edgev1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-http", Namespace: ns},
		Spec: edgev1alpha1.GatewaySpec{
			Name: "edge-http", Protocol: "HTTP", Port: 8080, UpstreamClusterName: "api",
		},
	}
	require.NoError(t, c.Create(ctx, gw))

	key := types.NamespacedName{Name: gw.Name, Namespace: ns}
	reconcileUntilStable(t, ctx, r, key)
	firstCount := len(s.gatewayUpserts())

	require.NoError(t, c.Get(ctx, key, gw))
	gw.Spec.Port = 9090
	require.NoError(t, c.Update(ctx, gw))

	reconcileUntilStable(t, ctx, r, key)

	upserts := s.gatewayUpserts()
	assert.Greater(t, len(upserts), firstCount, "second reconcile should add another upsert")
	assert.Equal(t, uint32(9090), upserts[len(upserts)-1].Port)
}

func TestGatewayController_DeleteRemovesFromStore(t *testing.T) {
	cfg, scheme := setupSuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newClient(t, cfg, scheme)
	ns := "gw-delete"
	makeNamespace(t, ctx, c, ns)

	s := &recordingStore{}
	trig := &recordingTrigger{}
	r := &controller.GatewayReconciler{Client: c, Scheme: scheme, Store: s, Trigger: trig}

	gw := &edgev1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-https", Namespace: ns},
		Spec: edgev1alpha1.GatewaySpec{
			Name: "edge-https", Protocol: "HTTPS", Port: 8443,
			TLSSecretName: "edge-cert", UpstreamClusterName: "api",
		},
	}
	require.NoError(t, c.Create(ctx, gw))

	key := types.NamespacedName{Name: gw.Name, Namespace: ns}
	reconcileUntilStable(t, ctx, r, key)

	require.NoError(t, c.Delete(ctx, gw))
	reconcileUntilStable(t, ctx, r, key)

	deletes := s.gatewayDeletes()
	require.NotEmpty(t, deletes)
	assert.Contains(t, deletes, "edge-https")

	// Final reconcile after finalizer removal — CR should be gone.
	_, _ = r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	var leftover edgev1alpha1.Gateway
	err := c.Get(ctx, key, &leftover)
	assert.True(t, apierrors.IsNotFound(err), "CR should be deleted once finalizer is removed")
}

func TestGatewayController_StoreErrorMarksSyncedFalse(t *testing.T) {
	cfg, scheme := setupSuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newClient(t, cfg, scheme)
	ns := "gw-err"
	makeNamespace(t, ctx, c, ns)

	s := &recordingStore{upsertGatewayErr: errors.New("simulated db failure")}
	trig := &recordingTrigger{}
	r := &controller.GatewayReconciler{Client: c, Scheme: scheme, Store: s, Trigger: trig}

	gw := &edgev1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-broken", Namespace: ns},
		Spec: edgev1alpha1.GatewaySpec{
			Name: "edge-broken", Protocol: "HTTP", Port: 8080, UpstreamClusterName: "api",
		},
	}
	require.NoError(t, c.Create(ctx, gw))

	key := types.NamespacedName{Name: gw.Name, Namespace: ns}
	// First reconcile installs the finalizer (no upsert attempt yet on this pass when
	// AddFinalizer ran, but our controller does both in one pass — so we still hit the error).
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated db failure")
	assert.Greater(t, res.RequeueAfter, time.Duration(0))

	var fetched edgev1alpha1.Gateway
	require.NoError(t, c.Get(ctx, key, &fetched))
	assert.False(t, fetched.Status.Synced)
}

func TestRouteRuleController_CreatePersistsAndTriggers(t *testing.T) {
	cfg, scheme := setupSuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newClient(t, cfg, scheme)
	ns := "rr-create"
	makeNamespace(t, ctx, c, ns)

	s := &recordingStore{}
	trig := &recordingTrigger{}
	r := &controller.RouteRuleReconciler{Client: c, Scheme: scheme, Store: s, Trigger: trig}

	rule := &edgev1alpha1.RouteRule{
		ObjectMeta: metav1.ObjectMeta{Name: "api-route", Namespace: ns},
		Spec: edgev1alpha1.RouteRuleSpec{
			GatewayRef: "edge-http", PathPrefix: "/api", ClusterRef: "api-cluster",
			Hostnames: []string{"api.example.com"}, TimeoutSeconds: 60,
		},
	}
	require.NoError(t, c.Create(ctx, rule))

	key := types.NamespacedName{Name: rule.Name, Namespace: ns}
	for i := 0; i < 5; i++ {
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
	}

	upserts := s.routeUpserts()
	require.NotEmpty(t, upserts)
	got := upserts[len(upserts)-1]
	assert.Equal(t, "api-route", got.Name)
	assert.Equal(t, "edge-http", got.GatewayName)
	assert.Equal(t, "/api", got.PathPrefix)
	assert.Equal(t, "api-cluster", got.ClusterName)
	assert.Equal(t, 60, got.TimeoutSeconds)
	assert.GreaterOrEqual(t, trig.Count(), 1)
}
