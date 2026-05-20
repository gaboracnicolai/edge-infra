// Command controller runs the edge.io CRD controller manager.
//
// It watches Gateway and RouteRule resources, persists them into the
// configuration store, and triggers an xDS reconcile pass on every change.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/controller"
	edgev1alpha1 "github.com/edge-infra/control-plane/internal/controller/api/v1alpha1"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(edgev1alpha1.AddToScheme(scheme))
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	ctrl.SetLogger(logr.FromSlogHandler(log.Handler()))

	if err := run(log); err != nil {
		log.Error("controller exited with error", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pgCtx, pgCancel := context.WithTimeout(rootCtx, 10*time.Second)
	pgStore, err := store.NewPostgresStore(pgCtx, cfg.PostgresDSN)
	pgCancel()
	if err != nil {
		return err
	}
	defer pgStore.Close()

	cache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
	reconciler := xds.NewReconciler(cache, pgStore, cfg.NodeID, log)

	leaderNS := os.Getenv("POD_NAMESPACE")
	if leaderNS == "" {
		leaderNS = "infra"
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		LeaderElection:          true,
		LeaderElectionID:        "edge-controller-leader",
		LeaderElectionNamespace: leaderNS,
	})
	if err != nil {
		return err
	}

	gwReconciler := &controller.GatewayReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Store:   pgStore,
		Trigger: reconciler,
	}
	if err := gwReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	rrReconciler := &controller.RouteRuleReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Store:   pgStore,
		Trigger: reconciler,
	}
	if err := rrReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	log.Info("starting controller manager",
		"leader_namespace", leaderNS,
		"leader_id", "edge-controller-leader",
	)
	return mgr.Start(rootCtx)
}
