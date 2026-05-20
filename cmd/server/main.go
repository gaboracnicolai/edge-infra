package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("server exited with error", "err", err)
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

	cache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, slogCacheLogger{log: log})
	reconciler := xds.NewReconciler(cache, pgStore, cfg.NodeID, log)

	xdsSrv := serverv3.NewServer(rootCtx, cache, nil)
	grpcSrv := newGRPCServer()
	registerXDS(grpcSrv, xdsSrv)

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("xds gRPC listening", "addr", cfg.ListenAddr, "node_id", cfg.NodeID)
		errCh <- grpcSrv.Serve(lis)
	}()
	go func() {
		errCh <- reconciler.Run(rootCtx, cfg.ReconcileInterval)
	}()

	select {
	case <-rootCtx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			cancel()
			grpcSrv.GracefulStop()
			return err
		}
	}

	grpcSrv.GracefulStop()
	return nil
}

func newGRPCServer() *grpc.Server {
	return grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
}

func registerXDS(s *grpc.Server, x serverv3.Server) {
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(s, x)
	clusterservice.RegisterClusterDiscoveryServiceServer(s, x)
	endpointservice.RegisterEndpointDiscoveryServiceServer(s, x)
	listenerservice.RegisterListenerDiscoveryServiceServer(s, x)
	routeservice.RegisterRouteDiscoveryServiceServer(s, x)
	secretservice.RegisterSecretDiscoveryServiceServer(s, x)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(s, x)
}

type slogCacheLogger struct {
	log *slog.Logger
}

func (l slogCacheLogger) Debugf(format string, args ...interface{}) {
	l.log.Debug("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Infof(format string, args ...interface{}) {
	l.log.Info("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Warnf(format string, args ...interface{}) {
	l.log.Warn("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Errorf(format string, args ...interface{}) {
	l.log.Error("xds-cache", "msg", sprintf(format, args...))
}

func sprintf(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
