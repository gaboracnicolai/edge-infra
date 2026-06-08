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
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/ha"
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

	// HA mode: wire Redis coordinator when REDIS_ADDR is configured.
	if cfg.RedisAddr != "" {
		rdb := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
		})
		coord := ha.NewRedisCoordinator(rdb, cfg.InstanceID)
		reconciler.WithCoordinator(coord)
		log.Info("ha: Redis coordinator enabled",
			"addr", cfg.RedisAddr,
			"instance_id", cfg.InstanceID,
		)
		go coord.Run(rootCtx, log)
	} else {
		log.Info("ha: running in single-instance mode (set REDIS_ADDR to enable HA)")
	}

	tlsCreds, err := buildTLSCreds(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	if tlsCreds == nil {
		log.Warn("xDS gRPC running WITHOUT TLS — set XDS_TLS_CERT/XDS_TLS_KEY to enable")
	}

	callbacks := &onConnectCallbacks{
		reconciler: reconciler,
		cache:      cache,
		log:        log,
	}

	xdsSrv := serverv3.NewServer(rootCtx, cache, callbacks)
	grpcSrv := newGRPCServer(tlsCreds)
	registerXDS(grpcSrv, xdsSrv)

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	// Buffered for all long-lived goroutines (gRPC, reconciler, health) so each
	// can report its exit without blocking even when the select below has
	// already returned on another's error or on shutdown.
	errCh := make(chan error, 3)
	go func() {
		log.Info("xds gRPC listening", "addr", cfg.ListenAddr, "node_id", cfg.NodeID)
		errCh <- grpcSrv.Serve(lis)
	}()
	go func() {
		errCh <- reconciler.Run(rootCtx, cfg.ReconcileInterval)
	}()

	// Health/readiness HTTP server (additive; read-only view of the xDS cache).
	healthSrv := newHealthServer(cfg.HealthAddr, cache, cfg.NodeID)
	go func() {
		errCh <- runHealthServer(rootCtx, healthSrv, log)
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

func newGRPCServer(creds credentials.TransportCredentials) *grpc.Server {
	opts := []grpc.ServerOption{
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
	}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	return grpc.NewServer(opts...)
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
