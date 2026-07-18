package main

import (
	"context"
	"log/slog"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/edge-infra/control-plane/internal/xds"
)

// onConnectCallbacks implements serverv3.Callbacks. It watches for Envoy nodes
// that connect without an existing snapshot and immediately triggers the
// reconciler so new nodes get their config within milliseconds instead of
// waiting up to one full reconcile interval.
type onConnectCallbacks struct {
	reconciler *xds.Reconciler
	cache      cachev3.SnapshotCache
	log        *slog.Logger
}

func (cb *onConnectCallbacks) OnStreamRequest(_ int64, req *discovery.DiscoveryRequest) error {
	if req.Node == nil || req.Node.Id == "" {
		return nil
	}
	// Record the version this node has ACKed so the divergence metric can count nodes
	// that have not acknowledged the current published config. CDS is the
	// representative wildcard type (the one the #47 version collision withheld); its
	// request version_info is the version the node currently holds.
	if req.GetTypeUrl() == resourcev3.ClusterType {
		cb.reconciler.RecordNodeAck(req.Node.Id, req.GetVersionInfo())
	}
	if _, err := cb.cache.GetSnapshot(req.Node.Id); err != nil {
		// No snapshot yet for this node — push one immediately rather than
		// waiting for the next reconcile tick.
		cb.log.Info("new node connected, triggering reconcile", "node_id", req.Node.Id)
		cb.reconciler.TriggerNow()
	}
	return nil
}

// OnStreamOpen/OnStreamClosed track the live xDS stream count (edge_cp_grpc_streams_active)
// and clear a node's ACK state on disconnect so it is not counted as behind.

func (cb *onConnectCallbacks) OnStreamOpen(_ context.Context, _ int64, _ string) error {
	cb.reconciler.StreamOpened()
	return nil
}

func (cb *onConnectCallbacks) OnStreamClosed(_ int64, node *core.Node) {
	cb.reconciler.StreamClosed()
	if node != nil && node.Id != "" {
		cb.reconciler.ForgetNode(node.Id)
	}
}
func (cb *onConnectCallbacks) OnDeltaStreamOpen(_ context.Context, _ int64, _ string) error {
	return nil
}
func (cb *onConnectCallbacks) OnDeltaStreamClosed(_ int64, _ *core.Node) {}
func (cb *onConnectCallbacks) OnStreamDeltaRequest(_ int64, _ *discovery.DeltaDiscoveryRequest) error {
	return nil
}
func (cb *onConnectCallbacks) OnStreamDeltaResponse(_ int64, _ *discovery.DeltaDiscoveryRequest, _ *discovery.DeltaDiscoveryResponse) {
}
func (cb *onConnectCallbacks) OnStreamResponse(_ context.Context, _ int64, _ *discovery.DiscoveryRequest, _ *discovery.DiscoveryResponse) {
}
func (cb *onConnectCallbacks) OnFetchRequest(_ context.Context, _ *discovery.DiscoveryRequest) error {
	return nil
}
func (cb *onConnectCallbacks) OnFetchResponse(_ *discovery.DiscoveryRequest, _ *discovery.DiscoveryResponse) {
}
