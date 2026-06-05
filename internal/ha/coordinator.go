package ha

import "context"

// Coordinator externalizes xDS snapshot state across control-plane replicas.
// A nil Coordinator means single-instance mode — the Reconciler falls back to
// its local in-process counter and hash.
type Coordinator interface {
	// LoadHash returns the last shared snapshot hash and the version it was
	// stamped with. Returns ("", 0, nil) if no snapshot has been recorded yet.
	LoadHash(ctx context.Context) (hash string, version uint64, err error)

	// StoreHash records hash as the current snapshot and returns the version to
	// stamp on the snapshot. If another replica already recorded the same hash,
	// the existing version is returned unchanged so all replicas agree on one
	// version per config change.
	StoreHash(ctx context.Context, hash string) (version uint64, err error)

	// Heartbeat refreshes this instance's liveness record in the shared store.
	// Call on a short interval (≤ 5 s) so peer instances can detect failures.
	Heartbeat(ctx context.Context) error
}
