package ha

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyHash        = "xds:snapshot:hash"
	keyVersion     = "xds:snapshot:version"
	keyInstancePfx = "xds:instance:"
	instanceTTL    = 15 * time.Second
	heartbeatEvery = 5 * time.Second
)

// storeHashScript atomically updates the shared hash and increments the version
// counter only when the hash has changed. Returns the (possibly unchanged) version.
// KEYS[1] = hash key, KEYS[2] = version key, ARGV[1] = new hash.
var storeHashScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur == ARGV[1] then
    local v = redis.call('GET', KEYS[2])
    if v == false then return 1 end
    return tonumber(v)
end
redis.call('SET', KEYS[1], ARGV[1])
return redis.call('INCR', KEYS[2])
`)

// RedisCoordinator implements Coordinator using Redis. It externalizes the
// xDS snapshot hash and version so that all control-plane replicas stamp the
// same version number for identical config, and so they can detect each
// other's liveness via heartbeat keys.
type RedisCoordinator struct {
	rdb        *redis.Client
	instanceID string
}

// NewRedisCoordinator returns a Coordinator backed by rdb. instanceID must be
// unique per control-plane replica (use the Kubernetes Pod name).
func NewRedisCoordinator(rdb *redis.Client, instanceID string) *RedisCoordinator {
	return &RedisCoordinator{rdb: rdb, instanceID: instanceID}
}

// LoadHash returns the current shared snapshot hash and version.
// Returns ("", 0, nil) if no snapshot has been published yet.
func (c *RedisCoordinator) LoadHash(ctx context.Context) (string, uint64, error) {
	hash, err := c.rdb.Get(ctx, keyHash).Result()
	if err == redis.Nil {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("ha load hash: %w", err)
	}

	verStr, err := c.rdb.Get(ctx, keyVersion).Result()
	if err == redis.Nil {
		return hash, 1, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("ha load version: %w", err)
	}
	v, err := strconv.ParseUint(verStr, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("ha parse version %q: %w", verStr, err)
	}
	return hash, v, nil
}

// StoreHash records the new hash and returns the version to stamp on the snapshot.
// Two replicas storing the same hash concurrently receive the same version.
func (c *RedisCoordinator) StoreHash(ctx context.Context, hash string) (uint64, error) {
	res, err := storeHashScript.Run(ctx, c.rdb,
		[]string{keyHash, keyVersion},
		hash,
	).Uint64()
	if err != nil {
		return 0, fmt.Errorf("ha store hash: %w", err)
	}
	return res, nil
}

// Heartbeat refreshes this instance's presence key with a short TTL.
// Expired keys signal that a replica has gone away.
func (c *RedisCoordinator) Heartbeat(ctx context.Context) error {
	return c.rdb.Set(ctx, keyInstancePfx+c.instanceID, "1", instanceTTL).Err()
}

// Run starts the heartbeat loop, refreshing every heartbeatEvery until ctx is
// cancelled. Heartbeat errors are logged but do not terminate the loop.
// The first heartbeat fires immediately before the first tick.
func (c *RedisCoordinator) Run(ctx context.Context, log interface{ Warn(string, ...any) }) {
	_ = c.Heartbeat(ctx)
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Heartbeat(ctx); err != nil {
				log.Warn("ha: heartbeat failed", "err", err)
			}
		}
	}
}
