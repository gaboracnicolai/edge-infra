package ha_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/ha"
)

func newTestCoord(t *testing.T) (*ha.RedisCoordinator, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return ha.NewRedisCoordinator(rdb, "test-instance"), mr
}

func TestLoadHash_Empty(t *testing.T) {
	coord, _ := newTestCoord(t)
	hash, ver, err := coord.LoadHash(context.Background())
	require.NoError(t, err)
	assert.Empty(t, hash)
	assert.Zero(t, ver)
}

func TestStoreHash_FirstCallVersionOne(t *testing.T) {
	coord, _ := newTestCoord(t)
	ver, err := coord.StoreHash(context.Background(), "abc123")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ver)
}

func TestStoreHash_SameHashReturnsSameVersion(t *testing.T) {
	coord, _ := newTestCoord(t)

	v1, err := coord.StoreHash(context.Background(), "abc123")
	require.NoError(t, err)

	v2, err := coord.StoreHash(context.Background(), "abc123")
	require.NoError(t, err)

	assert.Equal(t, v1, v2, "identical hash must not increment the version counter")
}

func TestStoreHash_DifferentHashIncrementsVersion(t *testing.T) {
	coord, _ := newTestCoord(t)

	v1, err := coord.StoreHash(context.Background(), "hash-a")
	require.NoError(t, err)

	v2, err := coord.StoreHash(context.Background(), "hash-b")
	require.NoError(t, err)

	assert.Greater(t, v2, v1)
}

func TestLoadHash_RoundTrip(t *testing.T) {
	coord, _ := newTestCoord(t)

	storedVer, err := coord.StoreHash(context.Background(), "deadbeef")
	require.NoError(t, err)

	gotHash, gotVer, err := coord.LoadHash(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "deadbeef", gotHash)
	assert.Equal(t, storedVer, gotVer)
}

func TestStoreHash_TwoReplicasSameHashSameVersion(t *testing.T) {
	mr := miniredis.RunT(t)
	newCoord := func(id string) *ha.RedisCoordinator {
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		return ha.NewRedisCoordinator(rdb, id)
	}

	replica1 := newCoord("pod-1")
	replica2 := newCoord("pod-2")

	v1, err := replica1.StoreHash(context.Background(), "config-hash-xyz")
	require.NoError(t, err)

	v2, err := replica2.StoreHash(context.Background(), "config-hash-xyz")
	require.NoError(t, err)

	assert.Equal(t, v1, v2, "same config hash must produce same version on both replicas")
}

func TestHeartbeat_SetsKeyWithTTL(t *testing.T) {
	coord, mr := newTestCoord(t)
	require.NoError(t, coord.Heartbeat(context.Background()))
	assert.True(t, mr.Exists("xds:instance:test-instance"))
	ttl := mr.TTL("xds:instance:test-instance")
	assert.Positive(t, ttl, "heartbeat key must have a TTL")
}

func TestHeartbeat_MultipleInstancesDoNotCollide(t *testing.T) {
	mr := miniredis.RunT(t)
	newCoord := func(id string) *ha.RedisCoordinator {
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		return ha.NewRedisCoordinator(rdb, id)
	}

	require.NoError(t, newCoord("pod-1").Heartbeat(context.Background()))
	require.NoError(t, newCoord("pod-2").Heartbeat(context.Background()))

	assert.True(t, mr.Exists("xds:instance:pod-1"))
	assert.True(t, mr.Exists("xds:instance:pod-2"))
}
