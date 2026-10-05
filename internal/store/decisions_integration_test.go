//go:build integration

package store_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/decisions"
	"github.com/edge-infra/control-plane/internal/store"
)

// B28.228: decisions appended in two batches export as one chain — numbered
// one after another, each line naming the sha256 of the line before it as its
// prev — and the export is the bytes that were hashed.
func TestDecisions_AppendedBatchesExportAsOneChain(t *testing.T) {
	dsn := adminReadDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	defer s.Close()

	// The table may hold earlier runs' records: start from its current head.
	var before bytes.Buffer
	require.NoError(t, s.ExportDecisions(ctx, 0, &before))
	head, after := decisions.Genesis, int64(0)
	if lines := bytes.Split(bytes.TrimSpace(before.Bytes()), []byte("\n")); len(before.Bytes()) > 0 {
		last := lines[len(lines)-1]
		head = decisions.Hash(string(last))
		var l struct{ Seq int64 }
		require.NoError(t, json.Unmarshal(last, &l))
		after = l.Seq
	}

	rec := func(decision string, status uint32) decisions.Record {
		return decisions.Record{Time: time.Now(), Node: "edge-egress/test", Agent: "system:serviceaccount:t:a",
			Decision: decision, Status: status, Path: "/v1/models", Destination: "mock-llm"}
	}
	require.NoError(t, s.AppendDecisions(ctx, []decisions.Record{rec(decisions.Allowed, 200), rec(decisions.Allowed, 200)}))
	require.NoError(t, s.AppendDecisions(ctx, []decisions.Record{rec(decisions.RateLimited, 429)}))

	var out bytes.Buffer
	require.NoError(t, s.ExportDecisions(ctx, after, &out))
	sc := bufio.NewScanner(&out)
	var got []string
	prev := head
	for sc.Scan() {
		line := sc.Text()
		var l struct {
			Seq      int64
			Prev     string
			Decision string
		}
		require.NoError(t, json.Unmarshal([]byte(line), &l))
		after++
		assert.Equal(t, after, l.Seq)
		assert.Equal(t, prev, l.Prev, "record %d must name the hash of the record before it", l.Seq)
		prev = decisions.Hash(line)
		got = append(got, l.Decision)
	}
	assert.Equal(t, []string{"allowed", "allowed", "rate_limited"}, got)
}
