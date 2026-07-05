package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyRows is a zero-row pgx.Rows: loaders see Next()==false and stop.
type emptyRows struct{}

func (emptyRows) Close()                                       {}
func (emptyRows) Err() error                                   { return nil }
func (emptyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (emptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (emptyRows) Next() bool                                   { return false }
func (emptyRows) Scan(_ ...any) error                          { return nil }
func (emptyRows) Values() ([]any, error)                       { return nil, nil }
func (emptyRows) RawValues() [][]byte                          { return nil }
func (emptyRows) Conn() *pgx.Conn                              { return nil }

// fakeTx records reads routed through a single transaction. Methods not used by
// LoadSnapshot are inherited from the embedded (nil) pgx.Tx and would panic if
// ever called — proving they are not.
type fakeTx struct {
	pgx.Tx
	queryCount int
	committed  bool
	rolledBack bool
}

func (f *fakeTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	f.queryCount++
	return emptyRows{}, nil
}
func (f *fakeTx) Commit(_ context.Context) error   { f.committed = true; return nil }
func (f *fakeTx) Rollback(_ context.Context) error { f.rolledBack = true; return nil }

// fakeDB is a pgxDB that hands out one fakeTx and records whether any read
// bypassed the transaction via the pool.
type fakeDB struct {
	tx            *fakeTx
	beginTxCalls  int
	lastTxOptions pgx.TxOptions
	directQueries int
}

func (f *fakeDB) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	f.beginTxCalls++
	f.lastTxOptions = opts
	return f.tx, nil
}
func (f *fakeDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	f.directQueries++
	return emptyRows{}, nil
}
func (f *fakeDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (f *fakeDB) Ping(_ context.Context) error { return nil }
func (f *fakeDB) Close()                       {}

// TestLoadSnapshot_ReadsInSingleTransaction pins the torn-read fix: every table
// must be read from one REPEATABLE READ, read-only point-in-time, never from
// five independent pooled connections.
func TestLoadSnapshot_ReadsInSingleTransaction(t *testing.T) {
	ftx := &fakeTx{}
	fdb := &fakeDB{tx: ftx}
	s := &PostgresStore{pool: fdb}

	_, err := s.LoadSnapshot(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1, fdb.beginTxCalls, "all reads must run in exactly one transaction")
	assert.Equal(t, pgx.RepeatableRead, fdb.lastTxOptions.IsoLevel,
		"reads must use a REPEATABLE READ point-in-time snapshot")
	assert.Equal(t, pgx.ReadOnly, fdb.lastTxOptions.AccessMode)
	assert.Equal(t, 0, fdb.directQueries, "no read may bypass the transaction via the pool")
	assert.Equal(t, 5, ftx.queryCount,
		"gateways, routes, clusters, endpoints, secrets must all read through the one tx")
	assert.True(t, ftx.committed, "the read tx must be committed on success")
}
