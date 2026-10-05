package store

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"

	"github.com/edge-infra/control-plane/internal/decisions"
)

// decisionChainLock is the transaction-scoped advisory lock every append to
// edge_decisions takes, so appends from every control-plane replica queue
// behind one another and each record's prev is the record before it. Any
// constant no other advisory lock uses.
const decisionChainLock int64 = 0x0edce15105

// AppendDecisions adds recs to the end of the decision log (B28.228), in order,
// in one transaction: each is numbered after the last record and names that
// record's hash as its prev.
func (s *PostgresStore) AppendDecisions(ctx context.Context, recs []decisions.Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("append decisions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, decisionChainLock); err != nil {
		return fmt.Errorf("append decisions: lock: %w", err)
	}
	var seq int64
	prev := decisions.Genesis
	err = tx.QueryRow(ctx, `SELECT seq, hash FROM edge_decisions ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("append decisions: read the chain head: %w", err)
	}

	batch := &pgx.Batch{}
	for _, r := range recs {
		seq++
		line := r.Line(seq, prev)
		prev = decisions.Hash(line)
		batch.Queue(`INSERT INTO edge_decisions (seq, line, hash) VALUES ($1, $2, $3)`, seq, line, prev)
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("append decisions: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("append decisions: commit: %w", err)
	}
	return nil
}

// ExportDecisions writes every record after seq after to w, oldest first, as
// NDJSON: each line exactly as it was hashed, then a newline.
func (s *PostgresStore) ExportDecisions(ctx context.Context, after int64, w io.Writer) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("export decisions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `SELECT line FROM edge_decisions WHERE seq > $1 ORDER BY seq`, after)
	if err != nil {
		return fmt.Errorf("export decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("export decisions: scan: %w", err)
		}
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return fmt.Errorf("export decisions: write: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("export decisions: %w", err)
	}
	return nil
}
