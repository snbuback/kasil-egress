package pg

import (
	"context"
	"fmt"
)

// pgxBatch is a tiny sequential batch runner: each statement is sent with
// Exec in order and its rows are drained. It exists so the upsert helpers can
// share one code path without exposing pgx types to callers.
type pgxBatch struct {
	queries []batchQuery
}

type batchQuery struct {
	sql  string
	args []any
}

func (b *pgxBatch) queue(sql string, args ...any) {
	b.queries = append(b.queries, batchQuery{sql: sql, args: args})
}

// run executes every queued statement and returns the first column of the
// first row of each (ids for RETURNING id).
func (b *pgxBatch) run(ctx context.Context, d *DB) ([]int64, error) {
	out := make([]int64, 0, len(b.queries))
	for _, q := range b.queries {
		var id int64
		err := d.pool.QueryRow(ctx, q.sql, q.args...).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", firstLine(q.sql), err)
		}
		out = append(out, id)
	}
	return out, nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
