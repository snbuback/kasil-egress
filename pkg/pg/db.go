// Package pg owns the egress schema and every write the collector performs.
// All statements are idempotent so a restarted DaemonSet can replay safely.
package pg

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Retention is the design's §8.2 budget.
type Retention struct {
	Raw     time.Duration // flow_raw_agg
	Hourly  time.Duration // flow_hourly
	Blocked time.Duration // blocked_flow
	DNS     time.Duration // dns_name
}

// DefaultRetention is Q1's answer: 48 h / 180 d / 90 d / 90 d.
func DefaultRetention() Retention {
	return Retention{
		Raw:     48 * time.Hour,
		Hourly:  180 * 24 * time.Hour,
		Blocked: 90 * 24 * time.Hour,
		DNS:     90 * 24 * time.Hour,
	}
}

// DB wraps a pgx pool.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 0
	cfg.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (d *DB) Close() { d.pool.Close() }

// Ping verifies connectivity.
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// Pool exposes the underlying pool for read queries in cmd/egressctl.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Migrate applies the schema. Each statement is individually idempotent, so
// this is safe to run on every start.
func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return d.EnsurePartitions(ctx, time.Now())
}

// EnsurePartitions creates the partitions needed for the current and next
// period. Naming is deterministic so retention can find them by name.
func (d *DB) EnsurePartitions(ctx context.Context, now time.Time) error {
	type part struct {
		parent string
		name   string
		from   time.Time
		to     time.Time
	}
	day := now.UTC().Truncate(24 * time.Hour)
	month := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	nextMonth := month.AddDate(0, 1, 0)

	parts := []part{
		{"egress.flow_raw_agg", "flow_raw_agg_p" + day.Format("20060102"), day, day.AddDate(0, 0, 1)},
		{"egress.flow_raw_agg", "flow_raw_agg_p" + day.AddDate(0, 0, 1).Format("20060102"), day.AddDate(0, 0, 1), day.AddDate(0, 0, 2)},
		{"egress.blocked_flow", "blocked_flow_p" + month.Format("200601"), month, nextMonth},
		{"egress.blocked_flow", "blocked_flow_p" + nextMonth.Format("200601"), nextMonth, nextMonth.AddDate(0, 1, 0)},
		{"egress.flow_hourly", "flow_hourly_p" + month.Format("200601"), month, nextMonth},
		{"egress.flow_hourly", "flow_hourly_p" + nextMonth.Format("200601"), nextMonth, nextMonth.AddDate(0, 1, 0)},
	}
	for _, p := range parts {
		stmt := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS egress.%s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
			p.name, p.parent, p.from.Format("2006-01-02T15:04:05Z"), p.to.Format("2006-01-02T15:04:05Z"))
		if _, err := d.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("create partition %s: %w", p.name, err)
		}
	}
	return nil
}

// MaintenanceStats reports what a maintenance run did.
type MaintenanceStats struct {
	RolledUpRows int64
	DroppedParts []string
	PrunedDNS    int64
}

// Maintain rolls raw aggregates up into flow_hourly, drops expired partitions
// and prunes DNS names. It is the body of the egress-maintenance CronJob.
func (d *DB) Maintain(ctx context.Context, now time.Time, r Retention) (MaintenanceStats, error) {
	var st MaintenanceStats
	if err := d.EnsurePartitions(ctx, now); err != nil {
		return st, err
	}

	// Roll up complete hours only: a partial hour would be counted again on
	// the next run.
	from := now.Add(-r.Raw).UTC().Truncate(time.Hour)
	to := now.UTC().Truncate(time.Hour)
	tag, err := d.pool.Exec(ctx, `
INSERT INTO egress.flow_hourly (bucket, src_workload_id, dst_kind, dst_key, port, proto, verdict, conns)
SELECT date_trunc('hour', ts) AS bucket, src_workload_id, dst_kind, dst_key, port, proto, verdict,
       GREATEST(SUM(conns), 0) AS conns
FROM egress.flow_raw_agg
WHERE ts >= $1 AND ts < $2
GROUP BY 1, 2, 3, 4, 5, 6, 7
ON CONFLICT (bucket, src_workload_id, dst_kind, dst_key, port, proto, verdict)
DO UPDATE SET conns = GREATEST(egress.flow_hourly.conns, EXCLUDED.conns)`, from, to)
	if err != nil {
		return st, fmt.Errorf("rollup: %w", err)
	}
	st.RolledUpRows = tag.RowsAffected()

	dropped, err := d.dropExpiredPartitions(ctx, now, r)
	if err != nil {
		return st, err
	}
	st.DroppedParts = dropped

	tag, err = d.pool.Exec(ctx, `DELETE FROM egress.dns_name WHERE last_seen < $1`, now.Add(-r.DNS))
	if err != nil {
		return st, fmt.Errorf("prune dns_name: %w", err)
	}
	st.PrunedDNS = tag.RowsAffected()

	if _, err := d.pool.Exec(ctx, `ANALYZE egress.edge`); err != nil {
		return st, err
	}
	return st, nil
}

func (d *DB) dropExpiredPartitions(ctx context.Context, now time.Time, r Retention) ([]string, error) {
	type partInfo struct{ name string }
	rows, err := d.pool.Query(ctx, `
SELECT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'egress' AND c.relkind = 'r' AND c.relispartition`)
	if err != nil {
		return nil, fmt.Errorf("list partitions: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var dropped []string
	for _, name := range names {
		cutoff, ok := partitionCutoff(name)
		if !ok || !cutoff.Before(now) {
			continue
		}
		var keep time.Duration
		var period time.Duration
		switch {
		case hasPrefix(name, "flow_raw_agg_p"):
			keep, period = r.Raw, 24*time.Hour
		case hasPrefix(name, "flow_hourly_p"):
			keep, period = r.Hourly, 31*24*time.Hour
		case hasPrefix(name, "blocked_flow_p"):
			keep, period = r.Blocked, 31*24*time.Hour
		default:
			continue
		}
		// A partition is expired when its whole range is older than the
		// retention window.
		if now.Sub(cutoff.Add(period)) <= keep {
			continue
		}
		if _, err := d.pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS egress.%s", pgx.Identifier{name}.Sanitize())); err != nil {
			return dropped, fmt.Errorf("drop %s: %w", name, err)
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// partitionCutoff parses the partition start from its generated name.
func partitionCutoff(name string) (time.Time, bool) {
	var layout string
	var stamp string
	switch {
	case hasPrefix(name, "flow_raw_agg_p"):
		layout, stamp = "20060102", name[len("flow_raw_agg_p"):]
	case hasPrefix(name, "flow_hourly_p"):
		layout, stamp = "200601", name[len("flow_hourly_p"):]
	case hasPrefix(name, "blocked_flow_p"):
		layout, stamp = "200601", name[len("blocked_flow_p"):]
	default:
		return time.Time{}, false
	}
	t, err := time.Parse(layout, stamp)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
