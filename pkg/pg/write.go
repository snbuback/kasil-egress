package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WorkloadRef identifies a workload row.
type WorkloadRef struct {
	Namespace string
	Kind      string
	Name      string
	Labels    map[string]string
}

// EdgeRow is one upsert into egress.edge.
type EdgeRow struct {
	SrcWorkloadID int64
	DstKind       string
	DstKey        string
	DstNamespace  string
	Port          int
	Proto         string
	Time          time.Time
	Conns         int64
	// HourMask is a 24-character bit string, hour 0 right-most.
	HourMask string
}

// RawAggRow is one row of egress.flow_raw_agg.
type RawAggRow struct {
	TS            time.Time
	Node          string
	SrcWorkloadID int64
	DstKind       string
	DstKey        string
	DstNamespace  string
	Port          int
	Proto         string
	Verdict       string
	Conns         int64
}

// BlockedRow is one denial for the review queue.
type BlockedRow struct {
	TS            time.Time
	SrcWorkloadID *int64
	SrcNamespace  string
	SrcPod        string
	SrcIP         string
	DstIP         string
	DstNamespace  string
	DstPod        string
	DstNames      []string
	Port          int
	Proto         string
	Direction     string
	Verdict       string
	DropReason    string
	Node          string
	Conns         int64
}

// DNSRow is one (name, address) observation.
type DNSRow struct {
	FQDN string
	IP   string
	Time time.Time
}

// HourMask renders the bit string for a timestamp in the given location.
func HourMask(t time.Time, loc *time.Location) string {
	h := t.In(loc).Hour()
	b := []byte(strings.Repeat("0", 24))
	b[23-h] = '1'
	return string(b)
}

// ResolveWorkloads upserts workload rows and returns their ids by key
// ("ns/kind/name"). The label set is refreshed, first_seen preserved.
func (d *DB) ResolveWorkloads(ctx context.Context, refs []WorkloadRef) (map[string]int64, error) {
	out := make(map[string]int64, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	batch := &pgxBatch{}
	for _, r := range refs {
		labels, err := json.Marshal(orEmpty(r.Labels))
		if err != nil {
			return nil, err
		}
		batch.queue(
			`INSERT INTO egress.workload (namespace, kind, name, labels)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (namespace, kind, name)
			 DO UPDATE SET labels = EXCLUDED.labels, last_seen = now()
			 RETURNING id`,
			r.Namespace, r.Kind, r.Name, labels,
		)
	}
	ids, err := batch.run(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("resolve workloads: %w", err)
	}
	for idx, r := range refs {
		out[r.Namespace+"/"+r.Kind+"/"+r.Name] = ids[idx]
	}
	return out, nil
}

// UpsertEdges adds connection counts to the edge inventory.
func (d *DB) UpsertEdges(ctx context.Context, rows []EdgeRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 10
	var sb strings.Builder
	sb.WriteString(`INSERT INTO egress.edge
  (src_workload_id, dst_kind, dst_key, dst_namespace, port, proto, first_seen, last_seen, conns_total, active_hours)
VALUES `)
	args := make([]any, 0, len(rows)*cols)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		base := i * cols
		fmt.Fprintf(&sb, "($%d,$%d,$%d,NULLIF($%d,''),$%d,$%d,$%d,$%d,$%d,$%d::bit(24))",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10)
		mask := r.HourMask
		if len(mask) != 24 {
			mask = strings.Repeat("0", 24)
		}
		args = append(args, r.SrcWorkloadID, r.DstKind, r.DstKey, r.DstNamespace, r.Port, r.Proto, r.Time, r.Time, r.Conns, mask)
	}
	sb.WriteString(` ON CONFLICT (src_workload_id, dst_kind, dst_key, port, proto) DO UPDATE SET
  conns_total = egress.edge.conns_total + EXCLUDED.conns_total,
  last_seen   = GREATEST(egress.edge.last_seen, EXCLUDED.last_seen),
  active_hours = egress.edge.active_hours | EXCLUDED.active_hours,
  dst_namespace = COALESCE(EXCLUDED.dst_namespace, egress.edge.dst_namespace),
  days_seen = CASE WHEN EXCLUDED.last_seen::date > egress.edge.last_seen::date
                   THEN LEAST(egress.edge.days_seen + 1, 32767)
                   ELSE egress.edge.days_seen END`)
	if _, err := d.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("upsert edges: %w", err)
	}
	return nil
}

// InsertRawAgg records aggregated windows. GREATEST on conflict keeps a
// replayed window idempotent while never losing a real increase.
func (d *DB) InsertRawAgg(ctx context.Context, rows []RawAggRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 9
	var sb strings.Builder
	sb.WriteString(`INSERT INTO egress.flow_raw_agg
  (ts, node, src_workload_id, dst_kind, dst_key, dst_namespace, port, proto, verdict, conns)
VALUES `)
	args := make([]any, 0, len(rows)*cols)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		base := i * cols
		// ts is truncated to the minute so a replay of the same aggregate
		// window lands on the same primary key.
		fmt.Fprintf(&sb, "(date_trunc('minute',$%d),$%d,$%d,$%d,$%d,NULLIF($%d,''),$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+1)
		args = append(args, r.TS, r.Node, r.SrcWorkloadID, r.DstKind, r.DstKey, r.DstNamespace, r.Port, r.Proto, r.Verdict)
	}
	sb.WriteString(` ON CONFLICT (ts, node, src_workload_id, dst_kind, dst_key, port, proto, verdict)
  DO UPDATE SET conns = GREATEST(egress.flow_raw_agg.conns, EXCLUDED.conns)`)
	if _, err := d.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("insert flow_raw_agg: %w", err)
	}
	return nil
}

// InsertBlocked appends denials to the review queue.
func (d *DB) InsertBlocked(ctx context.Context, rows []BlockedRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 16
	var sb strings.Builder
	sb.WriteString(`INSERT INTO egress.blocked_flow
  (ts, src_workload_id, src_namespace, src_pod, src_ip, dst_ip, dst_namespace, dst_pod, dst_names,
   port, proto, direction, verdict, drop_reason, node, conns)
VALUES `)
	args := make([]any, 0, len(rows)*cols)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		base := i * cols
		fmt.Fprintf(&sb, "(date_trunc('second',$%d),$%d,$%d,$%d,NULLIF($%d,'')::inet,NULLIF($%d,'')::inet,NULLIF($%d,''),NULLIF($%d,''),$%d::jsonb,$%d,NULLIF($%d,''),$%d,$%d,NULLIF($%d,''),NULLIF($%d,''),$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10,
			base+11, base+12, base+13, base+14, base+15, base+16)
		var names any
		if len(r.DstNames) > 0 {
			b, err := json.Marshal(r.DstNames)
			if err != nil {
				return err
			}
			names = string(b)
		}
		args = append(args,
			r.TS, r.SrcWorkloadID, r.SrcNamespace, r.SrcPod, r.SrcIP, r.DstIP, r.DstNamespace, r.DstPod,
			names, r.Port, r.Proto, r.Direction, r.Verdict, r.DropReason, r.Node, r.Conns)
	}
	if _, err := d.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("insert blocked_flow: %w", err)
	}
	return nil
}

// UpsertDNS records name -> address mappings.
func (d *DB) UpsertDNS(ctx context.Context, rows []DNSRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 3
	var sb strings.Builder
	sb.WriteString(`INSERT INTO egress.dns_name (fqdn, ip, first_seen, last_seen) VALUES `)
	args := make([]any, 0, len(rows)*cols)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(",")
		}
		base := i * cols
		fmt.Fprintf(&sb, "($%d,$%d::inet,$%d,$%d)", base+1, base+2, base+3, base+3)
		args = append(args, r.FQDN, r.IP, r.Time)
	}
	sb.WriteString(` ON CONFLICT (fqdn, ip) DO UPDATE SET last_seen = GREATEST(egress.dns_name.last_seen, EXCLUDED.last_seen)`)
	if _, err := d.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("upsert dns_name: %w", err)
	}
	return nil
}

// Offset is the read position of one flow-log file.
type Offset struct {
	Node   string
	File   string
	Inode  int64
	Offset int64
}

// LoadOffsets returns every checkpoint keyed "node\x00file".
func (d *DB) LoadOffsets(ctx context.Context) (map[string]Offset, error) {
	rows, err := d.pool.Query(ctx, `SELECT node, file, inode, offset FROM egress.ingest_offset`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Offset{}
	for rows.Next() {
		var o Offset
		if err := rows.Scan(&o.Node, &o.File, &o.Inode, &o.Offset); err != nil {
			return nil, err
		}
		out[o.Node+"\x00"+o.File] = o
	}
	return out, rows.Err()
}

// SaveOffsets checkpoints read positions.
func (d *DB) SaveOffsets(ctx context.Context, offsets []Offset) error {
	if len(offsets) == 0 {
		return nil
	}
	batch := &pgxBatch{}
	for _, o := range offsets {
		batch.queue(`INSERT INTO egress.ingest_offset (node, file, inode, offset, updated)
		             VALUES ($1,$2,$3,$4,now())
		             ON CONFLICT (node, file) DO UPDATE
		             SET inode = EXCLUDED.inode, offset = EXCLUDED.offset, updated = now()`,
			o.Node, o.File, o.Inode, o.Offset)
	}
	if _, err := batch.run(ctx, d); err != nil {
		return fmt.Errorf("save offsets: %w", err)
	}
	return nil
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
