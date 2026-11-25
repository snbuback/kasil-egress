package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/pg"
)

// loadEdges reads the edge inventory, optionally for one namespace.
func loadEdges(ctx context.Context, db *pg.DB, namespace string) ([]model.Edge, error) {
	rows, err := db.Pool().Query(ctx, `
SELECT e.id, w.namespace, w.kind, w.name, COALESCE(w.labels, '{}'::jsonb),
       e.dst_kind, e.dst_key, COALESCE(e.dst_namespace,''), e.port, e.proto,
       e.first_seen, e.last_seen, e.conns_total, e.days_seen, e.active_hours::text
FROM egress.edge e
JOIN egress.workload w ON w.id = e.src_workload_id
WHERE ($1 = '' OR w.namespace = $1)
ORDER BY w.namespace, w.kind, w.name, e.dst_kind, e.dst_key, e.port, e.proto`, namespace)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer rows.Close()

	var out []model.Edge
	for rows.Next() {
		var e model.Edge
		var labelsJSON []byte
		if err := rows.Scan(&e.ID, &e.Workload.Namespace, &e.Workload.Kind, &e.Workload.Name, &labelsJSON,
			&e.DstKind, &e.DstKey, &e.DstNamespace, &e.Port, &e.Proto,
			&e.FirstSeen, &e.LastSeen, &e.ConnsTotal, &e.DaysSeen, &e.ActiveHours); err != nil {
			return nil, err
		}
		e.Workload.Labels = decodeLabels(labelsJSON)
		out = append(out, e)
	}
	return out, rows.Err()
}

// loadDNS returns name -> addresses observed in the window.
func loadDNS(ctx context.Context, db *pg.DB) (map[string][]string, map[string][]string, error) {
	rows, err := db.Pool().Query(ctx, `SELECT fqdn, host(ip) FROM egress.dns_name ORDER BY last_seen DESC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	byIP := map[string][]string{}
	byName := map[string][]string{}
	for rows.Next() {
		var fqdn, ip string
		if err := rows.Scan(&fqdn, &ip); err != nil {
			return nil, nil, err
		}
		byIP[ip] = append(byIP[ip], fqdn)
		byName[fqdn] = append(byName[fqdn], ip)
	}
	return byIP, byName, rows.Err()
}

// attachDNS enriches cidr edges with the names Cilium knew for that address.
func attachDNS(edges []model.Edge, byIP map[string][]string) {
	for i := range edges {
		if edges[i].DstKind != model.KindCIDR {
			continue
		}
		ip := strings.TrimSuffix(edges[i].DstKey, "/32")
		if names, ok := byIP[ip]; ok {
			edges[i].DstNames = names
		}
	}
}

// resolvePeers fills Edge.Peer from the live workload index.
func resolvePeers(edges []model.Edge, idx *k8s.Index) {
	for i := range edges {
		if edges[i].DstKind != model.KindWorkload {
			continue
		}
		parts := strings.Split(edges[i].DstKey, "/")
		if len(parts) != 3 {
			continue
		}
		if w, ok := idx.Get(parts[0], parts[1], parts[2]); ok {
			m := w.Model()
			edges[i].Peer = &m
		}
	}
}

// loadBlocked reads the review queue.
func loadBlocked(ctx context.Context, db *pg.DB, namespace string, since time.Time) ([]model.Blocked, error) {
	rows, err := db.Pool().Query(ctx, `
SELECT b.id, b.ts, COALESCE(b.src_workload_id,0), b.src_namespace, b.src_pod,
       COALESCE(host(b.src_ip),''), COALESCE(host(b.dst_ip),''), COALESCE(b.dst_namespace,''),
       COALESCE(b.dst_pod,''), COALESCE(b.dst_names::text,'[]'), COALESCE(b.port,0),
       COALESCE(b.proto,''), b.direction, b.verdict, COALESCE(b.drop_reason,''), COALESCE(b.node,''), b.conns
FROM egress.blocked_flow b
WHERE b.ts >= $1 AND ($2 = '' OR b.src_namespace = $2)
ORDER BY b.ts DESC`, since, namespace)
	if err != nil {
		return nil, fmt.Errorf("query blocked_flow: %w", err)
	}
	defer rows.Close()
	var out []model.Blocked
	for rows.Next() {
		var b model.Blocked
		var wlID int64
		var namesJSON []byte
		if err := rows.Scan(&b.ID, &b.TS, &wlID, &b.SrcNamespace, &b.SrcPod, &b.SrcIP, &b.DstIP,
			&b.DstNamespace, &b.DstPod, &namesJSON, &b.Port, &b.Proto, &b.Direction, &b.Verdict,
			&b.DropReason, &b.Node, &b.Conns); err != nil {
			return nil, err
		}
		b.DstNames = decodeStringArray(namesJSON)
		b.SrcWorkloadID = wlID
		if wlID != 0 {
			if w, err := loadWorkloadByID(ctx, db, wlID); err == nil {
				b.Workload = w
			}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func loadWorkloadByID(ctx context.Context, db *pg.DB, id int64) (*model.Workload, error) {
	var w model.Workload
	err := db.Pool().QueryRow(ctx, `SELECT namespace, kind, name FROM egress.workload WHERE id = $1`, id).
		Scan(&w.Namespace, &w.Kind, &w.Name)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}

func decodeLabels(b []byte) map[string]string {
	out := map[string]string{}
	if len(b) == 0 {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func decodeStringArray(b []byte) []string {
	var out []string
	if len(b) == 0 {
		return nil
	}
	_ = json.Unmarshal(b, &out)
	return out
}
