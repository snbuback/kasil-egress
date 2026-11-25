package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/flow"
	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/pg"
)

// collector consumes decoded lines and writes them in batches.
type collector struct {
	log        *slog.Logger
	metrics    *metrics
	node       string
	loc        *time.Location
	podCIDR    netip.Prefix
	svcCIDR    netip.Prefix
	batchSize  int
	flushEvery time.Duration
	spoolDir   string
	index      *k8s.Index

	in   chan []byte
	conn *connector

	// buffers, all keyed so that repeated tuples collapse before the write
	edges         map[string]*pg.EdgeRow
	edgeSource    map[string]string // edge key -> workload key
	raw           map[string]*pg.RawAggRow
	rawSource     map[string]string
	blocked       []pg.BlockedRow
	blockedSource []string
	dns           map[string]pg.DNSRow
	refs          map[string]pg.WorkloadRef
}

func (c *collector) attach(conn *connector) { c.conn = conn }

func (c *collector) run(ctx context.Context) {
	tick := time.NewTicker(c.flushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			c.flush(context.Background())
			return
		case line := <-c.in:
			c.consume(line)
			if c.size() >= c.batchSize {
				c.flush(ctx)
			}
		case <-tick.C:
			c.flush(ctx)
		}
	}
}

func (c *collector) reset() {
	c.edges = map[string]*pg.EdgeRow{}
	c.edgeSource = map[string]string{}
	c.raw = map[string]*pg.RawAggRow{}
	c.rawSource = map[string]string{}
	c.blocked = nil
	c.blockedSource = nil
	c.dns = map[string]pg.DNSRow{}
	c.refs = map[string]pg.WorkloadRef{}
}

func (c *collector) size() int {
	return len(c.edges) + len(c.raw) + len(c.blocked) + len(c.dns)
}

// consume turns one raw line into rows.
func (c *collector) consume(line []byte) {
	o, err := flow.DecodeLine(line)
	if err != nil {
		reason := "decode"
		if err == flow.ErrIgnored {
			reason = "not_a_flow"
		}
		c.metrics.eventsIgnored.WithLabelValues(reason).Add(1)
		return
	}

	src, ok := c.sourceWorkload(o)
	if !ok {
		c.metrics.eventsIgnored.WithLabelValues("no_source").Add(1)
		return
	}
	c.refs[src.Key()] = pg.WorkloadRef{Namespace: src.Namespace, Kind: src.Kind, Name: src.Name, Labels: src.Labels}

	// Denials go to the review queue only. A denied attempt must never become
	// an edge, because edges are what the generator turns into allow rules.
	if o.IsDenied() && o.Direction == "EGRESS" {
		c.blocked = append(c.blocked, pg.BlockedRow{
			TS: o.Time, SrcNamespace: o.Src.Namespace, SrcPod: o.Src.PodName,
			SrcIP: o.Src.IP, DstIP: o.Dst.IP, DstNamespace: o.Dst.Namespace, DstPod: o.Dst.PodName,
			DstNames: o.DstNames, Port: o.Port, Proto: o.Proto, Direction: o.Direction,
			Verdict: o.Verdict, DropReason: o.DropReason, Node: o.Node, Conns: o.Conns,
		})
		c.blockedSource = append(c.blockedSource, src.Key())
		return
	}

	if !o.IsEgressRequest() {
		return
	}

	if o.DNSQuery != "" {
		for _, ip := range o.DNSIPs {
			if strings.Contains(ip, ":") {
				continue // v1 is IPv4 only
			}
			c.dns[o.DNSQuery+"|"+ip] = pg.DNSRow{FQDN: o.DNSQuery, IP: ip, Time: o.Time}
		}
	}

	dst := flow.Classify(o, flow.ClusterCIDRs{Pod: c.podCIDR, Svc: c.svcCIDR})
	key := src.Key() + "|" + dst.Kind + "|" + dst.Key + "|" + fmt.Sprint(o.Port) + "|" + o.Proto
	if row, ok := c.edges[key]; ok {
		row.Conns += o.Conns
		if o.Time.After(row.Time) {
			row.Time = o.Time
		}
		row.HourMask = orBits(row.HourMask, pg.HourMask(o.Time, c.loc))
	} else {
		c.edges[key] = &pg.EdgeRow{
			DstKind:      dst.Kind,
			DstKey:       dst.Key,
			DstNamespace: dst.Namespace,
			Port:         o.Port,
			Proto:        o.Proto,
			Time:         o.Time,
			Conns:        o.Conns,
			HourMask:     pg.HourMask(o.Time, c.loc),
		}
		c.edgeSource[key] = src.Key()
	}

	if !o.Aggregate {
		return
	}
	rkey := o.Time.UTC().Truncate(time.Minute).Format(time.RFC3339) + "|" + o.Node + "|" + key
	if row, ok := c.raw[rkey]; ok {
		if o.Conns > row.Conns {
			row.Conns = o.Conns
		}
	} else {
		c.raw[rkey] = &pg.RawAggRow{
			TS: o.Time, Node: o.Node, DstKind: dst.Kind, DstKey: dst.Key,
			DstNamespace: dst.Namespace, Port: o.Port, Proto: o.Proto, Verdict: o.Verdict, Conns: o.Conns,
		}
		c.rawSource[rkey] = src.Key()
	}
}

// sourceWorkload prefers the workload Cilium attached to the flow and falls
// back to the pod index.
func (c *collector) sourceWorkload(o *flow.Observation) (model.Workload, bool) {
	if o.Src.Namespace == "" && o.Src.PodName == "" {
		return model.Workload{}, false
	}
	if o.Src.Workload != "" && o.Src.Kind != "" {
		w := model.Workload{Namespace: o.Src.Namespace, Kind: o.Src.Kind, Name: o.Src.Workload}
		if c.index != nil {
			if kw, ok := c.index.Resolve(o.Src.Namespace, o.Src.PodName); ok {
				w.Selector = kw.Selector
				w.PodLabels = kw.PodLabels
				w.Labels = kw.Labels
			}
		}
		if len(w.Selector) == 0 {
			w.Selector = map[string]string{"app.kubernetes.io/name": w.Name}
		}
		return w, true
	}
	if c.index != nil {
		if kw, ok := c.index.Resolve(o.Src.Namespace, o.Src.PodName); ok {
			return kw.Model(), true
		}
	}
	if o.Src.PodName == "" {
		return model.Workload{}, false
	}
	// Unknown pod: keep it as a bare pod so the traffic is not lost.
	return model.Workload{
		Namespace: o.Src.Namespace,
		Kind:      "Pod",
		Name:      o.Src.PodName,
		Selector:  map[string]string{"app.kubernetes.io/name": o.Src.PodName},
	}, true
}

func (c *collector) flush(ctx context.Context) {
	if c.size() == 0 {
		return
	}
	start := time.Now()
	db := c.conn.handle()
	if db == nil {
		c.spool()
		c.metrics.linesDropped.WithLabelValues("no_database").Add(float64(len(c.edges)))
		c.reset()
		return
	}

	refs := make([]pg.WorkloadRef, 0, len(c.refs))
	for _, r := range c.refs {
		refs = append(refs, r)
	}
	ids, err := db.ResolveWorkloads(ctx, refs)
	if err != nil {
		c.log.Warn("resolve workloads failed, spooling", "error", err)
		c.spool()
		c.reset()
		return
	}
	for key, row := range c.edges {
		if id, ok := ids[c.edgeSource[key]]; ok {
			row.SrcWorkloadID = id
		}
	}
	for key, row := range c.raw {
		if id, ok := ids[c.rawSource[key]]; ok {
			row.SrcWorkloadID = id
		}
	}
	for i := range c.blocked {
		if id, ok := ids[c.blockedSource[i]]; ok {
			id := id
			c.blocked[i].SrcWorkloadID = &id
		}
	}

	edges := make([]pg.EdgeRow, 0, len(c.edges))
	for _, r := range c.edges {
		edges = append(edges, *r)
	}
	raw := make([]pg.RawAggRow, 0, len(c.raw))
	for _, r := range c.raw {
		raw = append(raw, *r)
	}
	dns := make([]pg.DNSRow, 0, len(c.dns))
	for _, r := range c.dns {
		dns = append(dns, r)
	}

	if err := db.UpsertEdges(ctx, edges); err != nil {
		c.log.Warn("edge upsert failed, spooling", "error", err)
		c.metrics.linesDropped.WithLabelValues("write_error").Add(float64(len(edges)))
		c.spool()
		c.reset()
		return
	}
	if err := db.InsertRawAgg(ctx, raw); err != nil {
		c.log.Warn("raw aggregate insert failed", "error", err)
		c.metrics.linesDropped.WithLabelValues("raw_write_error").Add(float64(len(raw)))
	}
	if err := db.InsertBlocked(ctx, c.blocked); err != nil {
		c.log.Warn("blocked_flow insert failed", "error", err)
		c.metrics.linesDropped.WithLabelValues("blocked_write_error").Add(float64(len(c.blocked)))
	}
	if err := db.UpsertDNS(ctx, dns); err != nil {
		c.log.Warn("dns upsert failed", "error", err)
	}
	c.metrics.lastWrite.Set(float64(time.Now().Unix()))
	c.metrics.upsertSeconds.Observe(time.Since(start).Seconds())
	c.log.Debug("flushed", "edges", len(edges), "raw", len(raw), "blocked", len(c.blocked), "dns", len(dns))
	c.reset()
}

// spool writes the current buffers to disk so they can be replayed later.
func (c *collector) spool() {
	if c.size() == 0 {
		return
	}
	if err := os.MkdirAll(c.spoolDir, 0o755); err != nil {
		c.log.Warn("cannot create spool dir", "dir", c.spoolDir, "error", err)
		return
	}
	name := filepath.Join(c.spoolDir, fmt.Sprintf("spool-%d.json", time.Now().UnixNano()))
	f, err := os.Create(name)
	if err != nil {
		c.log.Warn("cannot create spool file", "error", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for key, r := range c.edges {
		_ = enc.Encode(map[string]any{"kind": "edge", "workload": c.edgeSource[key], "row": r})
	}
	for key, r := range c.raw {
		_ = enc.Encode(map[string]any{"kind": "raw", "workload": c.rawSource[key], "row": r})
	}
	for i, r := range c.blocked {
		_ = enc.Encode(map[string]any{"kind": "blocked", "workload": c.blockedSource[i], "row": r})
	}
	for _, r := range c.dns {
		_ = enc.Encode(map[string]any{"kind": "dns", "row": r})
	}
	for _, r := range c.refs {
		_ = enc.Encode(map[string]any{"kind": "workload", "row": r})
	}
	if st, err := f.Stat(); err == nil {
		c.metrics.spoolBytes.Set(float64(st.Size()))
	}
	c.log.Warn("spooled batch", "file", name, "edges", len(c.edges), "raw", len(c.raw), "blocked", len(c.blocked))
}

func orBits(a, b string) string {
	if len(a) != 24 {
		return b
	}
	out := []byte(a)
	for i := 0; i < 24 && i < len(b); i++ {
		if b[i] == '1' {
			out[i] = '1'
		}
	}
	return string(out)
}

// allowlistCoverage periodically publishes how many observed edges have a
// shipped rule: the dashboard's coverage signal.
func (c *collector) allowlistCoverage(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			db := c.conn.handle()
			if db == nil {
				continue
			}
			rows, err := db.Pool().Query(ctx, `
SELECT w.namespace, w.name, (r.id IS NOT NULL) AS allowed, count(*)
FROM egress.edge e
JOIN egress.workload w ON w.id = e.src_workload_id
LEFT JOIN egress.policy_rule r ON r.edge_id = e.id
GROUP BY 1,2,3`)
			if err != nil {
				continue
			}
			c.metrics.edgeAllowed.Reset()
			for rows.Next() {
				var ns, name string
				var allowed bool
				var n int
				if err := rows.Scan(&ns, &name, &allowed, &n); err == nil {
					c.metrics.edgeAllowed.Set([]string{ns, name, fmt.Sprint(allowed)}, float64(n))
				}
			}
			rows.Close()
		}
	}
}
