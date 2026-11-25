package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// metrics is a minimal Prometheus text exposition: a handful of series do not
// justify a client library dependency in the collector image.
type metrics struct {
	linesRead     *counterVec
	linesDropped  *counterVec
	eventsIgnored *counterVec
	upsertSeconds *histogram
	lastWrite     *gauge
	dbUp          *gauge
	spoolBytes    *gauge
	edgeAllowed   *gaugeVec
}

func newMetrics() *metrics {
	return &metrics{
		linesRead:     newCounterVec("egressd_lines_read_total", "Flow-log lines read", "file"),
		linesDropped:  newCounterVec("egressd_lines_dropped_total", "Lines dropped before ingestion", "reason"),
		eventsIgnored: newCounterVec("egressd_events_ignored_total", "Records that carried no flow", "reason"),
		upsertSeconds: newHistogram("egressd_upsert_seconds", "Time spent writing a batch",
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}),
		lastWrite:  newGauge("egressd_last_write_timestamp_seconds", "Unix time of the last successful write"),
		dbUp:       newGauge("egressd_database_up", "1 when the collector holds a working database connection"),
		spoolBytes: newGauge("egressd_spool_bytes", "Bytes waiting in the on-disk spool"),
		edgeAllowed: newGaugeVec("egress_edge_allowlisted",
			"Edges per workload, split by whether a shipped rule covers them", "namespace", "source_workload", "allowed"),
	}
}

func (m *metrics) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		case "/metrics":
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var sb strings.Builder
		m.linesRead.write(&sb)
		m.linesDropped.write(&sb)
		m.eventsIgnored.write(&sb)
		m.upsertSeconds.write(&sb)
		m.lastWrite.write(&sb)
		m.dbUp.write(&sb)
		m.spoolBytes.write(&sb)
		m.edgeAllowed.write(&sb)
		_, _ = w.Write([]byte(sb.String()))
	})
}

func serveHTTP(ctx context.Context, addr string, m *metrics, log *slog.Logger) {
	srv := &http.Server{Addr: addr, Handler: m.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Warn("metrics server stopped", "error", err)
	}
}

// ---- tiny metric types -------------------------------------------------

type counter struct {
	mu sync.Mutex
	v  float64
}

func (c *counter) Add(d float64) {
	c.mu.Lock()
	c.v += d
	c.mu.Unlock()
}

type counterVec struct {
	name   string
	help   string
	label  string
	mu     sync.Mutex
	values map[string]float64
}

func newCounterVec(name, help, label string) *counterVec {
	return &counterVec{name: name, help: help, label: label, values: map[string]float64{}}
}

func (c *counterVec) WithLabelValues(v string) *counterHandle {
	return &counterHandle{vec: c, label: v}
}

type counterHandle struct {
	vec   *counterVec
	label string
}

func (h *counterHandle) Add(d float64) { h.vec.add(h.label, d) }

func (c *counterVec) add(label string, d float64) {
	c.mu.Lock()
	c.values[label] += d
	c.mu.Unlock()
}

func (c *counterVec) write(sb *strings.Builder) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	c.mu.Lock()
	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(sb, "%s{%s=%q} %g\n", c.name, c.label, k, c.values[k])
	}
	c.mu.Unlock()
}

type gauge struct {
	name  string
	help  string
	mu    sync.Mutex
	value float64
}

func newGauge(name, help string) *gauge { return &gauge{name: name, help: help} }

func (g *gauge) Set(v float64) {
	g.mu.Lock()
	g.value = v
	g.mu.Unlock()
}

func (g *gauge) write(sb *strings.Builder) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
	g.mu.Lock()
	fmt.Fprintf(sb, "%s %g\n", g.name, g.value)
	g.mu.Unlock()
}

type gaugeVec struct {
	name   string
	help   string
	labels []string
	mu     sync.Mutex
	values map[string]float64
}

func newGaugeVec(name, help string, labels ...string) *gaugeVec {
	return &gaugeVec{name: name, help: help, labels: labels, values: map[string]float64{}}
}

func (g *gaugeVec) Reset() {
	g.mu.Lock()
	g.values = map[string]float64{}
	g.mu.Unlock()
}

func (g *gaugeVec) Set(labels []string, v float64) {
	key := strings.Join(labels, "\x00")
	g.mu.Lock()
	g.values[key] = v
	g.mu.Unlock()
}

func (g *gaugeVec) write(sb *strings.Builder) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
	g.mu.Lock()
	keys := make([]string, 0, len(g.values))
	for k := range g.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts := strings.Split(k, "\x00")
		var lbl strings.Builder
		for i, name := range g.labels {
			if i > 0 {
				lbl.WriteString(",")
			}
			val := ""
			if i < len(parts) {
				val = parts[i]
			}
			fmt.Fprintf(&lbl, "%s=%q", name, val)
		}
		fmt.Fprintf(sb, "%s{%s} %g\n", g.name, lbl.String(), g.values[k])
	}
	g.mu.Unlock()
}

type histogram struct {
	name    string
	help    string
	buckets []float64
	mu      sync.Mutex
	counts  []float64
	sum     float64
	count   float64
}

func newHistogram(name, help string, buckets []float64) *histogram {
	return &histogram{name: name, help: help, buckets: buckets, counts: make([]float64, len(buckets))}
}

func (h *histogram) Observe(v float64) {
	h.mu.Lock()
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
	h.mu.Unlock()
}

func (h *histogram) write(sb *strings.Builder) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	h.mu.Lock()
	for i, b := range h.buckets {
		fmt.Fprintf(sb, "%s_bucket{le=%q} %g\n", h.name, fmt.Sprint(b), h.counts[i])
	}
	fmt.Fprintf(sb, "%s_bucket{le=\"+Inf\"} %g\n", h.name, h.count)
	fmt.Fprintf(sb, "%s_sum %g\n%s_count %g\n", h.name, h.sum, h.name, h.count)
	h.mu.Unlock()
}
