// Command egressd is the per-node collector: it tails Cilium's dynamic
// flow-log exporter files, normalizes the records and batches them into the
// egress database.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/pg"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "egressd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		logDir     = flag.String("log-dir", "/var/run/cilium/hubble", "directory holding the flow-log files")
		files      = flag.String("files", "audit-agg.log,deny-raw.log,dns-raw.log", "comma-separated file names to tail")
		dsnFlag    = flag.String("dsn", os.Getenv("EGRESS_DSN"), "PostgreSQL DSN (default $EGRESS_DSN)")
		node       = flag.String("node", os.Getenv("NODE_NAME"), "node name (default $NODE_NAME)")
		metricsAdr = flag.String("metrics-addr", ":9110", "metrics/health listen address")
		spoolDir   = flag.String("spool-dir", "/var/lib/egressd", "on-disk spool used while Postgres is unavailable")
		batchSize  = flag.Int("batch-size", 500, "rows per write")
		flushEvery = flag.Duration("flush-interval", 2*time.Second, "max time between writes")
		ckptEvery  = flag.Duration("checkpoint-interval", 5*time.Second, "offset checkpoint interval")
		podCIDR    = flag.String("pod-cidr", "172.16.0.0/16", "cluster pod CIDR")
		svcCIDR    = flag.String("svc-cidr", "172.30.0.0/16", "cluster service CIDR")
		tz         = flag.String("timezone", envOr("TZ", "UTC"), "timezone for the hour-of-day mask")
		debug      = flag.Bool("debug", false, "verbose logging")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return nil
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *dsnFlag == "" && os.Getenv("EGRESS_DSN_FILE") != "" {
		b, err := os.ReadFile(os.Getenv("EGRESS_DSN_FILE"))
		if err != nil {
			return fmt.Errorf("read EGRESS_DSN_FILE: %w", err)
		}
		*dsnFlag = strings.TrimSpace(string(b))
	}
	if *dsnFlag == "" {
		return fmt.Errorf("no DSN: set --dsn, EGRESS_DSN or EGRESS_DSN_FILE")
	}
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		log.Warn("unknown timezone, falling back to UTC", "timezone", *tz, "error", err)
		loc = time.UTC
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	m := newMetrics()
	go serveHTTP(ctx, *metricsAdr, m, log)

	c := &collector{
		log:        log,
		metrics:    m,
		node:       *node,
		loc:        loc,
		podCIDR:    mustPrefix(*podCIDR),
		svcCIDR:    mustPrefix(*svcCIDR),
		batchSize:  *batchSize,
		flushEvery: *flushEvery,
		spoolDir:   *spoolDir,
		in:         make(chan []byte, 10000),
	}
	c.reset()

	// Kubernetes client for pod -> workload resolution. Without it the
	// collector still runs: it falls back to flow.source.workloads and marks
	// the rest as bare pods.
	if client, err := k8s.InCluster(); err == nil {
		idx := k8s.NewIndex(client)
		if err := idx.Refresh(ctx); err != nil {
			log.Warn("initial workload index refresh failed", "error", err)
		}
		c.index = idx
		go func() {
			t := time.NewTicker(45 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := idx.Refresh(ctx); err != nil {
						log.Warn("workload index refresh failed", "error", err)
					}
				}
			}
		}()
	} else {
		log.Warn("no in-cluster Kubernetes client, relying on the flow's own workload metadata", "error", err)
	}

	conn := newConnector(*dsnFlag, *spoolDir, log, m)
	go conn.run(ctx)

	tail := &tailer{
		dir:       *logDir,
		node:      *node,
		files:     splitList(*files),
		log:       log,
		metrics:   m,
		offsets:   conn.offset,
		save:      conn.saveOffsets,
		out:       c.in,
		ckptEvery: *ckptEvery,
	}
	c.attach(conn)
	go tail.run(ctx)
	go c.run(ctx)
	go c.allowlistCoverage(ctx)

	<-ctx.Done()
	log.Info("shutting down")
	time.Sleep(500 * time.Millisecond) // let the final flush land
	return nil
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic("invalid CIDR " + s + ": " + err.Error())
	}
	return p
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// connector owns the database handle and reconnects when it is lost.
type connector struct {
	dsn      string
	spoolDir string
	log      *slog.Logger
	metrics  *metrics

	mu   chan struct{} // 1-slot mutex guarding the fields below
	db   *pg.DB
	offs map[string]pg.Offset
	// pendingOffsets are checkpoints that could not be written yet.
	pending []pg.Offset
}

func newConnector(dsn, spoolDir string, log *slog.Logger, m *metrics) *connector {
	return &connector{dsn: dsn, spoolDir: spoolDir, log: log, metrics: m, mu: make(chan struct{}, 1), offs: map[string]pg.Offset{}}
}

func (c *connector) lock()   { c.mu <- struct{}{} }
func (c *connector) unlock() { <-c.mu }

func (c *connector) run(ctx context.Context) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		db, err := pg.Open(ctx, c.dsn)
		if err != nil {
			c.metrics.dbUp.Set(0)
			c.log.Warn("database unavailable", "error", err, "retry_in", backoff)
			sleep(ctx, backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if err := db.Migrate(ctx); err != nil {
			db.Close()
			c.metrics.dbUp.Set(0)
			c.log.Warn("schema migration failed", "error", err)
			sleep(ctx, backoff)
			continue
		}
		offs, err := db.LoadOffsets(ctx)
		if err != nil {
			db.Close()
			sleep(ctx, backoff)
			continue
		}
		c.lock()
		c.db = db
		c.offs = offs
		c.unlock()
		backoff = time.Second
		c.metrics.dbUp.Set(1)
		c.log.Info("database connected", "checkpoints", len(offs))
		replaySpool(ctx, db, c.spoolDir, c.log, c.metrics)

		// Stay connected until the DB goes away.
		for {
			select {
			case <-ctx.Done():
				db.Close()
				return
			case <-time.After(15 * time.Second):
				if err := db.Ping(ctx); err != nil {
					c.log.Warn("database ping failed, reconnecting", "error", err)
					c.lock()
					c.db = nil
					c.unlock()
					db.Close()
					c.metrics.dbUp.Set(0)
					break
				}
			}
		}
	}
}

func (c *connector) handle() *pg.DB {
	c.lock()
	db := c.db
	c.unlock()
	return db
}

func (c *connector) offset(key string) (pg.Offset, bool) {
	c.lock()
	o, ok := c.offs[key]
	c.unlock()
	return o, ok
}

func (c *connector) saveOffsets(ctx context.Context, offs []pg.Offset) {
	db := c.handle()
	if db == nil {
		c.lock()
		c.pending = append(c.pending, offs...)
		c.unlock()
		return
	}
	if err := db.SaveOffsets(ctx, offs); err == nil {
		return
	}
	c.lock()
	c.pending = append(c.pending, offs...)
	c.unlock()
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
