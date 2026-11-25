package main

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/snbuback/kasil-egress/pkg/model"
)

func testCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:   newMetrics(),
		node:      "kube2.kasil.cloud",
		loc:       time.UTC,
		podCIDR:   netip.MustParsePrefix("172.16.0.0/16"),
		svcCIDR:   netip.MustParsePrefix("172.30.0.0/16"),
		batchSize: 500,
		spoolDir:  t.TempDir(),
	}
	c.reset()
	return c
}

func feed(t *testing.T, c *collector, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, line := range splitLines(b) {
		c.consume(line)
		lines++
	}
	return lines
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, ch := range b {
		if ch == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestConsumeAuditAgg(t *testing.T) {
	c := testCollector(t)
	feed(t, c, "../../testdata/flows/audit-agg.json.log")

	// The fixture holds five distinct egress tuples plus one ingress and one
	// reply record, which must not produce edges.
	if len(c.edges) != 5 {
		for k := range c.edges {
			t.Logf("edge key: %s", k)
		}
		t.Fatalf("edges = %d, want 5 (ingress and reply records must be ignored)", len(c.edges))
	}
	var nanomq *pgEdge
	for key, r := range c.edges {
		if c.edgeSource[key] == "frigate/Deployment/frigate" && r.DstKey == "nanomq/StatefulSet/nanomq" {
			nanomq = &pgEdge{r.SrcWorkloadID, r.DstKind, r.DstKey, r.Port, r.Proto, r.Conns, r.HourMask}
		}
	}
	if nanomq == nil {
		t.Fatal("nanomq edge missing")
	}
	if nanomq.Conns != 41233 {
		t.Errorf("nanomq conns = %d, want 41233", nanomq.Conns)
	}
	if nanomq.Kind != model.KindWorkload || nanomq.Proto != "TCP" || nanomq.Port != 1883 {
		t.Errorf("nanomq edge = %+v", nanomq)
	}
	// 10:00 UTC -> hour bit 10 set. The mask is a PostgreSQL bit(24),
	// MSB first, so hour 10 is the character at index 23-10.
	if nanomq.Hours != "000000000000010000000000" {
		t.Errorf("hour mask = %q", nanomq.Hours)
	}

	// Aggregate rows are kept for the 60 s windows.
	if len(c.raw) == 0 {
		t.Error("no flow_raw_agg rows produced from aggregated records")
	}
	// Every workload seen in the fixtures must be registered for upsert.
	for _, key := range []string{"frigate/Deployment/frigate", "hermes/StatefulSet/hermes", "renovate/CronJob/renovate"} {
		if _, ok := c.refs[key]; !ok {
			t.Errorf("workload %s missing from refs", key)
		}
	}
}

type pgEdge struct {
	SrcWorkloadID int64
	Kind          string
	Key           string
	Port          int
	Proto         string
	Conns         int64
	Hours         string
}

func TestConsumeDeny(t *testing.T) {
	c := testCollector(t)
	feed(t, c, "../../testdata/flows/deny-raw.json.log")

	if len(c.blocked) != 2 {
		t.Fatalf("blocked rows = %d, want 2", len(c.blocked))
	}
	if len(c.edges) != 0 {
		t.Errorf("denials must not become edges, got %d", len(c.edges))
	}
	b := c.blocked[0]
	if b.Verdict != "DROPPED" || b.DropReason != "POLICY_DENIED" {
		t.Errorf("blocked row = %+v", b)
	}
	if b.Port != 443 || b.Proto != "TCP" || b.DstIP != "140.82.121.6" {
		t.Errorf("blocked row target = %d/%s %s", b.Port, b.Proto, b.DstIP)
	}
	if c.blockedSource[0] != "renovate/CronJob/renovate" {
		t.Errorf("blocked source = %q", c.blockedSource[0])
	}
}

func TestConsumeDNS(t *testing.T) {
	c := testCollector(t)
	feed(t, c, "../../testdata/flows/dns-raw.json.log")

	// The response carries one answer; the request carries none.
	if len(c.dns) != 1 {
		t.Fatalf("dns rows = %d, want 1", len(c.dns))
	}
	for _, r := range c.dns {
		if r.FQDN != "api.telegram.org" || r.IP != "149.154.167.220" {
			t.Errorf("dns row = %+v", r)
		}
	}
}

func TestConsumeClassifiesLANAndFQDN(t *testing.T) {
	c := testCollector(t)
	feed(t, c, "../../testdata/flows/audit-agg.json.log")

	kinds := map[string]bool{}
	for _, r := range c.edges {
		kinds[r.DstKind+"|"+r.DstKey] = true
	}
	for _, want := range []string{
		"workload|nanomq/StatefulSet/nanomq",
		"cidr|192.168.31.10/32",
		"fqdn|api.telegram.org",
		"fqdn|api.github.com",
	} {
		if !kinds[want] {
			t.Errorf("missing edge %s (got %v)", want, kinds)
		}
	}
}

func TestOrBits(t *testing.T) {
	a := "100000000000000000000000"
	b := "000000000000000000000001"
	if got := orBits(a, b); got != "100000000000000000000001" {
		t.Errorf("orBits = %q", got)
	}
	if got := orBits("short", b); got != b {
		t.Errorf("orBits with a short input = %q", got)
	}
}
