package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/policy"
)

func fixture() Input {
	w := model.Workload{
		Namespace: "frigate", Kind: "Deployment", Name: "frigate",
		Selector:  map[string]string{"app.kubernetes.io/name": "frigate"},
		PodLabels: map[string]string{"app.kubernetes.io/name": "frigate"},
	}
	from := time.Date(2026, 11, 24, 9, 12, 0, 0, time.UTC)
	to := time.Date(2026, 12, 8, 9, 12, 0, 0, time.UTC)
	edges := []model.Edge{
		{ID: 1, Workload: w, DstKind: model.KindWorkload, DstKey: "nanomq/StatefulSet/nanomq", DstNamespace: "nanomq", Port: 1883, Proto: "TCP", ConnsTotal: 41233, FirstSeen: from, LastSeen: to, ActiveHours: "111111111111111111111111"},
		{ID: 2, Workload: w, DstKind: model.KindCIDR, DstKey: "192.168.31.10/32", Port: 554, Proto: "TCP", ConnsTotal: 1988, FirstSeen: from, LastSeen: to, ActiveHours: "111111111111111111111111"},
		{ID: 3, Workload: w, DstKind: model.KindFQDN, DstKey: "api.telegram.org", Port: 443, Proto: "TCP", ConnsTotal: 412, FirstSeen: from, LastSeen: to, ActiveHours: "000000000011111111111100"},
	}
	c := policy.Build(w, edges, policy.Options{
		PodCIDR:      netip.MustParsePrefix("172.16.0.0/16"),
		SvcCIDR:      netip.MustParsePrefix("172.30.0.0/16"),
		PrivateCIDRs: policy.DefaultPrivateCIDRs(),
	})
	return Input{
		GeneratedAt: time.Date(2026, 12, 8, 10, 0, 0, 0, time.UTC),
		Cluster:     Cluster{Name: "kasil", PodCIDR: "172.16.0.0/16", SvcCIDR: "172.30.0.0/16", Window: "2026-11-24 → 2026-12-08"},
		Workloads: []Workload{{
			Workload:  w,
			Replicas:  2,
			Nodes:     []string{"kube2.kasil.cloud", "kube3.kasil.cloud"},
			Images:    []string{"ghcr.io/blakeblackshear/frigate:0.18.3"},
			Edges:     edges,
			Candidate: c,
			Flags:     ComputeFlags(w, edges, nil),
		}},
		Exemptions: []Exemption{{Subject: "kube-system", Reason: "control plane"}},
		Coverage:   Coverage{Workloads: 1, WithRules: 1, WithExemptions: 1, Percent: 100},
	}
}

func TestMarkdown(t *testing.T) {
	var sb strings.Builder
	if err := Markdown(&sb, fixture(), "frigate"); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	for _, want := range []string{
		"## namespace: frigate",
		"### Deployment/frigate",
		"replicas 2",
		"node kube2.kasil.cloud,kube3.kasil.cloud",
		"image ghcr.io/blakeblackshear/frigate:0.18.3",
		"| destination | kind | port/proto | conns |",
		"nanomq/StatefulSet/nanomq",
		"192.168.31.10/32",
		"api.telegram.org",
		"fan-out: 3 peers",
		"suggested policy (review, not applied)",
		"name: frigate-egress",
		// The suggestion is shadow: a Phase 1 report must never hand over an
		// enforcing policy.
		"enableDefaultDeny:\n    egress: false",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown missing %q\n%s", want, got)
		}
	}
}

func TestMarkdownEmptyNamespace(t *testing.T) {
	var sb strings.Builder
	if err := Markdown(&sb, fixture(), "nope"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "no observed egress") {
		t.Errorf("unexpected output: %s", sb.String())
	}
}

func TestSummary(t *testing.T) {
	var sb strings.Builder
	if err := Summary(&sb, fixture()); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	for _, want := range []string{
		"# Egress audit — summary",
		"workloads audited: 1",
		"coverage: 100.0%",
		"| frigate | 1 | 3 |",
		"| kube-system | control plane |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q\n%s", want, got)
		}
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, fixture()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("csv rows = %d, want header + 3", len(rows))
	}
	if rows[0][0] != "namespace" || rows[0][3] != "destination" {
		t.Errorf("header = %v", rows[0])
	}
	if rows[1][0] != "frigate" || rows[1][3] != "nanomq/StatefulSet/nanomq" {
		t.Errorf("first row = %v", rows[1])
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, fixture()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["Workloads"]; !ok {
		t.Errorf("json missing Workloads: %s", buf.String())
	}
}

func TestComputeFlags(t *testing.T) {
	w := model.Workload{Namespace: "x", Kind: "Deployment", Name: "y", Selector: map[string]string{"a": "b"}}
	pub := model.Edge{DstKind: model.KindCIDR, DstKey: "140.82.121.6/32", Port: 443, Proto: "TCP", ConnsTotal: 2,
		FirstSeen: time.Now().Add(-48 * time.Hour), LastSeen: time.Now(), ActiveHours: "010000000000000000000000"}
	flags := ComputeFlags(w, []model.Edge{pub}, nil)
	for _, want := range []string{"NO-DNS", "CRON-ONLY", "LOW-VOLUME"} {
		found := false
		for _, f := range flags {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("flags %v missing %s", flags, want)
		}
	}

	// A workload with three external /24s is BROAD.
	var broad []model.Edge
	for _, ip := range []string{"1.0.0.1", "2.0.0.1", "3.0.0.1"} {
		broad = append(broad, model.Edge{DstKind: model.KindFQDN, DstKey: "x" + ip, Port: 443, Proto: "TCP",
			ConnsTotal: 100, FirstSeen: time.Now().Add(-24 * time.Hour), LastSeen: time.Now(), ActiveHours: "111111111111111111111111"})
	}
	for i := range broad {
		broad[i].DstKind = model.KindCIDR
		broad[i].DstKey = []string{"1.0.0.1/32", "2.0.0.1/32", "3.0.0.1/32"}[i]
	}
	flags = ComputeFlags(w, broad, []string{"CiliumClusterwideNetworkPolicy/via-vpn-isolation"})
	var hasBroad, hasPre bool
	for _, f := range flags {
		if f == "BROAD" {
			hasBroad = true
		}
		if f == "PRE-POLICED" {
			hasPre = true
		}
	}
	if !hasBroad || !hasPre {
		t.Errorf("flags = %v, want BROAD and PRE-POLICED", flags)
	}

	// Unlabelled workloads cannot be selected by a label policy.
	flags = ComputeFlags(model.Workload{Namespace: "x", Kind: "Pod", Name: "z"}, nil, nil)
	if !contains(flags, "UNLABELED") || !contains(flags, "NO-EDGES") {
		t.Errorf("flags = %v, want UNLABELED and NO-EDGES", flags)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
