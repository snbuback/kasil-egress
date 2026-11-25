package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/model"
)

func testWorkload() model.Workload {
	return model.Workload{
		Namespace: "frigate", Kind: "Deployment", Name: "frigate",
		Selector:  map[string]string{"app.kubernetes.io/name": "frigate", "app.kubernetes.io/instance": "frigate"},
		PodLabels: map[string]string{"app.kubernetes.io/name": "frigate", "app.kubernetes.io/instance": "frigate", "pod-template-hash": "7d9f8c6b5"},
	}
}

func edge(id int64, kind, key string, port int, proto string) model.Edge {
	return model.Edge{
		ID: id, Workload: testWorkload(), DstKind: kind, DstKey: key, Port: port, Proto: proto,
		FirstSeen:  time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 12, 8, 9, 0, 0, 0, time.UTC),
		ConnsTotal: 100, DaysSeen: 14,
	}
}

func baseOpts() Options {
	return Options{
		PodCIDR:       netip.MustParsePrefix("172.16.0.0/16"),
		SvcCIDR:       netip.MustParsePrefix("172.30.0.0/16"),
		PrivateCIDRs:  DefaultPrivateCIDRs(),
		GeneratedFrom: "test",
	}
}

func TestBuildGroupsAndSorts(t *testing.T) {
	nanomq := model.Workload{
		Namespace: "nanomq", Kind: "StatefulSet", Name: "nanomq",
		Selector:  map[string]string{"app.kubernetes.io/name": "nanomq"},
		PodLabels: map[string]string{"app.kubernetes.io/name": "nanomq"},
	}
	edges := []model.Edge{
		edge(1, model.KindWorkload, "nanomq/StatefulSet/nanomq", 1883, "TCP"),
		edge(2, model.KindWorkload, "nanomq/StatefulSet/nanomq", 8883, "TCP"),
		edge(3, model.KindCIDR, "192.168.31.10/32", 554, "TCP"),
		edge(4, model.KindFQDN, "api.telegram.org", 443, "TCP"),
		edge(5, model.KindCIDR, "140.82.121.6/32", 443, "TCP"), // public, unnamed
		edge(6, model.KindEntity, "kube-apiserver", 443, "TCP"),
		edge(7, model.KindWorkload, "unknown/Deployment/ghost", 80, "TCP"),
		edge(8, model.KindCIDR, "192.168.31.11/32", 80, "TCP"),
		edge(9, model.KindService, "172.30.5.5", 443, "TCP"), // service without a name
		edge(10, model.KindService, "victoria/vmsingle", 8428, "TCP"),
	}
	for i := range edges {
		if edges[i].DstKind == model.KindWorkload && strings.HasPrefix(edges[i].DstKey, "nanomq/") {
			p := nanomq
			edges[i].Peer = &p
		}
	}

	c := Build(testWorkload(), edges, baseOpts())

	var kinds []string
	for _, r := range c.Rules {
		kinds = append(kinds, r.Kind+":"+r.Value)
	}
	want := []string{
		"workload:nanomq/StatefulSet/nanomq",
		"service:victoria/vmsingle",
		"cidr:192.168.31.10/32",
		"cidr:192.168.31.11/32",
		"fqdn:api.telegram.org",
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("rules = %v, want %v", kinds, want)
	}
	// Both nanomq ports collapse into one rule.
	if got := len(c.Rules[0].Ports); got != 2 {
		t.Errorf("nanomq ports = %d, want 2", got)
	}
	// And they are sorted.
	if c.Rules[0].Ports[0].Port != 1883 || c.Rules[0].Ports[1].Port != 8883 {
		t.Errorf("ports not sorted: %+v", c.Rules[0].Ports)
	}

	reasons := map[string]string{}
	for _, s := range c.Skipped {
		reasons[s.Dest] = s.Reason
	}
	for dest, reason := range map[string]string{
		"140.82.121.6/32":          "world-unnamed",
		"kube-apiserver":           "baseline-covers",
		"unknown/Deployment/ghost": "peer-unresolved",
		"172.30.5.5":               "service-ip-unknown",
	} {
		if reasons[dest] != reason {
			t.Errorf("skip reason for %s = %q, want %q", dest, reasons[dest], reason)
		}
	}
}

func TestRenderGolden(t *testing.T) {
	edges := []model.Edge{
		edge(1, model.KindFQDN, "api.telegram.org", 443, "TCP"),
		edge(2, model.KindCIDR, "192.168.31.10/32", 554, "TCP"),
	}
	c := Build(testWorkload(), edges, baseOpts())
	opts := baseOpts()
	out, err := Render(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"apiVersion: cilium.io/v2",
		"kind: CiliumNetworkPolicy",
		"name: frigate-egress",
		"namespace: frigate",
		"enableDefaultDeny:\n    egress: true",
		"app.kubernetes.io/instance: frigate",
		"toCIDR:\n        - 192.168.31.10/32",
		"toFQDNs:\n        - matchName: api.telegram.org",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered policy missing %q\n%s", want, got)
		}
	}
	// FQDN rules imply the DNS rule.
	if !strings.Contains(got, "matchPattern: '*'") {
		t.Errorf("rendered policy is missing the DNS rule:\n%s", got)
	}
	// The CIDR rule must not be merged with the FQDN rule's ports.
	if strings.Contains(got, "0.0.0.0/0") {
		t.Errorf("rendered policy contains a world rule:\n%s", got)
	}

	// Shadow mode flips the flag without changing the rules.
	shadow := opts
	shadow.Shadow = true
	out2, err := Render(c, shadow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out2), "egress: false") {
		t.Errorf("shadow render did not disable default-deny:\n%s", out2)
	}
}

func viaVPNIsolation() k8s.Policy {
	return k8s.Policy{
		Kind: "CiliumClusterwideNetworkPolicy", Name: "via-vpn-isolation",
		Selector: k8s.Selector{MatchLabels: map[string]string{"kasil.cloud/via-vpn": "true"}},
		Egress: []k8s.EgressRule{
			{
				ToEndpoints: []k8s.Selector{{MatchLabels: map[string]string{
					"k8s:io.kubernetes.pod.namespace": "kube-system",
					"k8s:k8s-app":                     "kube-dns",
				}}},
				ToPorts: []k8s.ToPort{{Ports: []k8s.Port{{Port: "53", Protocol: "UDP"}, {Port: "53", Protocol: "TCP"}}}},
			},
			{ToEntities: []string{"world"}},
		},
	}
}

func TestNeverWidenDropsInClusterPeers(t *testing.T) {
	// A workload labelled as untrusted: the isolation policy constrains it.
	w := testWorkload()
	w.PodLabels["kasil.cloud/via-vpn"] = "true"

	nanomq := model.Workload{
		Namespace: "nanomq", Kind: "StatefulSet", Name: "nanomq",
		Selector:  map[string]string{"app.kubernetes.io/name": "nanomq"},
		PodLabels: map[string]string{"app.kubernetes.io/name": "nanomq"},
	}
	edges := []model.Edge{
		{ID: 1, Workload: w, DstKind: model.KindWorkload, DstKey: "nanomq/StatefulSet/nanomq", Port: 1883, Proto: "TCP", Peer: &nanomq},
		{ID: 2, Workload: w, DstKind: model.KindFQDN, DstKey: "api.telegram.org", Port: 443, Proto: "TCP"},
		{ID: 3, Workload: w, DstKind: model.KindCIDR, DstKey: "192.168.31.10/32", Port: 554, Proto: "TCP"},
	}
	constraint := NewConstraint([]k8s.Policy{viaVPNIsolation()})
	if !constraint.Active() {
		t.Fatal("constraint should be active")
	}
	opts := baseOpts()
	opts.Constraint = constraint

	c := Build(w, edges, opts)
	if len(c.PrePoliced) != 1 || c.PrePoliced[0] != "CiliumClusterwideNetworkPolicy/via-vpn-isolation" {
		t.Errorf("PrePoliced = %v", c.PrePoliced)
	}
	var kept []string
	for _, r := range c.Rules {
		kept = append(kept, r.Kind+":"+r.Value)
	}
	want := []string{"cidr:192.168.31.10/32", "fqdn:api.telegram.org"}
	if strings.Join(kept, ",") != strings.Join(want, ",") {
		t.Fatalf("kept rules = %v, want %v (the in-cluster peer must be dropped)", kept, want)
	}
	var dropped bool
	for _, s := range c.Skipped {
		if s.Reason == "pre-policed-dropped" && strings.Contains(s.Dest, "nanomq") {
			dropped = true
		}
	}
	if !dropped {
		t.Errorf("in-cluster peer was not reported as pre-policed-dropped: %+v", c.Skipped)
	}

	// An explicit acknowledgement re-enables it, with the annotation on the
	// rendered object.
	ack := opts
	ack.AckPrePoliced = "CiliumClusterwideNetworkPolicy/via-vpn-isolation"
	c2 := Build(w, edges, ack)
	if len(c2.Rules) != 3 {
		t.Errorf("with --ack-pre-policed: %d rules, want 3", len(c2.Rules))
	}
	out, err := Render(c2, ack)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "egress.kasil.io/ack-pre-policed") {
		t.Errorf("acknowledgement annotation missing:\n%s", out)
	}
}

func TestConstraintInactiveSkipsGeneration(t *testing.T) {
	// The isolation CCNP with enableDefaultDeny.egress=false constrains
	// nothing, so generation is refused rather than guessed.
	p := viaVPNIsolation()
	no := false
	p.EnableDefaultDenyEgress = &no
	c := NewConstraint([]k8s.Policy{p})
	if c.Active() {
		t.Fatal("policy with enableDefaultDeny.egress=false must not be active")
	}
	if !c.SkipGeneration() {
		t.Fatal("SkipGeneration must be set when a selecting policy constrains nothing")
	}
}

func TestRuleName(t *testing.T) {
	tests := []struct {
		w    model.Workload
		want string
	}{
		{model.Workload{Namespace: "frigate", Kind: "Deployment", Name: "frigate"}, "frigate-egress"},
		{model.Workload{Namespace: "renovate", Kind: "CronJob", Name: "renovate"}, "renovate-cronjob-egress"},
		{model.Workload{Namespace: "x", Kind: "Deployment", Name: "Victoria_Metrics"}, "victoria-metrics-egress"},
		{model.Workload{Namespace: "x", Kind: "Deployment", Name: "a--b"}, "a-b-egress"},
	}
	for _, tt := range tests {
		if got := RuleName(tt.w); got != tt.want {
			t.Errorf("RuleName(%s/%s) = %q, want %q", tt.w.Kind, tt.w.Name, got, tt.want)
		}
	}
}
