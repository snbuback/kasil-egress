package flow

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

var cidrs = ClusterCIDRs{
	Pod: netip.MustParsePrefix("172.16.0.0/16"),
	Svc: netip.MustParsePrefix("172.30.0.0/16"),
}

func TestDecodeAuditAgg(t *testing.T) {
	lines := readLines(t, "../../testdata/flows/audit-agg.json.log")
	var got []*Observation
	for _, l := range lines {
		o, err := DecodeLine([]byte(l))
		if err != nil {
			t.Fatalf("decode %q: %v", l, err)
		}
		got = append(got, o)
	}
	if len(got) != len(lines) {
		t.Fatalf("decoded %d of %d lines", len(got), len(lines))
	}
	first := got[0]
	if first.Verdict != "FORWARDED" || first.Direction != "EGRESS" {
		t.Fatalf("unexpected verdict/direction: %s/%s", first.Verdict, first.Direction)
	}
	if first.Conns != 41233 {
		t.Errorf("aggregate conns = %d, want 41233", first.Conns)
	}
	if first.Port != 1883 || first.Proto != "TCP" {
		t.Errorf("l4 = %d/%s, want 1883/TCP", first.Port, first.Proto)
	}
	if first.Src.Namespace != "frigate" || first.Src.Workload != "frigate" || first.Src.Kind != "Deployment" {
		t.Errorf("source = %+v", first.Src)
	}
	if first.Dst.Workload != "nanomq" || first.Dst.Kind != "StatefulSet" {
		t.Errorf("destination = %+v", first.Dst)
	}
	if first.Node != "kube2.kasil.cloud" {
		t.Errorf("node = %q", first.Node)
	}
	if len(first.DstNames) != 1 || first.DstNames[0] != "nanomq.nanomq.svc.cluster.local" {
		t.Errorf("dst names = %v", first.DstNames)
	}

	// The fixture deliberately contains an ingress record and a reply record;
	// only the five egress requests may contribute edges.
	var egress int
	for _, o := range got {
		if o.IsEgressRequest() {
			egress++
		}
	}
	if egress != 5 {
		t.Errorf("egress request records = %d, want 5", egress)
	}
}

func TestDecodeDenyRaw(t *testing.T) {
	lines := readLines(t, "../../testdata/flows/deny-raw.json.log")
	o, err := DecodeLine([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !o.IsDenied() || o.Verdict != "DROPPED" {
		t.Fatalf("expected a denial, got %s", o.Verdict)
	}
	if o.DropReason != "POLICY_DENIED" {
		t.Errorf("drop reason = %q, want POLICY_DENIED", o.DropReason)
	}
	if o.Port != 443 || o.Dst.IP != "140.82.121.6" {
		t.Errorf("flow = %d -> %s", o.Port, o.Dst.IP)
	}
	if o.Conns != 1 {
		t.Errorf("non-aggregated conns = %d, want 1", o.Conns)
	}

	o2, err := DecodeLine([]byte(lines[1]))
	if err != nil {
		t.Fatal(err)
	}
	if o2.Proto != "UDP" || o2.Port != 53 {
		t.Errorf("udp deny decoded as %s/%d", o2.Proto, o2.Port)
	}
}

func TestDecodeDNS(t *testing.T) {
	lines := readLines(t, "../../testdata/flows/dns-raw.json.log")
	req, err := DecodeLine([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	if req.DNSQuery != "api.telegram.org" {
		t.Errorf("query = %q", req.DNSQuery)
	}
	if len(req.DNSIPs) != 0 {
		t.Errorf("request should carry no answers, got %v", req.DNSIPs)
	}
	resp, err := DecodeLine([]byte(lines[1]))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.DNSIPs) != 1 || resp.DNSIPs[0] != "149.154.167.220" {
		t.Errorf("answers = %v", resp.DNSIPs)
	}
}

func TestDecodeStaticBare(t *testing.T) {
	lines := readLines(t, "../../testdata/flows/static-bare.json.log")
	o, err := DecodeLine([]byte(lines[0]))
	if err != nil {
		t.Fatalf("bare flow: %v", err)
	}
	if o.Src.Namespace != "grafana" || o.Port != 8428 {
		t.Errorf("unexpected observation: %+v", o)
	}
	if _, err := DecodeLine([]byte(lines[1])); err != ErrIgnored {
		t.Errorf("lost event: got %v, want ErrIgnored", err)
	}
	if _, err := DecodeLine([]byte(lines[2])); err == nil {
		t.Error("garbage line decoded without error")
	}
	if _, err := DecodeLine([]byte("")); err != ErrIgnored {
		t.Errorf("empty line: got %v, want ErrIgnored", err)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		obs  Observation
		want Dest
	}{
		{
			name: "workload wins over everything",
			obs:  Observation{Src: Endpoint{}, Dst: Endpoint{Namespace: "nanomq", Workload: "nanomq", Kind: "StatefulSet"}, DstNames: []string{"api.example.com"}},
			want: Dest{Kind: KindWorkload, Key: "nanomq/StatefulSet/nanomq", Namespace: "nanomq"},
		},
		{
			name: "service fqdn",
			obs:  Observation{Dst: Endpoint{IP: "172.30.0.42"}, DstNames: []string{"kube-dns.kube-system.svc.cluster.local"}},
			want: Dest{Kind: KindService, Key: "kube-system/kube-dns", Namespace: "kube-system"},
		},
		{
			name: "apiserver",
			obs:  Observation{Dst: Endpoint{IP: "172.30.0.1"}, DstNames: []string{"kubernetes.default.svc.cluster.local"}},
			want: Dest{Kind: KindEntity, Key: "kube-apiserver"},
		},
		{
			name: "unresolved pod",
			obs:  Observation{Dst: Endpoint{Namespace: "frigate", PodName: "frigate-abc"}},
			want: Dest{Kind: KindWorkload, Key: "frigate/Pod/frigate-abc", Namespace: "frigate"},
		},
		{
			name: "service IP without a name",
			obs:  Observation{Dst: Endpoint{IP: "172.30.1.7"}},
			want: Dest{Kind: KindService, Key: "172.30.1.7", NoOwner: true},
		},
		{
			name: "pod IP without an owner",
			obs:  Observation{Dst: Endpoint{IP: "172.16.9.9"}},
			want: Dest{Kind: KindCIDR, Key: "172.16.9.9/32", NoOwner: true},
		},
		{
			name: "fqdn",
			obs:  Observation{Dst: Endpoint{IP: "140.82.121.6"}, DstNames: []string{"api.github.com."}},
			want: Dest{Kind: KindFQDN, Key: "api.github.com"},
		},
		{
			name: "lan device",
			obs:  Observation{Dst: Endpoint{IP: "192.168.31.10"}},
			want: Dest{Kind: KindCIDR, Key: "192.168.31.10/32"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(&tt.obs, cidrs); got != tt.want {
				t.Errorf("Classify() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
