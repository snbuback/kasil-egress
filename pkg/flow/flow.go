// Package flow decodes Hubble flow-log records written by Cilium's dynamic
// (and static) flow-log exporter and normalizes them into Observations that
// the collector and the report generator both understand.
//
// # Wire format
//
// The exporter writes one JSON object per line using
// encoding/json on observerpb.ExportEvent, whose generated MarshalJSON uses
// protojson with proto field names (snake_case). A line therefore looks like
//
//	{"flow":{...},"node_name":"kube2.kasil.cloud","time":"2026-11-25T10:00:00Z"}
//
// and, for the static file exporter, a bare flow object. Both are accepted.
// Enum values are proto enum names ("EGRESS", "DROPPED"), the l4 oneof is
// wrapped ("l4":{"TCP":{...}}"), and aggregated exporters add
// "aggregate":{"egress_flow_count":N}.
//
// Rather than re-declare that schema by hand, this package unmarshals into the
// real flowpb.Flow / observerpb.ExportEvent types from the Cilium API module.
// That is the same approach the upstream hubble CLI takes, and it means a new
// Cilium field can never silently break the parser.
package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// ErrIgnored marks a syntactically valid record that carries no flow (a lost
// event or an agent event). Callers count it and move on.
var ErrIgnored = errors.New("not a flow record")

// Observation is one normalized flow record.
type Observation struct {
	Time            time.Time
	Node            string
	Verdict         string
	DropReason      string
	Direction       string
	IsReply         bool
	Aggregate       bool
	Conns           int64
	PolicyMatchType uint32

	Src      Endpoint
	Dst      Endpoint
	DstNames []string

	Port  int
	Proto string

	DNSQuery string
	DNSIPs   []string
	DNSRCode int
}

// Endpoint is the source or destination side of a flow.
type Endpoint struct {
	Namespace string
	PodName   string
	IP        string
	Identity  uint32
	Workload  string
	Kind      string
	Labels    []string
}

// DecodeLine parses a single flow-log line. It accepts both the dynamic
// exporter envelope and a bare flow object, and tolerates a trailing CR.
func DecodeLine(line []byte) (*Observation, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return nil, ErrIgnored
	}

	var env observerpb.ExportEvent
	if err := env.UnmarshalJSON(line); err == nil {
		switch r := env.ResponseTypes.(type) {
		case *observerpb.ExportEvent_Flow:
			if r.Flow == nil {
				return nil, ErrIgnored
			}
			obs := FromFlow(r.Flow)
			if obs.Node == "" {
				obs.Node = env.GetNodeName()
			}
			if obs.Time.IsZero() {
				obs.Time = env.GetTime().AsTime()
			}
			return obs, nil
		case *observerpb.ExportEvent_LostEvents, *observerpb.ExportEvent_AgentEvent, *observerpb.ExportEvent_DebugEvent:
			return nil, ErrIgnored
		}
	}

	var f flowpb.Flow
	if err := f.UnmarshalJSON(line); err != nil {
		// Non-flow envelopes (lost events, agent events) carry no flow and are
		// not an error; anything else is.
		if bytes.Contains(line, []byte(`"lost_events"`)) || bytes.Contains(line, []byte(`"agent_event"`)) || bytes.Contains(line, []byte(`"debug_event"`)) {
			return nil, ErrIgnored
		}
		// Fall back to a plain JSON decode for records produced by an older
		// exporter that did not use protojson (enums as numbers).
		var legacy flowpb.Flow
		if err2 := json.Unmarshal(line, &legacy); err2 != nil {
			return nil, fmt.Errorf("decode flow: %w", err)
		}
		return FromFlow(&legacy), nil
	}
	return FromFlow(&f), nil
}

// FromFlow converts a parsed protobuf flow into an Observation.
func FromFlow(f *flowpb.Flow) *Observation {
	o := &Observation{
		Time:            f.GetTime().AsTime(),
		Node:            f.GetNodeName(),
		Verdict:         f.GetVerdict().String(),
		DropReason:      f.GetDropReasonDesc().String(),
		Direction:       f.GetTrafficDirection().String(),
		IsReply:         f.GetIsReply().GetValue(),
		PolicyMatchType: f.GetPolicyMatchType(),
		Src:             endpoint(f.GetSource(), f.GetIP().GetSource()),
		Dst:             endpoint(f.GetDestination(), f.GetIP().GetDestination()),
		DstNames:        normalizeNames(f.GetDestinationNames()),
	}
	if agg := f.GetAggregate(); agg != nil {
		o.Aggregate = true
		o.Conns = int64(agg.GetEgressFlowCount())
		if o.Direction == "" || o.Direction == "TRAFFIC_DIRECTION_UNKNOWN" {
			if agg.GetIngressFlowCount() > 0 && agg.GetEgressFlowCount() == 0 {
				o.Direction = "INGRESS"
			}
		}
		if o.Direction == "EGRESS" && o.Conns == 0 {
			o.Conns = int64(agg.GetUnknownDirectionFlowCount())
		}
	} else {
		o.Conns = 1
	}
	if o.Conns <= 0 {
		o.Conns = 1
	}
	o.Port, o.Proto = l4(f.GetL4())
	if dns := f.GetL7().GetDns(); dns != nil {
		o.DNSQuery = strings.TrimSuffix(dns.GetQuery(), ".")
		for _, ip := range dns.GetIps() {
			o.DNSIPs = append(o.DNSIPs, ip)
		}
		o.DNSRCode = int(dns.GetRcode())
	}
	return o
}

func endpoint(e *flowpb.Endpoint, ip string) Endpoint {
	ep := Endpoint{IP: ip}
	if e == nil {
		return ep
	}
	ep.Namespace = e.GetNamespace()
	ep.PodName = e.GetPodName()
	ep.Identity = e.GetIdentity()
	ep.Labels = e.GetLabels()
	if w := e.GetWorkloads(); len(w) > 0 {
		// Cilium lists every known owner; the first entry is the most
		// specific one (e.g. Deployment before ReplicaSet).
		ep.Workload = w[0].GetName()
		ep.Kind = w[0].GetKind()
	}
	return ep
}

func l4(l *flowpb.Layer4) (port int, proto string) {
	if l == nil {
		return 0, "UNKNOWN"
	}
	switch p := l.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		return int(p.TCP.GetDestinationPort()), "TCP"
	case *flowpb.Layer4_UDP:
		return int(p.UDP.GetDestinationPort()), "UDP"
	case *flowpb.Layer4_ICMPv4:
		return 0, "ICMPv4"
	case *flowpb.Layer4_ICMPv6:
		return 0, "ICMPv6"
	case *flowpb.Layer4_SCTP:
		return int(p.SCTP.GetDestinationPort()), "SCTP"
	case *flowpb.Layer4_VRRP:
		return 0, "VRRP"
	case *flowpb.Layer4_IGMP:
		return 0, "IGMP"
	}
	return 0, "UNKNOWN"
}

func normalizeNames(names []string) []string {
	out := make([]string, 0, len(names))
	seen := map[string]struct{}{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// IsEgressRequest reports whether the observation is a request-direction
// egress flow. Reply flows and ingress flows are dropped by the collector:
// they duplicate the same edge from the peer's perspective (per-node
// duplication is a documented non-goal of the aggregation feature).
func (o *Observation) IsEgressRequest() bool {
	return o.Direction == "EGRESS" && !o.IsReply
}

// IsDenied reports whether the record is a denial (or a would-be denial in
// audit mode), which is what the review queue is built from.
func (o *Observation) IsDenied() bool {
	switch o.Verdict {
	case "DROPPED", "AUDIT", "ERROR":
		return true
	}
	return false
}
