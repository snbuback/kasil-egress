package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/snbuback/kasil-egress/pkg/model"
)

// Rule kinds. They mirror the report's `kind` column and the emitted YAML.
const (
	RuleWorkload = "workload"
	RuleService  = "service"
	RuleFQDN     = "fqdn"
	RuleCIDR     = "cidr"
	RuleEntity   = "entity"
)

// Port is one allowed port/proto pair.
type Port struct {
	Port  int
	Proto string
}

func (p Port) String() string { return fmt.Sprintf("%d/%s", p.Port, strings.ToUpper(p.Proto)) }

// Rule is one generated allow rule, deduplicated across edges.
type Rule struct {
	Kind      string
	Value     string // workload key, ns/svc, fqdn, prefix
	Namespace string
	// Selector is set for workload peers: the labels that select the peer's
	// pods.
	Selector map[string]string
	// PeerLabels are the peer pod's full labels, used to evaluate a
	// pre-existing policy selector against this rule.
	PeerLabels map[string]string
	Ports      []Port
	EdgeIDs    []int64
	// Note carries a reviewer-facing comment (e.g. "LAN device").
	Note string
}

// Skipped records an observed edge that produced no rule, with the reason.
type Skipped struct {
	EdgeID int64
	Dest   string
	Port   Port
	Reason string
}

// Candidate is the generated allowlist for one workload.
type Candidate struct {
	Workload model.Workload
	Rules    []Rule
	Skipped  []Skipped
	// PrePoliced lists existing policies that already select this workload
	// and constrain its egress.
	PrePoliced []string
	// EgressGateway lists CiliumEgressGatewayPolicy objects selecting it.
	EgressGateway []string
	Flags         []string
}

// Options configures generation.
type Options struct {
	// Shadow emits enableDefaultDeny.egress: false (rules evaluated, nothing
	// denied). Enforce emits true.
	Shadow bool
	// PodCIDR and SvcCIDR are used to reject pod-IP rules and to classify
	// in-cluster destinations.
	PodCIDR netip.Prefix
	SvcCIDR netip.Prefix
	// PrivateCIDRs are the LAN ranges that a toCIDR rule may legitimately
	// cover (a camera, a router). Public unnamed destinations are never
	// auto-emitted.
	PrivateCIDRs []netip.Prefix
	// Constraint is the upper bound imposed by pre-existing policies.
	Constraint *Constraint
	// AckPrePoliced records an explicit human acknowledgement that the
	// generated policy widens the existing one.
	AckPrePoliced string
	// GeneratedFrom is stamped into an annotation.
	GeneratedFrom string
}

// DefaultPrivateCIDRs are RFC1918 blocks (plus CGNAT) treated as "LAN".
func DefaultPrivateCIDRs() []netip.Prefix {
	must := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	return []netip.Prefix{must("10.0.0.0/8"), must("172.16.0.0/12"), must("192.168.0.0/16"), must("100.64.0.0/10")}
}

// Build turns observed edges into a deterministic allowlist.
func Build(w model.Workload, edges []model.Edge, opts Options) Candidate {
	c := Candidate{Workload: w}
	if opts.Constraint != nil {
		c.PrePoliced = opts.Constraint.Refs()
	}

	type key struct{ kind, value string }
	acc := map[key]*Rule{}
	var order []key

	add := func(r Rule) {
		k := key{r.Kind, r.Value}
		if existing, ok := acc[k]; ok {
			existing.Ports = mergePorts(existing.Ports, r.Ports)
			existing.EdgeIDs = append(existing.EdgeIDs, r.EdgeIDs...)
			return
		}
		rr := r
		acc[k] = &rr
		order = append(order, k)
	}

	skip := func(e model.Edge, reason string) {
		c.Skipped = append(c.Skipped, Skipped{EdgeID: e.ID, Dest: e.DstKey, Port: Port{e.Port, e.Proto}, Reason: reason})
	}

	// observed remembers each edge's own destination and port so that a rule
	// dropped by a pre-existing ceiling is reported with the exact peer and
	// port that edge carried, not the merged rule's whole port list.
	type edgeObs struct {
		dest string
		port Port
	}
	observed := map[int64]edgeObs{}

	for _, e := range edges {
		if e.Port == 0 || (e.Proto != "TCP" && e.Proto != "UDP" && e.Proto != "SCTP") {
			skip(e, "non-tcp-udp")
			continue
		}
		port := Port{e.Port, e.Proto}
		observed[e.ID] = edgeObs{dest: e.DstKey, port: port}
		switch e.DstKind {
		case model.KindWorkload:
			if e.Peer == nil || len(e.Peer.Selector) == 0 {
				skip(e, "peer-unresolved")
				continue
			}
			add(Rule{
				Kind: RuleWorkload, Value: e.Peer.Key(), Namespace: e.Peer.Namespace,
				Selector: e.Peer.Selector, PeerLabels: e.Peer.PodLabels,
				Ports: []Port{port}, EdgeIDs: []int64{e.ID},
			})
		case model.KindService:
			if strings.Contains(e.DstKey, "/") {
				add(Rule{Kind: RuleService, Value: e.DstKey, Namespace: e.DstNamespace, Ports: []Port{port}, EdgeIDs: []int64{e.ID}})
				continue
			}
			skip(e, "service-ip-unknown")
		case model.KindFQDN:
			if !strings.Contains(e.DstKey, ".") {
				skip(e, "fqdn-invalid")
				continue
			}
			add(Rule{Kind: RuleFQDN, Value: e.DstKey, Ports: []Port{port}, EdgeIDs: []int64{e.ID}})
		case model.KindCIDR:
			pfx, err := netip.ParsePrefix(e.DstKey)
			if err != nil {
				skip(e, "cidr-invalid")
				continue
			}
			if isPrivate(pfx, opts.PrivateCIDRs) {
				add(Rule{Kind: RuleCIDR, Value: pfx.Masked().String(), Ports: []Port{port}, EdgeIDs: []int64{e.ID}, Note: "LAN destination"})
				continue
			}
			// A public destination with no DNS name is exactly the case the
			// design refuses to guess: a human decides CIDR or nothing.
			skip(e, "world-unnamed")
		case model.KindEntity:
			skip(e, "baseline-covers")
		default:
			skip(e, "unknown-kind")
		}
	}

	// Any recorded pre-existing constraint filters the rules and records what
	// it removed: those edges were already being dropped before this tool
	// existed, and re-allowing them would widen the isolation. Only an
	// acknowledgement that names a constraining policy lifts the filter.
	if opts.Constraint != nil && opts.Constraint.Active() && !opts.Constraint.AcknowledgedActive(opts.AckPrePoliced) {
		var kept []Rule
		for _, k := range order {
			r := acc[k]
			targeted := deniedPorts(*r, opts.Constraint)
			if len(targeted) == 0 {
				kept = append(kept, *r)
				continue
			}
			// One row per dropped edge, with that edge's own destination and
			// port: the report's "not emitted" list is what a reviewer reads
			// to decide whether the ceiling is still the right one.
			for _, id := range r.EdgeIDs {
				obs, ok := observed[id]
				if !ok {
					obs = edgeObs{dest: r.Value}
				}
				if !opts.Constraint.Allows(*r, obs.port) {
					c.Skipped = append(c.Skipped, Skipped{EdgeID: id, Dest: obs.dest, Port: obs.port, Reason: "pre-policed-dropped"})
				}
			}
			delete(acc, k)
		}
		c.Rules = kept
	} else {
		for _, k := range order {
			c.Rules = append(c.Rules, *acc[k])
		}
	}

	for i := range c.Rules {
		sortPorts(c.Rules[i].Ports)
	}
	sort.Slice(c.Rules, func(i, j int) bool {
		if c.Rules[i].Kind != c.Rules[j].Kind {
			return ruleOrder(c.Rules[i].Kind) < ruleOrder(c.Rules[j].Kind)
		}
		return c.Rules[i].Value < c.Rules[j].Value
	})
	sort.Slice(c.Skipped, func(i, j int) bool {
		if c.Skipped[i].Reason != c.Skipped[j].Reason {
			return c.Skipped[i].Reason < c.Skipped[j].Reason
		}
		return c.Skipped[i].Dest < c.Skipped[j].Dest
	})
	c.Flags = flags(c)
	return c
}

// Generate applies the pre-policed gate to Build. When a foreign policy
// selects the workload without constraining egress and the acknowledgement
// does not cover it, the result is a rules-less PRE-POLICED placeholder: the
// report, plan and diff all go through this one call, so they agree on when a
// human decision is required.
func Generate(w model.Workload, edges []model.Edge, opts Options) Candidate {
	if opts.Constraint != nil && opts.Constraint.BlocksGeneration(opts.AckPrePoliced) {
		c := Candidate{Workload: w, PrePoliced: opts.Constraint.Refs()}
		c.Skipped = append(c.Skipped, Skipped{Reason: "pre-policed-skip"})
		return c
	}
	return Build(w, edges, opts)
}

// NeedsDNSRule reports whether the candidate has FQDN rules and therefore
// needs the companion L7 DNS rule.
func (c Candidate) NeedsDNSRule() bool {
	for _, r := range c.Rules {
		if r.Kind == RuleFQDN {
			return true
		}
	}
	return false
}

// Empty reports whether nothing would be emitted.
func (c Candidate) Empty() bool { return len(c.Rules) == 0 }

// deniedPorts returns the ports of a rule that the existing ceiling does not
// allow. An empty result means the whole rule is inside the ceiling.
func deniedPorts(r Rule, c *Constraint) []Port {
	var out []Port
	for _, p := range r.Ports {
		if !c.Allows(r, p) {
			out = append(out, p)
		}
	}
	return out
}

// RuleName is the CNP object name for a workload.
func RuleName(w model.Workload) string {
	name := strings.ToLower(w.Name)
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, name)
	name = strings.Trim(name, "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	if name == "" {
		name = "workload"
	}
	// One policy per workload kind+name in a namespace: a Deployment and a
	// CronJob may share a name, and their pod selectors differ.
	if w.Kind != "Deployment" && w.Kind != "StatefulSet" && w.Kind != "DaemonSet" {
		name = name + "-" + strings.ToLower(w.Kind)
	}
	return name + "-egress"
}

func flags(c Candidate) []string {
	var out []string
	hasFQDN, hasCIDR := false, false
	for _, r := range c.Rules {
		switch r.Kind {
		case RuleFQDN:
			hasFQDN = true
		case RuleCIDR:
			hasCIDR = true
		}
	}
	if hasCIDR && !hasFQDN {
		out = append(out, "NO-DNS")
	}
	if len(c.Workload.Selector) == 0 {
		out = append(out, "UNLABELED")
	}
	if len(c.PrePoliced) > 0 {
		out = append(out, "PRE-POLICED")
	}
	return out
}

func isPrivate(p netip.Prefix, extra []netip.Prefix) bool {
	if !p.Addr().IsPrivate() && !p.Addr().IsLoopback() {
		for _, e := range extra {
			if e.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	return true
}

func ruleOrder(kind string) int {
	switch kind {
	case RuleWorkload:
		return 0
	case RuleService:
		return 1
	case RuleCIDR:
		return 2
	case RuleFQDN:
		return 3
	case RuleEntity:
		return 4
	}
	return 9
}

func mergePorts(a, b []Port) []Port {
	out := append([]Port{}, a...)
	for _, p := range b {
		found := false
		for _, q := range out {
			if p == q {
				found = true
				break
			}
		}
		if !found {
			out = append(out, p)
		}
	}
	return out
}

func sortPorts(ps []Port) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Port != ps[j].Port {
			return ps[i].Port < ps[j].Port
		}
		return ps[i].Proto < ps[j].Proto
	})
}
