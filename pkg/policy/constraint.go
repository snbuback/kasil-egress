package policy

import (
	"net/netip"
	"path"
	"strings"

	"github.com/snbuback/kasil-egress/pkg/k8s"
)

// Constraint is the upper bound imposed by Cilium policy objects this tool did
// not generate. Cilium policy is additive: a generated CiliumNetworkPolicy is
// unioned with every other policy selecting the endpoint, so for a workload
// that is already constrained the generated policy can only add allowed
// peers. Treating the existing policies as a ceiling is what keeps this tool
// from re-opening exactly the access an isolation policy exists to deny.
//
// Objects this pipeline owns (the chart's baseline and exemption CCNPs, and
// every `<workload>-egress` CNP it generated) are not part of the ceiling:
// they are the tool's own output and are replaced wholesale on the next
// plan. Excluding them is what lets `report` produce an allowlist and `diff`
// stay gap-free after a generated policy has been committed in shadow mode.
type Constraint struct {
	// Active policies switch the endpoint to egress default-deny, so their
	// allowed set is the ceiling.
	policies []k8s.Policy
	// selectingButInactive are foreign policies that select the workload
	// without constraining egress. Their presence means a generated
	// default-deny policy would change the effective policy in a way this
	// tool cannot reason about, so generation is refused until a human
	// acknowledges the policy by name.
	selectingButInactive []k8s.Policy
}

// NewConstraint builds the ceiling from the policies that select a workload.
// Pipeline-owned objects are skipped: see the type comment.
func NewConstraint(selecting []k8s.Policy) *Constraint {
	c := &Constraint{}
	for _, p := range selecting {
		if p.Gateway || p.Owned {
			continue
		}
		if p.ConstrainsEgress() {
			c.policies = append(c.policies, p)
		} else {
			c.selectingButInactive = append(c.selectingButInactive, p)
		}
	}
	return c
}

// Active reports whether any selecting policy actually constrains egress.
func (c *Constraint) Active() bool { return c != nil && len(c.policies) > 0 }

// SkipGeneration reports whether a human must decide: a foreign policy
// selects the workload but does not constrain egress, so combining it with a
// generated default-deny policy has effects that are not mechanically
// checkable.
func (c *Constraint) SkipGeneration() bool {
	return c != nil && len(c.policies) == 0 && len(c.selectingButInactive) > 0
}

// Acknowledged reports whether ack names every selecting-but-inactive policy
// that is blocking generation. The flag is a reviewed decision, so an
// acknowledgement that names only some of the policies still blocks: each
// one has to appear in the diff a human approved.
func (c *Constraint) Acknowledged(ack string) bool {
	if c == nil || len(c.selectingButInactive) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(c.selectingButInactive))
	for _, p := range c.selectingButInactive {
		want[p.Ref()] = struct{}{}
	}
	for _, part := range strings.Split(ack, ",") {
		delete(want, strings.TrimSpace(part))
	}
	return len(want) == 0
}

// AcknowledgedActive reports whether ack names at least one policy that
// constrains egress. Only that acknowledgement lifts the rule filter: an ack
// for some other policy must not silently widen an active ceiling.
func (c *Constraint) AcknowledgedActive(ack string) bool {
	if c == nil || ack == "" {
		return false
	}
	named := make(map[string]struct{})
	for _, part := range strings.Split(ack, ",") {
		named[strings.TrimSpace(part)] = struct{}{}
	}
	for _, p := range c.policies {
		if _, ok := named[p.Ref()]; ok {
			return true
		}
	}
	return false
}

// BlocksGeneration reports whether generation must be replaced by a
// PRE-POLICED placeholder: a foreign policy selects the workload but
// constrains nothing, and the acknowledgement does not cover it. This is the
// single gate used by report, plan and diff.
func (c *Constraint) BlocksGeneration(ack string) bool {
	return c.SkipGeneration() && !c.Acknowledged(ack)
}

// Refs returns "Kind/name" for every pre-existing selecting policy.
func (c *Constraint) Refs() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, p := range c.policies {
		out = append(out, p.Ref())
	}
	for _, p := range c.selectingButInactive {
		out = append(out, p.Ref())
	}
	return out
}

// Allows reports whether the union of the remaining (foreign, constraining)
// policies permits a generated rule and port. Cilium policy is additive, so a
// rule inside the union does not widen the endpoint's allowed set — the union
// is the ceiling — while a rule outside it is traffic the existing policy was
// already denying and is never emitted.
func (c *Constraint) Allows(r Rule, p Port) bool {
	if !c.Active() {
		return true
	}
	for _, pol := range c.policies {
		for _, rule := range pol.Egress {
			if !ruleAllowsPeer(rule, r) {
				continue
			}
			if ruleAllowsPort(rule, p) {
				return true
			}
		}
	}
	return false
}

// AllowsAll reports whether every port of a rule is inside the ceiling.
func (c *Constraint) AllowsAll(r Rule) bool {
	for _, p := range r.Ports {
		if !c.Allows(r, p) {
			return false
		}
	}
	return true
}

func ruleAllowsPeer(rule k8s.EgressRule, r Rule) bool {
	for _, ent := range rule.ToEntities {
		switch strings.ToLower(ent) {
		case "world", "all":
			// `world` covers every destination outside the cluster: LAN and
			// internet alike. It does not cover in-cluster peers.
			if r.Kind == RuleFQDN || r.Kind == RuleCIDR {
				return true
			}
		case "cluster":
			if r.Kind == RuleWorkload || r.Kind == RuleService {
				return true
			}
		}
	}
	switch r.Kind {
	case RuleWorkload:
		for _, sel := range rule.ToEndpoints {
			if selectorCovers(sel, r.PeerLabels) {
				return true
			}
		}
	case RuleCIDR:
		pfx, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return false
		}
		for _, cidr := range rule.ToCIDR {
			if allowed, err := netip.ParsePrefix(cidr); err == nil && allowed.Contains(pfx.Addr()) && pfx.Bits() >= allowed.Bits() {
				return true
			}
		}
		for _, cidrSet := range rule.ToCIDRSet {
			if allowed, err := netip.ParsePrefix(cidrSet.Cidr); err == nil && allowed.Contains(pfx.Addr()) && pfx.Bits() >= allowed.Bits() {
				return true
			}
		}
	case RuleFQDN:
		for _, f := range rule.ToFQDNs {
			if f.MatchName != "" && strings.EqualFold(f.MatchName, r.Value) {
				return true
			}
			if f.MatchPattern != "" {
				if ok, err := path.Match(strings.ToLower(f.MatchPattern), strings.ToLower(r.Value)); err == nil && ok {
					return true
				}
			}
		}
	case RuleService:
		for _, svc := range rule.ToServices {
			if svc.K8sService == nil {
				continue
			}
			if r.Value == svc.K8sService.Namespace+"/"+svc.K8sService.ServiceName {
				return true
			}
		}
	}
	return false
}

func ruleAllowsPort(rule k8s.EgressRule, p Port) bool {
	ports := rule.Ports()
	if len(ports) == 0 {
		return true // no toPorts: every port
	}
	for _, allowed := range ports {
		if allowed.Port != "" && allowed.Port != "0" && itoa(p.Port) != allowed.Port {
			continue
		}
		proto := strings.ToUpper(allowed.Protocol)
		if proto == "" || proto == "ANY" {
			return true
		}
		if proto == strings.ToUpper(p.Proto) {
			return true
		}
	}
	return false
}

// selectorCovers reports whether a Cilium endpoint selector matches a set of
// pod labels. Cilium labels carry a `k8s:` source prefix that Kubernetes
// labels do not, so both forms are accepted.
func selectorCovers(sel k8s.Selector, labels map[string]string) bool {
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return true
	}
	norm := make(map[string]string, len(labels)*2)
	for k, v := range labels {
		norm[k] = v
		if !strings.HasPrefix(k, "k8s:") {
			norm["k8s:"+k] = v
		}
	}
	return sel.Matches(norm)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
