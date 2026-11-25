package policy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/snbuback/kasil-egress/pkg/model"
)

// Issue is one lint finding.
type Issue struct {
	File     string
	Severity string // error | warning
	Message  string
}

func (i Issue) String() string { return fmt.Sprintf("%s: %s: %s", i.File, i.Severity, i.Message) }

// LintTarget is one live workload paired with the ceiling imposed on it by
// policies this pipeline did not generate. Resolution is by the policy's
// endpointSelector (a generated policy is built from the workload's selector)
// with the deterministic object name from RuleName as a fallback: trimming the
// "-egress" suffix is not enough, because RuleName appends the workload kind
// for Job/CronJob/Pod ("renovate-cronjob-egress").
type LintTarget struct {
	Namespace  string
	Kind       string
	Name       string
	Selector   map[string]string
	Constraint *Constraint
}

// LintOptions configures the checks that need cluster knowledge.
type LintOptions struct {
	PodCIDR         netip.Prefix
	SvcCIDR         netip.Prefix
	AllowWorldBroad bool
	AllowPatterns   bool
	AckPrePoliced   string
	// Targets are the live workloads and their foreign-policy ceilings. A nil
	// slice means "not asked" (offline lint, --live=false); an empty non-nil
	// slice means the cluster was read and has no workloads.
	Targets []LintTarget
}

// constraintFor resolves the ceiling for a parsed policy. matched is false
// when the live inventory was read and no workload matches, which makes the
// never-widen check unevaluated rather than silently passing.
func (o LintOptions) constraintFor(doc cnpDoc) (c *Constraint, matched bool) {
	if o.Targets == nil {
		return nil, false
	}
	want := canonicalSelector(doc.Spec.EndpointSelector.MatchLabels)
	for _, t := range o.Targets {
		if t.Namespace == doc.Metadata.Namespace && canonicalSelector(t.Selector) == want {
			return t.Constraint, true
		}
	}
	for _, t := range o.Targets {
		if t.Namespace != doc.Metadata.Namespace {
			continue
		}
		if RuleName(model.Workload{Namespace: t.Namespace, Kind: t.Kind, Name: t.Name}) == doc.Metadata.Name {
			return t.Constraint, true
		}
	}
	return nil, false
}

// LintFiles lints every *.yaml under dir (recursively).
func LintFiles(dir string, opts LintOptions) ([]Issue, error) {
	var files []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var issues []Issue
	// namespace/selector -> file, to catch two policies selecting one workload.
	seen := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		doc, err := parsePolicy(raw)
		if err != nil {
			issues = append(issues, Issue{File: f, Severity: "error", Message: err.Error()})
			continue
		}
		issues = append(issues, lintDoc(f, doc, opts)...)
		key := doc.Metadata.Namespace + "/" + canonicalSelector(doc.Spec.EndpointSelector.MatchLabels)
		if other, ok := seen[key]; ok {
			issues = append(issues, Issue{File: f, Severity: "error",
				Message: fmt.Sprintf("selects the same endpoints as %s — two policies for one workload combine, which makes the effective allowlist the union of both", other)})
		} else {
			seen[key] = f
		}
	}
	return issues, nil
}

func lintDoc(file string, doc cnpDoc, opts LintOptions) []Issue {
	add := func(sev, format string, args ...any) []Issue {
		return []Issue{{File: file, Severity: sev, Message: fmt.Sprintf(format, args...)}}
	}
	var out []Issue

	if doc.APIVersion != "cilium.io/v2" || doc.Kind != "CiliumNetworkPolicy" {
		return add("error", "expected cilium.io/v2 CiliumNetworkPolicy, got %s %s", doc.APIVersion, doc.Kind)
	}
	if !strings.HasSuffix(doc.Metadata.Name, "-egress") {
		out = append(out, add("error", "name %q must end with -egress (one policy per workload)", doc.Metadata.Name)...)
	}
	if len(doc.Spec.EndpointSelector.MatchLabels) == 0 {
		out = append(out, add("error", "empty endpointSelector would select the whole namespace")...)
	}
	if len(doc.Spec.Egress) == 0 {
		out = append(out, add("error", "no egress rules: with enableDefaultDeny.egress=true this denies everything")...)
	}

	hasDNS := false
	for _, r := range doc.Spec.Egress {
		for _, tp := range r.ToPorts {
			if tp.Rules != nil && len(tp.Rules.DNS) > 0 {
				hasDNS = true
			}
		}
	}
	hasFQDN := false
	for _, r := range doc.Spec.Egress {
		if len(r.ToEndpoints) == 0 && len(r.ToServices) == 0 && len(r.ToCIDR) == 0 && len(r.ToFQDNs) == 0 {
			out = append(out, add("error", "egress rule with no peer selector would allow everything")...)
		}
		if len(r.ToFQDNs) == 0 {
			continue
		}
		hasFQDN = true
		for _, f := range r.ToFQDNs {
			if f.MatchName == "" && f.MatchPattern == "" {
				out = append(out, add("error", "toFQDNs entry with neither matchName nor matchPattern")...)
			}
			if f.MatchPattern != "" && !opts.AllowPatterns {
				out = append(out, add("error", "toFQDNs matchPattern %q needs --allow-patterns (a pattern is wider than the name that was observed)", f.MatchPattern)...)
			}
		}
	}
	if hasFQDN && !hasDNS {
		out = append(out, add("error", "toFQDNs without an L7 DNS rule: Cilium never proxies DNS for this endpoint, so the names are never resolved and the rule never matches")...)
	}

	for _, r := range doc.Spec.Egress {
		for _, cidr := range r.ToCIDR {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				out = append(out, add("error", "toCIDR %q is not a prefix", cidr)...)
				continue
			}
			if opts.PodCIDR.IsValid() && opts.PodCIDR.Contains(pfx.Addr()) {
				out = append(out, add("error", "toCIDR %s selects pod IPs: a restarted pod gets a new address and the rule silently stops matching; select the peer workload instead", cidr)...)
			}
			if !opts.AllowWorldBroad && pfx.Bits() < 8 {
				out = append(out, add("error", "toCIDR %s is broader than /8 — the policy becomes theatre (pass --allow-world-broad to override deliberately)", cidr)...)
			}
		}
		for _, svc := range r.ToServices {
			if svc.K8sService == nil || svc.K8sService.ServiceName == "" {
				out = append(out, add("error", "toServices entry without k8sService")...)
			}
		}
	}

	// Never-widen: the file may only contain peers that the foreign policies
	// selecting this workload permit. An owned policy is never a ceiling, so
	// a committed shadow policy cannot block its own regeneration.
	if opts.AckPrePoliced == "" {
		c, matched := opts.constraintFor(doc)
		switch {
		case matched && c != nil && c.Active():
			for _, r := range doc.Spec.Egress {
				for _, rule := range rulesFromYAML(r, doc.Spec.EndpointSelector.MatchLabels) {
					if !c.AllowsAll(rule) {
						out = append(out, add("error",
							"rule %s:%s is outside what %s already allows — emitting it would widen an existing isolation policy (needs --ack-pre-policed with a reviewed diff)",
							rule.Kind, rule.Value, strings.Join(c.Refs(), ","))...)
					}
				}
			}
		case !matched && opts.Targets != nil:
			out = append(out, add("warning",
				"no live workload matches endpointSelector %q or the name %q — never-widen check not evaluated (stale file?)",
				canonicalSelector(doc.Spec.EndpointSelector.MatchLabels), doc.Metadata.Name)...)
		}
	}
	return out
}

// rulesFromYAML maps a parsed egress rule back onto the generator's Rule type
// so the constraint check has one implementation.
func rulesFromYAML(r egressRule, endpointSelector map[string]string) []Rule {
	var out []Rule
	ports := Rule{}.Ports
	for _, tp := range r.ToPorts {
		for _, p := range tp.Ports {
			var n int
			fmt.Sscanf(p.Port, "%d", &n)
			ports = append(ports, Port{Port: n, Proto: strings.ToUpper(p.Protocol)})
		}
	}
	for _, cidr := range r.ToCIDR {
		out = append(out, Rule{Kind: RuleCIDR, Value: cidr, Ports: ports})
	}
	for _, f := range r.ToFQDNs {
		v := f.MatchName
		if v == "" {
			v = f.MatchPattern
		}
		out = append(out, Rule{Kind: RuleFQDN, Value: v, Ports: ports})
	}
	for _, svc := range r.ToServices {
		if svc.K8sService != nil {
			out = append(out, Rule{Kind: RuleService, Value: svc.K8sService.Namespace + "/" + svc.K8sService.ServiceName, Ports: ports})
		}
	}
	for _, ep := range r.ToEndpoints {
		// A toEndpoints rule cannot be checked against another selector
		// without the peer's actual labels; represent it by its selector and
		// let the constraint decide (selectorCovers handles the k8s: prefix).
		out = append(out, Rule{Kind: RuleWorkload, Value: canonicalSelector(ep.MatchLabels), Selector: ep.MatchLabels, PeerLabels: ep.MatchLabels, Ports: ports})
	}
	return out
}

func parsePolicy(raw []byte) (cnpDoc, error) {
	var doc cnpDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("parse: %w", err)
	}
	if doc.Kind == "" {
		return doc, fmt.Errorf("not a Kubernetes object (no kind)")
	}
	return doc, nil
}

func canonicalSelector(sel map[string]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}
