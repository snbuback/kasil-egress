package policy

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/snbuback/kasil-egress/pkg/k8s"
)

// Render turns a candidate into a CiliumNetworkPolicy document.
//
// The output is deterministic: rules are ordered workload -> service -> cidr ->
// fqdn -> dns, peers inside a rule are sorted, and ports are sorted, so a diff
// between two runs only shows real changes.
func Render(c Candidate, opts Options) ([]byte, error) {
	if c.Empty() {
		return nil, fmt.Errorf("%s: no rules generated", c.Workload.Key())
	}

	doc := cnpDoc{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: meta{
			Name:      RuleName(c.Workload),
			Namespace: c.Workload.Namespace,
			Annotations: map[string]string{
				// Marks the object as this pipeline's own output so future
				// runs never treat it as a foreign constraint (see
				// k8s.OwnedKey).
				k8s.OwnedKey: k8s.OwnedValue,
			},
		},
		Spec: spec{
			Description:       fmt.Sprintf("egress allowlist for %s (%s/%s)", c.Workload.Name, c.Workload.Kind, c.Workload.Name),
			EndpointSelector:  selector{MatchLabels: c.Workload.Selector},
			EnableDefaultDeny: enableDefaultDeny{Egress: !opts.Shadow},
		},
	}
	if opts.GeneratedFrom != "" {
		doc.Metadata.Annotations["egress.kasil.io/generated-from"] = opts.GeneratedFrom
	}
	if len(c.PrePoliced) > 0 {
		doc.Metadata.Annotations["egress.kasil.io/pre-policed"] = strings.Join(c.PrePoliced, ",")
	}
	if opts.AckPrePoliced != "" {
		doc.Metadata.Annotations["egress.kasil.io/ack-pre-policed"] = opts.AckPrePoliced
	}

	var workloads, services, cidrs, fqdns []Rule
	for _, r := range c.Rules {
		switch r.Kind {
		case RuleWorkload:
			workloads = append(workloads, r)
		case RuleService:
			services = append(services, r)
		case RuleCIDR:
			cidrs = append(cidrs, r)
		case RuleFQDN:
			fqdns = append(fqdns, r)
		}
	}

	for _, r := range workloads {
		doc.Spec.Egress = append(doc.Spec.Egress, egressRule{
			ToEndpoints: []endpointSelector{{MatchLabels: withNamespace(r.Namespace, r.Selector)}},
			ToPorts:     toPorts(r.Ports, nil),
		})
	}
	for _, r := range services {
		ns, name, ok := strings.Cut(r.Value, "/")
		if !ok {
			continue
		}
		doc.Spec.Egress = append(doc.Spec.Egress, egressRule{
			ToServices: []serviceRef{{K8sService: &k8sService{Namespace: ns, ServiceName: name}}},
			ToPorts:    toPorts(r.Ports, nil),
		})
	}
	if len(cidrs) > 0 {
		// One rule per CIDR: a shared rule would allow every port on every
		// address, which is exactly the broadening reviewers are told to
		// reject.
		for _, r := range cidrs {
			doc.Spec.Egress = append(doc.Spec.Egress, egressRule{
				ToCIDR:  []string{r.Value},
				ToPorts: toPorts(r.Ports, nil),
			})
		}
	}
	for _, r := range fqdns {
		doc.Spec.Egress = append(doc.Spec.Egress, egressRule{
			ToFQDNs: []fqdnRef{{MatchName: r.Value}},
			ToPorts: toPorts(r.Ports, nil),
		})
	}
	if c.NeedsDNSRule() {
		doc.Spec.Egress = append(doc.Spec.Egress, dnsRule())
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dnsRule is the companion rule that makes Cilium proxy DNS for the endpoint.
// Without an L7 DNS rule toFQDNs never resolves, so the generator emits it
// whenever it emits a name.
func dnsRule() egressRule {
	return egressRule{
		ToEndpoints: []endpointSelector{{
			MatchLabels: map[string]string{
				"io.kubernetes.pod.namespace": "kube-system",
				"k8s-app":                     "kube-dns",
			},
		}},
		ToPorts: []toPort{{
			Ports: []port{{Port: "53", Protocol: "UDP"}, {Port: "53", Protocol: "TCP"}},
			Rules: &l7Rules{DNS: []dnsMatch{{MatchPattern: "*"}}},
		}},
	}
}

func withNamespace(ns string, sel map[string]string) map[string]string {
	out := map[string]string{"io.kubernetes.pod.namespace": ns}
	for k, v := range sel {
		if strings.HasPrefix(k, "k8s:") {
			k = strings.TrimPrefix(k, "k8s:")
		}
		out[k] = v
	}
	return out
}

func toPorts(ports []Port, rules *l7Rules) []toPort {
	if len(ports) == 0 {
		return nil
	}
	sorted := append([]Port{}, ports...)
	sortPorts(sorted)
	out := make([]port, 0, len(sorted))
	for _, p := range sorted {
		out = append(out, port{Port: itoa(p.Port), Protocol: strings.ToUpper(p.Proto)})
	}
	return []toPort{{Ports: out, Rules: rules}}
}

// RuleValueForTest exposes the rendered selector of a rule (used by tests).
func RuleValueForTest(r Rule) string { return r.Kind + ":" + r.Value }

// ---- YAML shapes -------------------------------------------------------

type cnpDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   meta   `yaml:"metadata"`
	Spec       spec   `yaml:"spec"`
}

type meta struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type spec struct {
	Description       string            `yaml:"description,omitempty"`
	EndpointSelector  selector          `yaml:"endpointSelector"`
	EnableDefaultDeny enableDefaultDeny `yaml:"enableDefaultDeny"`
	Egress            []egressRule      `yaml:"egress"`
}

type selector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

type enableDefaultDeny struct {
	Egress  bool `yaml:"egress"`
	Ingress bool `yaml:"ingress"`
}

type egressRule struct {
	ToEndpoints []endpointSelector `yaml:"toEndpoints,omitempty"`
	ToServices  []serviceRef       `yaml:"toServices,omitempty"`
	ToCIDR      []string           `yaml:"toCIDR,omitempty"`
	ToFQDNs     []fqdnRef          `yaml:"toFQDNs,omitempty"`
	ToPorts     []toPort           `yaml:"toPorts,omitempty"`
}

type endpointSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

type serviceRef struct {
	K8sService *k8sService `yaml:"k8sService,omitempty"`
}

type k8sService struct {
	Namespace   string `yaml:"namespace"`
	ServiceName string `yaml:"serviceName"`
}

type fqdnRef struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

type toPort struct {
	Ports []port   `yaml:"ports,omitempty"`
	Rules *l7Rules `yaml:"rules,omitempty"`
}

type port struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol,omitempty"`
}

type l7Rules struct {
	DNS []dnsMatch `yaml:"dns,omitempty"`
}

type dnsMatch struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}
