package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snbuback/kasil-egress/pkg/k8s"
)

func writePolicy(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func lintOpts() LintOptions {
	return LintOptions{
		PodCIDR: netip.MustParsePrefix("172.16.0.0/16"),
		SvcCIDR: netip.MustParsePrefix("172.30.0.0/16"),
	}
}

func issuesFor(t *testing.T, body string, opts LintOptions) []Issue {
	t.Helper()
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", body)
	issues, err := LintFiles(dir, opts)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	return issues
}

func hasIssue(issues []Issue, substr string) bool {
	for _, i := range issues {
		if strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

const goodPolicy = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: frigate-egress
  namespace: frigate
spec:
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: frigate
  enableDefaultDeny:
    egress: true
  egress:
    - toCIDR:
        - 192.168.31.10/32
      toPorts:
        - ports:
            - port: "554"
              protocol: TCP
`

func TestLintGoodPolicy(t *testing.T) {
	issues := issuesFor(t, goodPolicy, lintOpts())
	for _, i := range issues {
		if i.Severity == "error" {
			t.Errorf("unexpected error: %s", i)
		}
	}
}

func TestLintCatches(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
		opts func() LintOptions
	}{
		{
			name: "fqdn without dns rule",
			body: strings.Replace(goodPolicy, `    - toCIDR:
        - 192.168.31.10/32
      toPorts:
        - ports:
            - port: "554"
              protocol: TCP`, `    - toFQDNs:
        - matchName: api.telegram.org`, 1),
			want: "without an L7 DNS rule",
		},
		{
			name: "pod ip rule",
			body: strings.Replace(goodPolicy, "192.168.31.10/32", "172.16.4.9/32", 1),
			want: "selects pod IPs",
		},
		{
			name: "world broad",
			body: strings.Replace(goodPolicy, "192.168.31.10/32", "0.0.0.0/0", 1),
			want: "broader than /8",
		},
		{
			name: "pattern needs ack",
			body: strings.Replace(goodPolicy, `    - toCIDR:
        - 192.168.31.10/32
      toPorts:
        - ports:
            - port: "554"
              protocol: TCP`, `    - toFQDNs:
        - matchPattern: "*.telegram.org"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"`, 1),
			want: "needs --allow-patterns",
		},
		{
			name: "wrong name suffix",
			body: strings.Replace(goodPolicy, "frigate-egress", "frigate", 1),
			want: "must end with -egress",
		},
		{
			name: "empty selector",
			body: strings.Replace(goodPolicy, `    matchLabels:
      app.kubernetes.io/name: frigate`, `    matchLabels: {}`, 1),
			want: "empty endpointSelector",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := issuesFor(t, tt.body, lintOpts())
			if !hasIssue(issues, tt.want) {
				t.Errorf("expected an issue containing %q, got %v", tt.want, issues)
			}
		})
	}
}

func TestLintNeverWiden(t *testing.T) {
	// A file that adds an in-cluster peer to a workload already isolated by
	// via-vpn-isolation must fail unless acknowledged.
	body := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: untrusted-egress
  namespace: apps
spec:
  endpointSelector:
    matchLabels:
      app: untrusted
  enableDefaultDeny:
    egress: true
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: nanomq
            app.kubernetes.io/name: nanomq
      toPorts:
        - ports:
            - port: "1883"
              protocol: TCP
`
	opts := lintOpts()
	opts.Targets = []LintTarget{{
		Namespace:  "apps",
		Kind:       "Deployment",
		Name:       "untrusted",
		Selector:   map[string]string{"app": "untrusted"},
		Constraint: NewConstraint([]k8s.Policy{viaVPNIsolation()}),
	}}

	issues := issuesFor(t, body, opts)
	if !hasIssue(issues, "outside what CiliumClusterwideNetworkPolicy/via-vpn-isolation already allows") {
		t.Fatalf("never-widen rule did not fire: %v", issues)
	}

	opts.AckPrePoliced = "CiliumClusterwideNetworkPolicy/via-vpn-isolation"
	issues = issuesFor(t, body, opts)
	if hasIssue(issues, "outside what") {
		t.Errorf("never-widen rule still fired with an acknowledgement: %v", issues)
	}
}

// A generated policy for a CronJob is named "<name>-cronjob-egress" (RuleName
// appends the kind for Job/CronJob/Pod), so resolving the constraint by
// trimming "-egress" would look up the wrong workload and silently skip the
// never-widen check. Resolution must work through the endpointSelector.
func TestLintNeverWidenCronJob(t *testing.T) {
	body := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: renovate-cronjob-egress
  namespace: renovate
spec:
  endpointSelector:
    matchLabels:
      app: renovate
  enableDefaultDeny:
    egress: true
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: nanomq
            app.kubernetes.io/name: nanomq
      toPorts:
        - ports:
            - port: "1883"
              protocol: TCP
`
	opts := lintOpts()
	opts.Targets = []LintTarget{{
		Namespace:  "renovate",
		Kind:       "CronJob",
		Name:       "renovate",
		Selector:   map[string]string{"app": "renovate"},
		Constraint: NewConstraint([]k8s.Policy{viaVPNIsolation()}),
	}}

	issues := issuesFor(t, body, opts)
	if !hasIssue(issues, "outside what CiliumClusterwideNetworkPolicy/via-vpn-isolation already allows") {
		t.Fatalf("never-widen rule did not fire for a CronJob policy: %v", issues)
	}

	opts.AckPrePoliced = "CiliumClusterwideNetworkPolicy/via-vpn-isolation"
	if issues = issuesFor(t, body, opts); hasIssue(issues, "outside what") {
		t.Errorf("never-widen rule still fired with an acknowledgement: %v", issues)
	}
}

// A policy file whose selector matches no live workload must not pass silently
// in live mode: the never-widen check cannot be evaluated.
func TestLintUnmatchedSelectorWarns(t *testing.T) {
	opts := lintOpts()
	opts.Targets = []LintTarget{}
	issues := issuesFor(t, goodPolicy, opts)
	if !hasIssue(issues, "never-widen check not evaluated") {
		t.Fatalf("expected a warning for an unmatched selector, got %v", issues)
	}
	for _, i := range issues {
		if i.Severity == "error" {
			t.Errorf("unexpected error: %s", i)
		}
	}
}

// The pipeline's own inactive policy is not a constraint: linting a
// regenerated file must not fail because a shadow copy is applied.
func TestLintIgnoresOwnedPolicy(t *testing.T) {
	owned := viaVPNIsolation()
	owned.Owned = true
	no := false
	owned.EnableDefaultDenyEgress = &no
	opts := lintOpts()
	opts.Targets = []LintTarget{{
		Namespace:  "apps",
		Kind:       "Deployment",
		Name:       "untrusted",
		Selector:   map[string]string{"app": "untrusted"},
		Constraint: NewConstraint([]k8s.Policy{owned}),
	}}
	issues := issuesFor(t, strings.Replace(goodPolicy, "frigate", "untrusted", -1), opts)
	for _, i := range issues {
		if i.Severity == "error" && strings.Contains(i.Message, "outside what") {
			t.Errorf("owned policy was treated as a constraint: %v", issues)
		}
	}
}

func TestLintDuplicateSelectors(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "a.yaml", goodPolicy)
	writePolicy(t, dir, "b.yaml", strings.Replace(goodPolicy, "frigate-egress", "frigate-other-egress", 1))
	issues, err := LintFiles(dir, lintOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssue(issues, "selects the same endpoints") {
		t.Errorf("duplicate selector not detected: %v", issues)
	}
}

func TestLintIgnoresNonYAML(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "README.md", "not yaml")
	issues, err := LintFiles(dir, lintOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("unexpected issues: %v", issues)
	}
}
