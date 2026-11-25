// Package report renders the audit inventory. It is pure: everything it
// needs arrives in Input, which keeps the output golden-testable without a
// database or a cluster.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/policy"
)

// Input is one report generation run.
type Input struct {
	GeneratedAt time.Time
	Since       time.Time
	Until       time.Time
	// Cluster is the metadata block printed at the top of the summary.
	Cluster Cluster
	// Workloads are the audited workloads, sorted by namespace then key.
	Workloads []Workload
	// Exemptions are documented, not forgotten: workloads deliberately left
	// unpoliced.
	Exemptions []Exemption
	// PolicyInventory is the pre-existing policy objects, as read live.
	PolicyInventory []PolicyRow
	// Coverage summarises how much of the inventory produced an answer.
	Coverage Coverage
}

// Cluster describes the environment the report was produced against.
type Cluster struct {
	Name     string
	PodCIDR  string
	SvcCIDR  string
	Nodes    []string
	Window   string
	Exporter string
}

// PolicyRow is one line of the policy inventory.
type PolicyRow struct {
	Kind       string
	Name       string
	Namespace  string
	Selector   string
	Pods       int
	Constrains bool
	Source     string
}

// Exemption is a workload that is deliberately not policed.
type Exemption struct {
	Subject string
	Reason  string
}

// Workload is one audited workload.
type Workload struct {
	model.Workload
	Replicas  int
	Nodes     []string
	Images    []string
	Candidate policy.Candidate
	Edges     []model.Edge
	Flags     []string
}

// Coverage summarises how much of the inventory produced an answer.
type Coverage struct {
	Workloads      int
	WithRules      int
	WithExemptions int
	WithoutEdges   int
	Percent        float64
}

// ComputeFlags derives the human-facing flags for a workload from its edges.
func ComputeFlags(w model.Workload, edges []model.Edge, prePoliced []string) []string {
	var flags []string
	if len(w.Selector) == 0 {
		flags = append(flags, "UNLABELED")
	}
	if len(prePoliced) > 0 {
		flags = append(flags, "PRE-POLICED")
	}
	if len(edges) == 0 {
		return append(flags, "NO-EDGES")
	}

	var (
		totalConns   int64
		days         = map[string]struct{}{}
		externalIPs  = map[string]struct{}{}
		externalNets = map[string]struct{}{}
		noDNS        bool
		hours        = map[int]struct{}{}
	)
	for _, e := range edges {
		totalConns += e.ConnsTotal
		days[e.LastSeen.UTC().Format("2006-01-02")] = struct{}{}
		for h, bit := range e.ActiveHours {
			if bit == '1' {
				hours[h] = struct{}{}
			}
		}
		if e.DstKind != model.KindCIDR {
			continue
		}
		pfx, err := netip.ParsePrefix(e.DstKey)
		if err != nil {
			continue
		}
		if pfx.Addr().IsPrivate() || pfx.Addr().IsLoopback() {
			continue
		}
		externalIPs[pfx.Addr().String()] = struct{}{}
		externalNets[pfx.Masked().String()] = struct{}{}
		if len(e.DstNames) == 0 {
			noDNS = true
		}
	}
	if noDNS {
		flags = append(flags, "NO-DNS")
	}
	if len(externalNets) >= 3 || len(externalIPs) >= 10 {
		flags = append(flags, "BROAD")
	}
	if len(hours) == 1 {
		flags = append(flags, "CRON-ONLY")
	}
	span := 1.0
	if !daysSpan(edges) {
		span = float64(len(days))
	} else {
		span = daysBetween(edges)
	}
	if span <= 0 {
		span = 1
	}
	if float64(totalConns)/span < 1 {
		flags = append(flags, "LOW-VOLUME")
	}
	return flags
}

func daysSpan(edges []model.Edge) bool {
	if len(edges) == 0 {
		return false
	}
	var min, max time.Time
	for _, e := range edges {
		if min.IsZero() || e.FirstSeen.Before(min) {
			min = e.FirstSeen
		}
		if max.IsZero() || e.LastSeen.After(max) {
			max = e.LastSeen
		}
	}
	return max.Sub(min) > 24*time.Hour
}

func daysBetween(edges []model.Edge) float64 {
	var min, max time.Time
	for _, e := range edges {
		if min.IsZero() || e.FirstSeen.Before(min) {
			min = e.FirstSeen
		}
		if max.IsZero() || e.LastSeen.After(max) {
			max = e.LastSeen
		}
	}
	d := max.Sub(min).Hours() / 24
	if d < 1 {
		return 1
	}
	return d
}

// Markdown writes the per-namespace report (one file) for a set of workloads.
func Markdown(w io.Writer, in Input, namespace string) error {
	var ws []Workload
	for _, w := range in.Workloads {
		if w.Namespace == namespace {
			ws = append(ws, w)
		}
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].Key() < ws[j].Key() })

	fmt.Fprintf(w, "## namespace: %s\n\n", namespace)
	if len(ws) == 0 {
		fmt.Fprintf(w, "_no observed egress in this namespace_\n")
		return nil
	}
	for _, x := range ws {
		fmt.Fprintf(w, "### %s/%s", x.Kind, x.Name)
		var meta []string
		if x.Replicas > 0 {
			meta = append(meta, fmt.Sprintf("replicas %d", x.Replicas))
		}
		if len(x.Nodes) > 0 {
			meta = append(meta, "node "+strings.Join(x.Nodes, ","))
		}
		if len(x.Images) > 0 {
			meta = append(meta, "image "+strings.Join(x.Images, ","))
		}
		if len(meta) > 0 {
			fmt.Fprintf(w, "  (%s)", strings.Join(meta, ", "))
		}
		fmt.Fprintf(w, "\n")
		if from, to := observed(x.Edges); !from.IsZero() {
			fmt.Fprintf(w, "observed %s → %s\n", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
		}
		if len(x.Flags) > 0 {
			fmt.Fprintf(w, "\n**flags:** %s\n", strings.Join(x.Flags, ", "))
		}
		fmt.Fprintf(w, "\n| destination | kind | port/proto | conns | conns/day | first seen | last seen | hours | notes |\n")
		fmt.Fprintf(w, "|---|---|---|---|---|---|---|---|---|\n")
		for _, e := range x.Edges {
			fmt.Fprintf(w, "| %s | %s | %d/%s | %d | %.1f | %s | %s | %s | %s |\n",
				dest(e), e.DstKind, e.Port, e.Proto, e.ConnsTotal, float64(e.ConnsTotal)/daysBetween(x.Edges),
				e.FirstSeen.UTC().Format("01-02 15:04"), e.LastSeen.UTC().Format("01-02 15:04"),
				hours(e.ActiveHours), note(e))
		}
		fanOut := fmt.Sprintf("\nfan-out: %d peers", len(x.Edges))
		if len(x.Flags) > 0 {
			fanOut += " · flags: " + strings.Join(x.Flags, ", ")
		}
		fmt.Fprintf(w, "%s\n", fanOut)
		if len(x.Candidate.Rules) > 0 {
			fmt.Fprintf(w, "\nsuggested policy (review, not applied):\n\n```yaml\n")
			// Shadow, like `egressctl plan`'s default: the report is a Phase 1
			// artifact and must never suggest an enforcing policy.
			body, err := policy.Render(x.Candidate, policy.Options{Shadow: true})
			if err == nil {
				fmt.Fprintf(w, "%s", body)
			} else {
				fmt.Fprintf(w, "# %v\n", err)
			}
			fmt.Fprintf(w, "```\n")
		}
		if len(x.Candidate.Skipped) > 0 {
			fmt.Fprintf(w, "\nnot emitted:\n\n")
			for _, s := range x.Candidate.Skipped {
				fmt.Fprintf(w, "- `%s` %d/%s — %s\n", s.Dest, s.Port.Port, s.Port.Proto, s.Reason)
			}
		}
		fmt.Fprintf(w, "\n")
	}
	return nil
}

// Summary writes the global summary.
func Summary(w io.Writer, in Input) error {
	fmt.Fprintf(w, "# Egress audit — summary\n\n")
	fmt.Fprintf(w, "- generated: %s\n", in.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "- window: %s\n", in.Cluster.Window)
	if in.Cluster.Name != "" {
		fmt.Fprintf(w, "- cluster: %s (pod CIDR %s, service CIDR %s)\n", in.Cluster.Name, in.Cluster.PodCIDR, in.Cluster.SvcCIDR)
	}
	fmt.Fprintf(w, "- workloads audited: %d\n", in.Coverage.Workloads)
	fmt.Fprintf(w, "- workloads with generated rules: %d\n", in.Coverage.WithRules)
	fmt.Fprintf(w, "- workloads without observed egress: %d\n", in.Coverage.WithoutEdges)
	fmt.Fprintf(w, "- exemptions: %d\n", in.Coverage.WithExemptions)
	fmt.Fprintf(w, "- coverage: %.1f%%\n\n", in.Coverage.Percent)

	fmt.Fprintf(w, "## namespace × destination-kind\n\n")
	kinds := []string{model.KindWorkload, model.KindService, model.KindCIDR, model.KindFQDN, model.KindEntity}
	fmt.Fprintf(w, "| namespace | workloads | edges | %s |\n", strings.Join(kinds, " | "))
	fmt.Fprintf(w, "|---|---|---|%s\n", strings.Repeat("---|", len(kinds)))
	byNS := map[string][]Workload{}
	for _, x := range in.Workloads {
		byNS[x.Namespace] = append(byNS[x.Namespace], x)
	}
	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	for _, ns := range nss {
		counts := map[string]int{}
		edges := 0
		for _, x := range byNS[ns] {
			edges += len(x.Edges)
			for _, e := range x.Edges {
				counts[e.DstKind]++
			}
		}
		cells := make([]string, 0, len(kinds))
		for _, k := range kinds {
			cells = append(cells, strconv.Itoa(counts[k]))
		}
		fmt.Fprintf(w, "| %s | %d | %d | %s |\n", ns, len(byNS[ns]), edges, strings.Join(cells, " | "))
	}

	fmt.Fprintf(w, "\n## exemptions (documented, not forgotten)\n\n")
	fmt.Fprintf(w, "| subject | reason |\n|---|---|\n")
	for _, e := range in.Exemptions {
		fmt.Fprintf(w, "| %s | %s |\n", e.Subject, e.Reason)
	}

	if len(in.PolicyInventory) > 0 {
		fmt.Fprintf(w, "\n## policy inventory (pre-existing objects)\n\n")
		fmt.Fprintf(w, "| kind | name | namespace | selector | pods | constrains egress |\n|---|---|---|---|---|---|\n")
		for _, p := range in.PolicyInventory {
			fmt.Fprintf(w, "| %s | %s | %s | `%s` | %d | %v |\n", p.Kind, p.Name, p.Namespace, p.Selector, p.Pods, p.Constrains)
		}
	}

	if flagged := allFlags(in); len(flagged) > 0 {
		fmt.Fprintf(w, "\n## flags to review\n\n")
		for _, line := range flagged {
			fmt.Fprintf(w, "- %s\n", line)
		}
	}
	return nil
}

// CSV writes one row per edge.
func CSV(w io.Writer, in Input) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{
		"namespace", "kind", "name", "destination", "dst_kind", "port", "proto",
		"conns", "conns_per_day", "first_seen", "last_seen", "hours", "flags",
	}); err != nil {
		return err
	}
	for _, x := range in.Workloads {
		for _, e := range x.Edges {
			row := []string{
				x.Namespace, x.Kind, x.Name, dest(e), e.DstKind, strconv.Itoa(e.Port), e.Proto,
				strconv.FormatInt(e.ConnsTotal, 10), fmt.Sprintf("%.1f", float64(e.ConnsTotal)/daysBetween(x.Edges)),
				e.FirstSeen.UTC().Format(time.RFC3339), e.LastSeen.UTC().Format(time.RFC3339),
				hours(e.ActiveHours), strings.Join(x.Flags, " "),
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	return cw.Error()
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, in Input) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(in)
}

func dest(e model.Edge) string {
	if len(e.DstNames) > 0 {
		return e.DstKey + " (" + strings.Join(e.DstNames, ", ") + ")"
	}
	return e.DstKey
}

func note(e model.Edge) string {
	var n []string
	if e.DstKind == model.KindWorkload && e.Peer == nil {
		n = append(n, "NO-OWNER")
	}
	if len(e.DstNames) == 0 && e.DstKind == model.KindCIDR {
		n = append(n, "NO-DNS")
	}
	return strings.Join(n, " ")
}

// hours renders a PostgreSQL bit(24) mask as a list of hour-of-day values.
// The mask is MSB-first (PostgreSQL bit string order), so index i is hour
// 23-i.
func hours(mask string) string {
	var out []string
	for i, bit := range mask {
		if bit == '1' {
			out = append(out, fmt.Sprintf("%02d", len(mask)-1-i))
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

func observed(edges []model.Edge) (time.Time, time.Time) {
	var from, to time.Time
	for _, e := range edges {
		if from.IsZero() || e.FirstSeen.Before(from) {
			from = e.FirstSeen
		}
		if to.IsZero() || e.LastSeen.After(to) {
			to = e.LastSeen
		}
	}
	return from, to
}

func allFlags(in Input) []string {
	var out []string
	for _, w := range in.Workloads {
		if len(w.Flags) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("`%s/%s/%s` — %s", w.Namespace, w.Kind, w.Name, strings.Join(w.Flags, ", ")))
	}
	return out
}
