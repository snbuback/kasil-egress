package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/pg"
	"github.com/snbuback/kasil-egress/pkg/policy"
	"github.com/snbuback/kasil-egress/pkg/report"
)

// defaultExemptions are the documented Phase 2 exemptions (§10.4). They are
// reported every time so the gap stays visible rather than becoming tribal
// knowledge.
var defaultExemptions = []report.Exemption{
	{Subject: "kube-system", Reason: "CNI/DNS/control plane; a mistake takes the cluster down and there is nothing to gain"},
	{Subject: "piraeus-datastore", Reason: "LINSTOR/DRBD control plane; replication is kernel-level and unaffected by pod policy"},
	{Subject: "victoria/vmagent", Reason: "cluster-wide scrape fan-out by design; excluded from capture, so there is no inventory to generate from"},
	{Subject: "homeassistant-hass (hostNetwork)", Reason: "hostNetwork pod: not a Cilium endpoint, cannot be selected by a pod policy — accepted v1 gap"},
	{Subject: "music-assistant-server (hostNetwork)", Reason: "hostNetwork pod: not a Cilium endpoint, cannot be selected by a pod policy — accepted v1 gap"},
}

// auditInput groups everything the report and plan commands need.
type auditInput struct {
	edges      []model.Edge
	candidates []policy.Candidate
	workloads  []report.Workload
	policySet  *k8s.PolicySet
	policyRows []report.PolicyRow
	index      *k8s.Index
	exemptions []report.Exemption
	window     string
}

// collect reads the database and the cluster and joins them into per-workload
// candidates.
func collect(ctx context.Context, db *pg.DB, client *k8s.Client, e env, namespace string, opts policy.Options) (*auditInput, error) {
	idx := k8s.NewIndex(client)
	if err := idx.Refresh(ctx); err != nil {
		return nil, err
	}
	ps, err := k8s.FetchPolicies(ctx, client)
	if err != nil {
		return nil, err
	}
	edges, err := loadEdges(ctx, db, namespace)
	if err != nil {
		return nil, err
	}
	byIP, _, err := loadDNS(ctx, db)
	if err != nil {
		return nil, err
	}
	attachDNS(edges, byIP)
	resolvePeers(edges, idx)

	byWorkload := map[string][]model.Edge{}
	for _, ed := range edges {
		byWorkload[ed.Workload.Key()] = append(byWorkload[ed.Workload.Key()], ed)
	}

	wls := idx.Workloads()
	// Include workloads that only exist in the database (deleted pods).
	known := map[string]struct{}{}
	for _, w := range wls {
		known[w.Key()] = struct{}{}
	}
	for _, ed := range edges {
		if _, ok := known[ed.Workload.Key()]; !ok {
			known[ed.Workload.Key()] = struct{}{}
			wls = append(wls, k8s.Workload{
				Namespace: ed.Workload.Namespace, Kind: ed.Workload.Kind, Name: ed.Workload.Name,
			})
		}
	}

	in := &auditInput{policySet: ps, index: idx, exemptions: defaultExemptions}
	in.policyRows = policyInventory(ps, idx)
	var from, to time.Time
	for _, w := range wls {
		if namespace != "" && w.Namespace != namespace {
			continue
		}
		wedges := byWorkload[w.Key()]
		selecting, gateways := ps.Selecting(w)
		constraint := policy.NewConstraint(selecting)
		o := opts
		o.Constraint = constraint

		wm := w.Model()
		c := policy.Generate(wm, wedges, o)
		var gw []string
		for _, g := range gateways {
			gw = append(gw, g.Ref()+"→"+g.EgressIP)
		}
		c.EgressGateway = gw
		flags := report.ComputeFlags(wm, wedges, c.PrePoliced)
		wmeta := idx.Meta(w)
		in.candidates = append(in.candidates, c)
		in.workloads = append(in.workloads, report.Workload{
			Workload:  wm,
			Replicas:  wmeta.Replicas,
			Nodes:     wmeta.Nodes,
			Images:    wmeta.Images,
			Candidate: c,
			Edges:     wedges,
			Flags:     flags,
		})
		for _, ed := range wedges {
			if from.IsZero() || ed.FirstSeen.Before(from) {
				from = ed.FirstSeen
			}
			if to.IsZero() || ed.LastSeen.After(to) {
				to = ed.LastSeen
			}
		}
	}
	in.edges = edges
	if !from.IsZero() {
		in.window = fmt.Sprintf("%s → %s", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	} else {
		in.window = "no traffic observed"
	}
	return in, nil
}

// policyInventory renders the live policy objects for the summary. Pipeline
// objects are included but marked as such: they are the tool's own baseline
// and exemptions, not foreign constraints.
func policyInventory(ps *k8s.PolicySet, idx *k8s.Index) []report.PolicyRow {
	rows := make([]report.PolicyRow, 0, len(ps.Policies))
	for _, p := range ps.Policies {
		if p.Gateway {
			var sels []string
			for _, s := range p.Selectors {
				sels = append(sels, k8s.SelectorString(s.MatchLabels))
			}
			rows = append(rows, report.PolicyRow{
				Kind: p.Kind, Name: p.Name, Namespace: p.Namespace,
				Selector: "[" + strings.Join(sels, " | ") + "] → " + p.EgressIP,
				Source:   "egress-gateway",
			})
			continue
		}
		pods := 0
		for _, w := range idx.Workloads() {
			if p.Kind == "CiliumNetworkPolicy" && p.Namespace != w.Namespace {
				continue
			}
			if p.Selector.Matches(w.PodLabels) {
				pods++
			}
		}
		source := "live"
		if p.Owned {
			source = "pipeline"
		}
		rows = append(rows, report.PolicyRow{
			Kind: p.Kind, Name: p.Name, Namespace: p.Namespace,
			Selector: k8s.SelectorString(p.Selector.MatchLabels),
			Pods:     pods, Constrains: p.ConstrainsEgress(), Source: source,
		})
	}
	return rows
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	load := registerEnv(fs)
	all := fs.Bool("all", false, "report every namespace")
	ns := fs.String("ns", "", "limit to one namespace")
	out := fs.String("out", "reports", "output directory")
	format := fs.String("format", "md", "md | csv | json")
	coverage := fs.Bool("coverage", false, "print the coverage line only")
	showPol := fs.Bool("show-policy-inventory", false, "print the live policy inventory")
	shadow := fs.Bool("shadow", true, "suggest policies in shadow mode")
	ack := fs.String("ack-pre-policed", "", "acknowledge a foreign policy that constrains nothing (same meaning as plan)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := noPositional(pos); err != nil {
		return err
	}
	if !*all && *ns == "" && !*coverage && !*showPol {
		return fmt.Errorf("choose --all, --ns, --coverage or --show-policy-inventory")
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, client, err := e.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	opts := policy.Options{
		Shadow:        *shadow,
		PodCIDR:       mustPrefix(e.podCIDR),
		SvcCIDR:       mustPrefix(e.svcCIDR),
		PrivateCIDRs:  policy.DefaultPrivateCIDRs(),
		AckPrePoliced: *ack,
		GeneratedFrom: "egressctl report " + time.Now().UTC().Format(time.RFC3339),
	}
	nsFilter := *ns
	if *all {
		nsFilter = ""
	}
	in, err := collect(ctx, db, client, e, nsFilter, opts)
	if err != nil {
		return err
	}

	if *showPol {
		fmt.Printf("policy inventory (%d objects)\n\n", len(in.policySet.Policies))
		for _, p := range in.policySet.Policies {
			pods := 0
			for _, w := range in.index.Workloads() {
				if p.Gateway {
					continue
				}
				if p.Kind == "CiliumNetworkPolicy" && p.Namespace != w.Namespace {
					continue
				}
				if p.Selector.Matches(w.PodLabels) {
					pods++
				}
			}
			gate := ""
			for _, s := range p.Selectors {
				if s.Matches(map[string]string{}) {
					gate += ""
				}
			}
			fmt.Printf("%-34s %-40s ns=%-20s pods=%d constrains=%v %s\n",
				p.Kind, p.Name, p.Namespace, pods, p.ConstrainsEgress(), gate)
		}
	}

	// Coverage: every workload must have rules or an exemption.
	cov := report.Coverage{Workloads: len(in.workloads)}
	for _, w := range in.workloads {
		switch {
		case len(w.Candidate.Rules) > 0:
			cov.WithRules++
		case len(w.Edges) == 0:
			cov.WithoutEdges++
		}
	}
	cov.WithExemptions = len(in.exemptions)
	if cov.Workloads > 0 {
		cov.Percent = 100 * float64(cov.WithRules+cov.WithoutEdges) / float64(cov.Workloads)
	}
	if *coverage {
		fmt.Printf("workloads=%d with_rules=%d no_edges=%d coverage=%.1f%%\n",
			cov.Workloads, cov.WithRules, cov.WithoutEdges, cov.Percent)
		if *out == "" {
			return nil
		}
	}

	rin := report.Input{
		GeneratedAt: time.Now(),
		Cluster: report.Cluster{
			Name:     "kasil",
			PodCIDR:  e.podCIDR,
			SvcCIDR:  e.svcCIDR,
			Window:   in.window,
			Exporter: "hubble-dynamic",
		},
		Workloads:       in.workloads,
		Exemptions:      in.exemptions,
		Coverage:        cov,
		PolicyInventory: in.policyRows,
	}

	if *format == "json" || *format == "csv" {
		if *out != "" {
			if err := os.MkdirAll(*out, 0o755); err != nil {
				return err
			}
		}
		f, err := os.Create(filepath.Join(*out, "egress-report."+*format))
		if err != nil {
			return err
		}
		defer f.Close()
		if *format == "json" {
			return report.JSON(f, rin)
		}
		return report.CSV(f, rin)
	}

	// Markdown: one file per namespace plus a summary.
	namespaces := map[string]struct{}{}
	for _, w := range in.workloads {
		namespaces[w.Namespace] = struct{}{}
	}
	list := make([]string, 0, len(namespaces))
	for ns := range namespaces {
		list = append(list, ns)
	}
	sort.Strings(list)
	for _, ns := range list {
		var sb strings.Builder
		if err := report.Markdown(&sb, rin, ns); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(*out, "namespace-"+ns+".md"), []byte(sb.String())); err != nil {
			return err
		}
	}
	var sb strings.Builder
	if err := report.Summary(&sb, rin); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*out, "summary.md"), []byte(sb.String())); err != nil {
		return err
	}
	fmt.Printf("wrote %d namespace reports and summary to %s\n", len(list), *out)
	return nil
}
