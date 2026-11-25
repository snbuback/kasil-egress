package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/pg"
	"github.com/snbuback/kasil-egress/pkg/policy"
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("invalid prefix %q: %v", s, err))
	}
	return p
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	load := registerEnv(fs)
	ns := fs.String("ns", "", "namespace to plan (empty = every namespace)")
	out := fs.String("out", "", "write one file per workload under this directory")
	enforce := fs.Bool("enforce", false, "emit enableDefaultDeny.egress: true (default is shadow)")
	ack := fs.String("ack-pre-policed", "", "acknowledge that the plan widens this pre-existing policy")
	record := fs.Bool("record", false, "record the generated rules in egress.policy/policy_rule")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := noPositional(pos); err != nil {
		return err
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
		Shadow:        !*enforce,
		PodCIDR:       mustPrefix(e.podCIDR),
		SvcCIDR:       mustPrefix(e.svcCIDR),
		PrivateCIDRs:  policy.DefaultPrivateCIDRs(),
		AckPrePoliced: *ack,
	}
	in, err := collect(ctx, db, client, e, *ns, opts)
	if err != nil {
		return err
	}

	var (
		emitted, skipped, exempt int
		problems                 []string
	)
	for _, c := range in.candidates {
		if c.Exemption != nil {
			// Documented exemption (§10.4): no policy is generated, by
			// design. Printed so the reason is in the run log, not tribal
			// knowledge.
			exempt++
			fmt.Fprintf(os.Stderr, "exempt %s: %s\n", short(c.Workload), c.Exemption.Reason)
			continue
		}
		opts := opts
		opts.GeneratedFrom = "egressctl plan"
		if c.Empty() {
			skipped++
			reason := "no rules"
			for _, s := range c.Skipped {
				if s.Reason == "pre-policed-skip" {
					reason = fmt.Sprintf("pre-policed: %s selects it but constrains no egress — needs a human decision (--ack-pre-policed <kind>/<name>)",
						strings.Join(c.PrePoliced, ", "))
				}
			}
			problems = append(problems, fmt.Sprintf("%s: %s", short(c.Workload), reason))
			continue
		}
		if len(c.Workload.Selector) == 0 {
			// Rendering this would emit endpointSelector: {} — a
			// namespace-wide default-deny. Refuse instead of writing a
			// policy whose scope is not what the file name says.
			skipped++
			problems = append(problems, fmt.Sprintf("%s: no stable pod labels, so a workload-scoped endpointSelector cannot be built — add labels or document an exemption", short(c.Workload)))
			continue
		}
		body, err := policy.Render(c, opts)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", short(c.Workload), err))
			continue
		}
		emitted++
		if *out != "" {
			path := filepath.Join(*out, c.Workload.Namespace, policy.RuleName(c.Workload)+".yaml")
			if err := writeFile(path, body); err != nil {
				return err
			}
			fmt.Printf("%s  (%d rules, %d edges not emitted)\n", path, len(c.Rules), len(c.Skipped))
		} else {
			fmt.Printf("--- %s (%d rules)\n%s", short(c.Workload), len(c.Rules), body)
		}
		if *record {
			if err := recordPolicy(ctx, db, c, *enforce); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\nplanned %d policies, skipped %d workloads, exempt %d\n", emitted, skipped, exempt)
	if len(problems) > 0 && *out != "" {
		fmt.Fprintf(os.Stderr, "\nneeds a human decision:\n")
		sort.Strings(problems)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
	}
	return nil
}

// recordPolicy writes the shipped rule set so diff/verify can tell "not
// covered" apart from "covered but denied".
func recordPolicy(ctx context.Context, db *pg.DB, c policy.Candidate, enforce bool) error {
	mode := "shadow"
	if enforce {
		mode = "enforce"
	}
	refs := make([]pg.RuleRef, 0, len(c.Rules))
	for _, r := range c.Rules {
		refs = append(refs, pg.RuleRef{Kind: r.Kind, Value: r.Value, EdgeIDs: r.EdgeIDs})
	}
	return db.RecordPolicy(ctx, c.Workload.Namespace, policy.RuleName(c.Workload), mode, refs)
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	load := registerEnv(fs)
	ns := fs.String("ns", "", "namespace to diff (empty = every namespace)")
	quiet := fs.Bool("quiet", false, "only print gaps")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := noPositional(pos); err != nil {
		return err
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
		Shadow:       true,
		PodCIDR:      mustPrefix(e.podCIDR),
		SvcCIDR:      mustPrefix(e.svcCIDR),
		PrivateCIDRs: policy.DefaultPrivateCIDRs(),
	}
	in, err := collect(ctx, db, client, e, *ns, opts)
	if err != nil {
		return err
	}

	gaps := 0
	for _, c := range in.candidates {
		if c.Exemption != nil {
			// Exempt by design: no policy exists to diff, and no edge is a
			// gap. Printed (unless --quiet) so the why is in the output.
			if !*quiet {
				fmt.Printf("%-55s exempt (%s)\n", short(c.Workload), c.Exemption.Subject)
			}
			continue
		}
		var lines []string
		for _, s := range c.Skipped {
			switch s.Reason {
			case "world-unnamed", "peer-unresolved", "service-ip-unknown", "pre-policed-skip":
				lines = append(lines, fmt.Sprintf("  %-42s %d/%-4s %s", s.Dest, s.Port.Port, s.Port.Proto, s.Reason))
			}
		}
		if len(lines) == 0 {
			if !*quiet {
				fmt.Printf("%-55s %3d rules — no gaps\n", short(c.Workload), len(c.Rules))
			}
			continue
		}
		gaps += len(lines)
		fmt.Printf("%-55s %3d rules\n", short(c.Workload), len(c.Rules))
		sort.Strings(lines)
		for _, l := range lines {
			fmt.Println(l)
		}
	}
	if gaps > 0 {
		fmt.Fprintf(os.Stderr, "\n%d edge(s) would be denied by the generated allowlist — do not flip to enforce yet\n", gaps)
		return fmt.Errorf("%d uncovered edge(s)", gaps)
	}
	fmt.Fprintf(os.Stderr, "\nno uncovered edges: the generated allowlists cover everything observed\n")
	return nil
}

func short(w model.Workload) string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// lintTarget is a generated policy file paired with the workload it belongs to.
type lintTarget struct {
	path string
	ns   string
	wl   string
}

func cmdLint(args []string) error {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	load := registerEnv(fs)
	allowWorld := fs.Bool("allow-world-broad", false, "permit CIDRs broader than /8")
	allowPatterns := fs.Bool("allow-patterns", false, "permit toFQDNs matchPattern rules")
	ack := fs.String("ack-pre-policed", "", "acknowledge widening a pre-existing policy")
	live := fs.Bool("live", true, "resolve pre-existing policies from the cluster")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: egressctl lint DIR [flags]")
	}
	dir := pos[0]
	if err := noPositional(pos[1:]); err != nil {
		return err
	}

	ev, err := load()
	if err != nil {
		return err
	}
	opts := policy.LintOptions{
		PodCIDR:         mustPrefix(ev.podCIDR),
		SvcCIDR:         mustPrefix(ev.svcCIDR),
		AllowWorldBroad: *allowWorld,
		AllowPatterns:   *allowPatterns,
		AckPrePoliced:   *ack,
	}
	if *live {
		// Live lint reads only the API server: no DSN, no database.
		ctx := context.Background()
		client, err := ev.kubeClient()
		if err != nil {
			return err
		}
		idx := k8s.NewIndex(client)
		if err := idx.Refresh(ctx); err != nil {
			return err
		}
		ps, err := k8s.FetchPolicies(ctx, client)
		if err != nil {
			return err
		}
		// Resolve the ceiling per workload, not per policy name: a policy's
		// endpointSelector is what identifies the workload it belongs to, and
		// for Job/CronJob/Pod the object name carries a kind suffix that
		// trimming "-egress" cannot recover.
		opts.Targets = make([]policy.LintTarget, 0, len(idx.Workloads()))
		exemptions := policy.DefaultExemptions()
		for _, w := range idx.Workloads() {
			sel, _ := ps.Selecting(w)
			t := policy.LintTarget{
				Namespace:  w.Namespace,
				Kind:       w.Kind,
				Name:       w.Name,
				Selector:   w.Selector,
				Constraint: policy.NewConstraint(sel),
			}
			if ex, ok := exemptions.Match(w.Model()); ok && ex.Workload != "" {
				t.Exempt = ex.Reason
			}
			opts.Targets = append(opts.Targets, t)
		}
	}

	issues, err := policy.LintFiles(dir, opts)
	if err != nil {
		return err
	}
	errs := 0
	for _, i := range issues {
		fmt.Println(i)
		if i.Severity == "error" {
			errs++
		}
	}
	if errs > 0 {
		return fmt.Errorf("%d lint error(s)", errs)
	}
	fmt.Fprintf(os.Stderr, "lint clean (%d files checked)\n", countFiles(dir))
	return nil
}

func countFiles(dir string) int {
	n := 0
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			n++
		}
		return nil
	})
	return n
}
