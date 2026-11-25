package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/model"
	"github.com/snbuback/kasil-egress/pkg/pg"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	load := registerEnv(fs)
	ns := fs.String("ns", "", "namespace")
	since := fs.Duration("since", time.Hour, "window")
	_ = fs.Parse(args)
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()

	blocked, err := loadBlocked(ctx, db, *ns, time.Now().Add(-*since))
	if err != nil {
		return err
	}

	type bucket struct {
		title string
		rows  []model.Blocked
	}
	buckets := []*bucket{
		{title: "uncovered (new need — plan a rule)"},
		{title: "covered-but-denied (rule or precedence bug)"},
		{title: "reviewed (expected / ignored)"},
	}
	for _, b := range blocked {
		state, covered, err := classifyDenial(ctx, db, b)
		if err != nil {
			return err
		}
		switch {
		case state != "":
			buckets[2].rows = append(buckets[2].rows, b)
		case covered:
			buckets[1].rows = append(buckets[1].rows, b)
		default:
			buckets[0].rows = append(buckets[0].rows, b)
		}
	}

	total := 0
	for _, b := range buckets {
		total += len(b.rows)
		fmt.Printf("\n## %s — %d\n\n", b.title, len(b.rows))
		if len(b.rows) == 0 {
			fmt.Println("_none_")
			continue
		}
		fmt.Printf("| last seen | workload | destination | port | verdict | count |\n|---|---|---|---|---|---|\n")
		for i, r := range b.rows {
			if i >= 30 {
				fmt.Printf("| … | %d more | | | | |\n", len(b.rows)-i)
				break
			}
			wl := r.SrcNamespace + "/" + r.SrcPod
			if r.Workload != nil {
				wl = r.Workload.Namespace + "/" + r.Workload.Kind + "/" + r.Workload.Name
			}
			dest := r.DstIP
			if len(r.DstNames) > 0 {
				dest += " (" + strings.Join(r.DstNames, ",") + ")"
			}
			fmt.Printf("| %s | %s | %s | %d/%s | %s | %d |\n",
				r.TS.UTC().Format("01-02 15:04"), wl, dest, r.Port, r.Proto, r.Verdict, r.Conns)
		}
	}
	fmt.Printf("\n%d denial record(s) in the last %s\n", total, *since)
	return nil
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	load := registerEnv(fs)
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: egressctl explain BLOCKED-ID")
	}
	var id int64
	if _, err := fmt.Sscanf(fs.Arg(0), "%d", &id); err != nil {
		return fmt.Errorf("invalid id %q", fs.Arg(0))
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()

	var b model.Blocked
	var namesJSON []byte
	var wlNS, wlKind, wlName *string
	err = db.Pool().QueryRow(ctx, `
SELECT b.id, b.ts, b.src_namespace, b.src_pod, COALESCE(host(b.src_ip),''), COALESCE(host(b.dst_ip),''),
       COALESCE(b.dst_namespace,''), COALESCE(b.dst_pod,''), COALESCE(b.dst_names::text,'[]'),
       COALESCE(b.port,0), COALESCE(b.proto,''), b.direction, b.verdict, COALESCE(b.drop_reason,''),
       COALESCE(b.node,''), b.conns, w.namespace, w.kind, w.name
FROM egress.blocked_flow b
LEFT JOIN egress.workload w ON w.id = b.src_workload_id
WHERE b.id = $1
ORDER BY b.ts DESC LIMIT 1`, id).Scan(
		&b.ID, &b.TS, &b.SrcNamespace, &b.SrcPod, &b.SrcIP, &b.DstIP, &b.DstNamespace, &b.DstPod,
		&namesJSON, &b.Port, &b.Proto, &b.Direction, &b.Verdict, &b.DropReason, &b.Node, &b.Conns,
		&wlNS, &wlKind, &wlName)
	if err != nil {
		return fmt.Errorf("blocked_flow id %d: %w", id, err)
	}
	b.DstNames = decodeStringArray(namesJSON)

	fmt.Printf("denial #%d\n", b.ID)
	fmt.Printf("  when        %s\n", b.TS.UTC().Format(time.RFC3339))
	fmt.Printf("  source      %s/%s (%s) on %s\n", b.SrcNamespace, b.SrcPod, b.SrcIP, b.Node)
	if wlNS != nil {
		fmt.Printf("  workload    %s/%s/%s\n", *wlNS, *wlKind, *wlName)
	}
	fmt.Printf("  destination %s", b.DstIP)
	if len(b.DstNames) > 0 {
		fmt.Printf(" (%s)", strings.Join(b.DstNames, ", "))
	}
	fmt.Printf("\n  port        %d/%s\n", b.Port, b.Proto)
	fmt.Printf("  verdict     %s (%s)\n", b.Verdict, b.DropReason)

	if b.Workload != nil {
		rows, err := db.Pool().Query(ctx, `
SELECT r.rule_kind, r.rule_value FROM egress.policy_rule r
JOIN egress.policy p ON p.id = r.policy_id
WHERE p.namespace = $1
ORDER BY r.rule_kind, r.rule_value`, b.Workload.Namespace)
		if err == nil {
			var rules []string
			for rows.Next() {
				var k, v string
				if err := rows.Scan(&k, &v); err == nil {
					rules = append(rules, k+":"+v)
				}
			}
			rows.Close()
			if len(rules) > 0 {
				fmt.Printf("\n  shipped rules for namespace %s (%d):\n", b.Workload.Namespace, len(rules))
				for i, r := range rules {
					if i >= 20 {
						fmt.Printf("    … %d more\n", len(rules)-i)
						break
					}
					fmt.Printf("    - %s\n", r)
				}
			}
		}
	}
	return nil
}

func cmdReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ExitOnError)
	load := registerEnv(fs)
	state := fs.String("state", "", "expected | unexpected | allowed_forever | ignored")
	reason := fs.String("reason", "", "why")
	by := fs.String("by", defaultUser(), "who decided")
	expires := fs.Duration("expires", 0, "suppress for this long (ignored only)")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: egressctl review EDGE-ID --state S --reason R")
	}
	switch *state {
	case model.ReviewExpected, model.ReviewUnexpected, model.ReviewAllowedForever, model.ReviewIgnored:
	default:
		return fmt.Errorf("--state must be one of expected|unexpected|allowed_forever|ignored")
	}
	if *reason == "" {
		return fmt.Errorf("--reason is required: the decision has to be auditable")
	}
	var id int64
	if _, err := fmt.Sscanf(fs.Arg(0), "%d", &id); err != nil {
		return fmt.Errorf("invalid edge id %q", fs.Arg(0))
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()
	var exp *time.Time
	if *expires > 0 {
		t := time.Now().Add(*expires)
		exp = &t
	}
	if err := db.Review(ctx, id, *state, *reason, *by, exp); err != nil {
		return err
	}
	fmt.Printf("edge %d reviewed as %s by %s\n", id, *state, *by)
	return nil
}

func cmdDigest(args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	load := registerEnv(fs)
	out := fs.String("out", "", "write the markdown here instead of stdout")
	webhook := fs.String("webhook-url", "", `POST {"content": md} to this URL (Discord-compatible)`)
	since := fs.Duration("since", 7*24*time.Hour, "review window")
	_ = fs.Parse(args)
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()

	md, err := buildDigest(ctx, db, time.Now().Add(-*since))
	if err != nil {
		return err
	}
	if *out != "" {
		if err := writeFile(*out, []byte(md)); err != nil {
			return err
		}
	}
	if *webhook != "" {
		if err := postWebhook(*webhook, md); err != nil {
			return err
		}
	}
	if *out == "" && *webhook == "" {
		fmt.Print(md)
	}
	return nil
}

func buildDigest(ctx context.Context, db *pg.DB, since time.Time) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Egress weekly digest — %s\n\n", time.Now().Format("2006-01-02"))

	rows, err := db.Pool().Query(ctx, `
SELECT b.src_namespace, COALESCE(w.name,''), COALESCE(host(b.dst_ip),''),
       COALESCE(b.dst_names::text,'[]'), COALESCE(b.port,0), COALESCE(b.proto,''), count(*), max(b.ts)
FROM egress.blocked_flow b
LEFT JOIN egress.workload w ON w.id = b.src_workload_id
WHERE b.ts >= $1
GROUP BY 1,2,3,4,5,6
ORDER BY 7 DESC`, since)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	type line struct {
		ns, name, ip, names, proto string
		port                       int
		count                      int64
		last                       time.Time
	}
	var denies []line
	for rows.Next() {
		var l line
		var namesJSON []byte
		if err := rows.Scan(&l.ns, &l.name, &l.ip, &namesJSON, &l.port, &l.proto, &l.count, &l.last); err != nil {
			return "", err
		}
		l.names = strings.Join(decodeStringArray(namesJSON), ",")
		denies = append(denies, l)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	fmt.Fprintf(&sb, "## denied traffic (%d groups)\n\n", len(denies))
	if len(denies) == 0 {
		fmt.Fprintf(&sb, "_none — an enforced namespace with no denials is the healthy state_\n")
	} else {
		fmt.Fprintf(&sb, "| last | workload | destination | port | count |\n|---|---|---|---|---|\n")
		for i, l := range denies {
			if i >= 40 {
				fmt.Fprintf(&sb, "| … | %d more | | | |\n", len(denies)-i)
				break
			}
			wl := l.name
			if wl == "" {
				wl = l.ns
			}
			dest := l.ip
			if l.names != "" {
				dest += " (" + l.names + ")"
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %d/%s | %d |\n", l.last.UTC().Format("01-02 15:04"), wl, dest, l.port, l.proto, l.count)
		}
	}

	var uncovered int
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM egress.v_uncovered`).Scan(&uncovered); err == nil {
		fmt.Fprintf(&sb, "\n## unreviewed edges: %d\n", uncovered)
	}

	staleRows, err := db.Pool().Query(ctx, `
SELECT namespace, policy_name, count(*) FROM egress.v_stale_rule GROUP BY 1,2 ORDER BY 3 DESC`)
	if err == nil {
		var stale []string
		for staleRows.Next() {
			var ns, name string
			var n int
			if err := staleRows.Scan(&ns, &name, &n); err == nil {
				stale = append(stale, fmt.Sprintf("- %s/%s: %d rule(s) unused for 30 d", ns, name, n))
			}
		}
		staleRows.Close()
		fmt.Fprintf(&sb, "\n## stale rules (30 d unused): %d\n", len(stale))
		for _, s := range stale {
			fmt.Fprintf(&sb, "%s\n", s)
		}
	}

	covRows, err := db.Pool().Query(ctx, `
SELECT w.namespace, count(DISTINCT w.id), count(DISTINCT e.id)
FROM egress.workload w LEFT JOIN egress.edge e ON e.src_workload_id = w.id
GROUP BY 1 ORDER BY 1`)
	if err == nil {
		fmt.Fprintf(&sb, "\n## workload coverage\n\n| namespace | workloads | edges |\n|---|---|---|\n")
		for covRows.Next() {
			var ns string
			var wl, ed int
			if err := covRows.Scan(&ns, &wl, &ed); err == nil {
				fmt.Fprintf(&sb, "| %s | %d | %d |\n", ns, wl, ed)
			}
		}
		covRows.Close()
	}
	fmt.Fprintf(&sb, "\n---\n_Review workflow: docs/runbooks/egress-deny.md_\n")
	return sb.String(), nil
}

// classifyDenial decides whether a denial was meant to be allowed (covered by
// a shipped rule) and whether a human already reviewed the underlying edge.
func classifyDenial(ctx context.Context, db *pg.DB, b model.Blocked) (state string, covered bool, err error) {
	ipKey := b.DstIP + "/32"
	nameKey := ""
	if len(b.DstNames) > 0 {
		nameKey = b.DstNames[0]
	}
	err = db.Pool().QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM egress.policy_rule r
  JOIN egress.edge e ON e.id = r.edge_id
  WHERE e.src_workload_id = $1
    AND (e.dst_key = $2 OR ($3 <> '' AND e.dst_key = $3))
)`, b.SrcWorkloadID, ipKey, nameKey).Scan(&covered)
	if err != nil {
		return "", false, err
	}
	err = db.Pool().QueryRow(ctx, `
SELECT rv.state FROM egress.review rv
JOIN egress.edge e ON e.id = rv.edge_id
WHERE e.src_workload_id = $1
  AND (e.dst_key = $2 OR ($3 <> '' AND e.dst_key = $3))
  AND ($4 = 0 OR e.port = $4)
  AND (rv.expires_at IS NULL OR rv.expires_at > now())
ORDER BY rv.decided_at DESC LIMIT 1`, b.SrcWorkloadID, ipKey, nameKey, b.Port).Scan(&state)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", covered, nil
		}
		return "", covered, err
	}
	return state, covered, nil
}

func postWebhook(url, md string) error {
	if len(md) > 1900 {
		md = md[:1900] + "\n…(truncated — full digest in the egress database)"
	}
	body, err := json.Marshal(map[string]string{"content": md})
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func defaultUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "operator"
}
