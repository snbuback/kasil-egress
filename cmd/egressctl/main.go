// Command egressctl is the reporting and policy-generation CLI for the egress
// allowlisting pipeline: report, plan, diff, lint, verify, review, explain,
// digest, schema and maintain.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/k8s"
	"github.com/snbuback/kasil-egress/pkg/pg"
)

// version is stamped at build time with -ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "egressctl: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "report":
		return cmdReport(rest)
	case "plan":
		return cmdPlan(rest)
	case "diff":
		return cmdDiff(rest)
	case "lint":
		return cmdLint(rest)
	case "verify":
		return cmdVerify(rest)
	case "explain":
		return cmdExplain(rest)
	case "review":
		return cmdReview(rest)
	case "digest":
		return cmdDigest(rest)
	case "schema":
		return cmdSchema(rest)
	case "maintain":
		return cmdMaintain(rest)
	case "audit-guard":
		return cmdAuditGuard(rest)
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `egressctl — egress inventory and policy generation

  report   [--all|--ns N] [--out DIR] [--format md|csv|json] [--coverage] [--show-policy-inventory] [--ack-pre-policed KIND/NAME]
  plan     [--ns N] [--out DIR] [--ack-pre-policed KIND/NAME] [--enforce]
  diff     [--ns N]
  lint     DIR [--allow-world-broad] [--allow-patterns] [--ack-pre-policed KIND/NAME]
  verify   [--ns N] [--since 1h]
  explain  BLOCKED-ID
  review   EDGE-ID --state expected|unexpected|allowed_forever|ignored --reason TEXT
  digest   [--webhook-url URL] [--out FILE]
  schema   apply
  maintain [--dry-run]
  version

Global flags: --dsn (or EGRESS_DSN), --kube-server (default in-cluster)
`)
}

// env holds the shared configuration for one invocation.
type env struct {
	dsn        string
	kubeServer string
	podCIDR    string
	svcCIDR    string
	timezone   string
}

// registerEnv adds the global flags to a flag set and returns a loader.
func registerEnv(fs *flag.FlagSet) func() (env, error) {
	e := env{}
	fs.StringVar(&e.dsn, "dsn", os.Getenv("EGRESS_DSN"), "PostgreSQL DSN (default $EGRESS_DSN)")
	fs.StringVar(&e.kubeServer, "kube-server", "", "Kubernetes API base URL (default: in-cluster)")
	fs.StringVar(&e.podCIDR, "pod-cidr", "172.16.0.0/16", "cluster pod CIDR")
	fs.StringVar(&e.svcCIDR, "svc-cidr", "172.30.0.0/16", "cluster service CIDR")
	fs.StringVar(&e.timezone, "timezone", defaultTZ(), "timezone for hour-of-day buckets")
	return func() (env, error) {
		if e.dsn == "" {
			if p := os.Getenv("EGRESS_DSN_FILE"); p != "" {
				b, err := os.ReadFile(p)
				if err != nil {
					return e, fmt.Errorf("read EGRESS_DSN_FILE: %w", err)
				}
				e.dsn = strings.TrimSpace(string(b))
			}
		}
		if e.dsn == "" {
			return e, errors.New("no DSN: set --dsn or EGRESS_DSN")
		}
		return e, nil
	}
}

func defaultTZ() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return tz
	}
	return "UTC"
}

func (e env) location() *time.Location {
	loc, err := time.LoadLocation(e.timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// open connects to Postgres and the API server.
func (e env) open(ctx context.Context) (*pg.DB, *k8s.Client, error) {
	db, err := pg.Open(ctx, e.dsn)
	if err != nil {
		return nil, nil, err
	}
	var client *k8s.Client
	if e.kubeServer != "" {
		client, err = k8s.New(k8s.Config{
			Server:    e.kubeServer,
			TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
			CAFile:    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		})
		if err != nil {
			db.Close()
			return nil, nil, err
		}
	} else {
		client, err = k8s.InCluster()
		if err != nil {
			db.Close()
			return nil, nil, err
		}
	}
	return db, client, nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func mustFlag(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
