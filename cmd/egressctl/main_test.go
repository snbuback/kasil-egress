package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateEnv removes every ambient input a command might read, so a test never
// depends on the machine it runs on.
func isolateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("EGRESS_DSN", "")
	t.Setenv("EGRESS_DSN_FILE", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
}

const policyFile = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: demo-egress
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: demo
  enableDefaultDeny:
    egress: true
  egress:
    - toCIDR:
        - 192.168.31.10/32
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
`

func writePolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "demo-egress.yaml"), []byte(policyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Flags written after the positional argument must be parsed. Go's flag
// package stops at the first non-flag argument, which silently dropped
// --live=false and made `review ID --state ...` fail validation.
func TestParseFlagsAfterPositional(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"flags first", []string{"--live=false", "--state", "expected", "demo"}},
		{"flags last", []string{"demo", "--live=false", "--state", "expected"}},
		{"flags mixed", []string{"--state", "expected", "demo", "--live=false"}},
		{"termintor", []string{"--live=false", "--state", "expected", "--", "demo"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			live := fs.Bool("live", true, "")
			state := fs.String("state", "", "")
			pos, err := parse(fs, tc.args)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if *live {
				t.Errorf("--live=false was not applied (args %v)", tc.args)
			}
			if *state != "expected" {
				t.Errorf("--state = %q, want expected (args %v)", *state, tc.args)
			}
			if len(pos) != 1 || pos[0] != "demo" {
				t.Errorf("positionals = %v, want [demo]", pos)
			}
		})
	}
}

// A value-taking flag keeps the next argument even when it starts with a dash,
// and unknown flags are still rejected by the flag set.
func TestParseValueTakingFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	ack := fs.String("ack", "", "")
	pos, err := parse(fs, []string{"--ack", "-weird", "id"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *ack != "-weird" {
		t.Errorf("--ack = %q, want -weird", *ack)
	}
	if len(pos) != 1 || pos[0] != "id" {
		t.Errorf("positionals = %v, want [id]", pos)
	}

	fs = flag.NewFlagSet("test", flag.ContinueOnError)
	if _, err := parse(fs, []string{"--nope", "x"}); err == nil {
		t.Error("unknown flag was accepted")
	}
}

// The shipped CI job and the rollout runbook both run `lint DIR --live=false`
// with no database configured. It must not ask for a DSN, and the flag after
// the positional must actually take effect (live mode would fail here because
// there is no API server).
func TestLintOfflineNeedsNoDSN(t *testing.T) {
	isolateEnv(t)
	dir := writePolicyDir(t)
	if err := cmdLint([]string{dir, "--live=false"}); err != nil {
		t.Fatalf("offline lint with no DSN and the flag after the positional failed: %v", err)
	}
}

// Live lint reads only the API server: no DSN either.
func TestLintLiveNeedsNoDSN(t *testing.T) {
	isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[],"metadata":{}}`)
	}))
	defer srv.Close()

	dir := writePolicyDir(t)
	if err := cmdLint([]string{dir, "--live", "--kube-server", srv.URL}); err != nil {
		t.Fatalf("live lint against a fake API server failed: %v", err)
	}
}

// The documented `review ID --state S --reason R` order must get past flag
// validation. Without a DSN it can only fail at the connection, never at
// --state.
func TestReviewFlagsAfterPositional(t *testing.T) {
	isolateEnv(t)
	err := cmdReview([]string{"42", "--state", "expected", "--reason", "checked"})
	if err == nil {
		t.Fatal("expected an error: there is no database")
	}
	if !strings.Contains(err.Error(), "DSN") {
		t.Fatalf("flags after the positional were not parsed: %v", err)
	}

	err = cmdReview([]string{"42", "--state", "bogus", "--reason", "x"})
	if err == nil || !strings.Contains(err.Error(), "--state must be one of") {
		t.Fatalf("invalid --state was not rejected: %v", err)
	}
}

// A stray positional on a command that takes none is a typo, not a no-op.
func TestUnexpectedPositional(t *testing.T) {
	isolateEnv(t)
	if err := cmdDiff([]string{"extra"}); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("stray argument was accepted: %v", err)
	}
}
