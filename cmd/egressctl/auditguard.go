package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/snbuback/kasil-egress/pkg/k8s"
)

// cmdAuditGuard is the safety net for the one switch that disables enforcement
// everywhere. Cilium 1.20.5 exposes no metric for policyAuditMode, so the only
// reliable signal is the effective agent configuration. The job records when
// it first saw the flag on and fails once that is older than --max-duration,
// which pages through the existing failed-Job alert.
func cmdAuditGuard(args []string) error {
	fs := flag.NewFlagSet("audit-guard", flag.ExitOnError)
	load := registerEnv(fs)
	maxDur := fs.Duration("max-duration", 72*time.Hour, "fail once audit mode has been on for longer than this")
	state := fs.String("state-configmap", "", "namespace/name of the state ConfigMap")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := noPositional(pos); err != nil {
		return err
	}
	if *state == "" {
		return fmt.Errorf("--state-configmap namespace/name is required")
	}
	ns, name, ok := strings.Cut(*state, "/")
	if !ok {
		return fmt.Errorf("--state-configmap must be namespace/name")
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	// audit-guard reads one ConfigMap and writes another: it must keep
	// working when Postgres is down, which is exactly when the guard matters.
	client, err := e.kubeClient()
	if err != nil {
		return err
	}

	cm, found, err := getConfigMap(ctx, client, "kube-system", "cilium-config")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("ConfigMap kube-system/cilium-config not found: cannot determine policyAuditMode")
	}
	on := strings.EqualFold(cm["policy-audit-mode"], "true")
	const key = "egress.kasil.io/audit-mode-since"

	stateCM, stateFound, err := getConfigMap(ctx, client, ns, name)
	if err != nil {
		return err
	}
	sinceRaw := ""
	if stateFound {
		// Annotations are not returned by getConfigMap, so read them directly.
		sinceRaw = stateCM["__annotation__"+key]
	}

	if !on {
		if sinceRaw != "" {
			if err := patchConfigMap(ctx, client, ns, name, map[string]string{}, map[string]string{key: ""}); err != nil {
				return err
			}
			fmt.Println("policyAuditMode is off; cleared the audit-mode timestamp")
			return nil
		}
		fmt.Println("policyAuditMode is off")
		return nil
	}

	now := time.Now().UTC()
	if sinceRaw == "" {
		if err := patchConfigMap(ctx, client, ns, name, map[string]string{"reason": "policyAuditMode observed on"}, map[string]string{key: now.Format(time.RFC3339)}); err != nil {
			return err
		}
		fmt.Printf("policyAuditMode is ON; recording first sighting %s (limit %s)\n", now.Format(time.RFC3339), *maxDur)
		return nil
	}
	since, err := time.Parse(time.RFC3339, sinceRaw)
	if err != nil {
		// A corrupt timestamp must not silently disable the guard.
		return fmt.Errorf("state ConfigMap has an unparseable timestamp %q: %w", sinceRaw, err)
	}
	elapsed := now.Sub(since)
	if elapsed > *maxDur {
		return fmt.Errorf("policyAuditMode has been enabled since %s (%s, limit %s): enforcement is globally disabled — set cilium.policyAuditMode=false",
			since.Format(time.RFC3339), elapsed.Round(time.Minute), *maxDur)
	}
	fmt.Printf("policyAuditMode has been on for %s (limit %s)\n", elapsed.Round(time.Minute), *maxDur)
	return nil
}

// getConfigMap returns data plus annotations (prefixed __annotation__), and
// whether the object exists.
func getConfigMap(ctx context.Context, c *k8s.Client, ns, name string) (map[string]string, bool, error) {
	body, err := c.Get(ctx, "/api/v1/namespaces/"+ns+"/configmaps/"+name, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, false, nil
		}
		return nil, false, err
	}
	var cm struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, false, err
	}
	out := map[string]string{}
	for k, v := range cm.Data {
		out[k] = v
	}
	for k, v := range cm.Metadata.Annotations {
		out["__annotation__"+k] = v
	}
	return out, true, nil
}

func patchConfigMap(ctx context.Context, c *k8s.Client, ns, name string, data, annotations map[string]string) error {
	payload := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"namespace": ns, "name": name, "annotations": annotations},
	}
	if len(data) > 0 {
		payload["data"] = data
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	out, status, err := c.Do(ctx, "PATCH", "/api/v1/namespaces/"+ns+"/configmaps/"+name, body, "application/merge-patch+json")
	if err != nil {
		return err
	}
	if status == 404 {
		create := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"namespace": ns, "name": name,
				"annotations": annotations,
				"labels":      map[string]string{"app.kubernetes.io/part-of": "egress"},
			},
		}
		if len(data) > 0 {
			create["data"] = data
		}
		b, err := json.Marshal(create)
		if err != nil {
			return err
		}
		out, status, err = c.Do(ctx, "POST", "/api/v1/namespaces/"+ns+"/configmaps", b, "application/json")
		if err != nil {
			return err
		}
	}
	if status >= 300 {
		return fmt.Errorf("configmap write failed: %d: %s", status, truncateString(string(out), 300))
	}
	return nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
