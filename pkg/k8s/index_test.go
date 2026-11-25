package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	pod := func(ns, name, uid, node string, labels map[string]string, owners []ownerRef, images ...string) map[string]any {
		var containers []map[string]any
		for _, img := range images {
			containers = append(containers, map[string]any{"name": "c", "image": img})
		}
		return map[string]any{
			"metadata": map[string]any{
				"name": name, "namespace": ns, "uid": uid,
				"labels": labels, "ownerReferences": owners,
			},
			"spec": map[string]any{"nodeName": node, "containers": containers},
		}
	}
	rs := map[string]any{
		"metadata": map[string]any{
			"name": "frigate-7d9f8c6b5", "namespace": "frigate",
			"ownerReferences": []ownerRef{{Kind: "Deployment", Name: "frigate", Controller: true}},
		},
		"spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "frigate"}}},
	}
	deploy := map[string]any{
		"metadata": map[string]any{"name": "frigate", "namespace": "frigate", "labels": map[string]string{"app": "frigate"}},
		"spec": map[string]any{
			"replicas": 2,
			"selector": map[string]any{"matchLabels": map[string]string{"app": "frigate"}},
		},
	}
	// Scaled to zero: no pods, but the desired replica count is still known.
	idle := map[string]any{
		"metadata": map[string]any{"name": "idle", "namespace": "default", "labels": map[string]string{"app": "idle"}},
		"spec": map[string]any{
			"replicas": 3,
			"selector": map[string]any{"matchLabels": map[string]string{"app": "idle"}},
		},
	}
	job := map[string]any{
		"metadata": map[string]any{
			"name": "renovate-29384756", "namespace": "renovate",
			"ownerReferences": []ownerRef{{Kind: "CronJob", Name: "renovate", Controller: true}},
		},
		"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "renovate", "job-name": "renovate-29384756"}}}},
	}
	cronjob := map[string]any{
		"metadata": map[string]any{"name": "renovate", "namespace": "renovate"},
		"spec":     map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "renovate"}}}}}},
	}
	sts := map[string]any{
		"metadata": map[string]any{"name": "hermes", "namespace": "hermes"},
		"spec": map[string]any{
			"replicas": 1,
			"selector": map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": "hermes"}},
		},
	}

	lists := map[string][]any{
		"/api/v1/pods": {
			pod("frigate", "frigate-7d9f8c6b5-abcde", "uid-1", "kube2.kasil.cloud",
				map[string]string{"app": "frigate", "pod-template-hash": "7d9f8c6b5"},
				[]ownerRef{{Kind: "ReplicaSet", Name: "frigate-7d9f8c6b5", Controller: true}},
				"ghcr.io/blakeblackshear/frigate:0.18.3"),
			pod("frigate", "frigate-7d9f8c6b5-fghij", "uid-5", "kube3.kasil.cloud",
				map[string]string{"app": "frigate", "pod-template-hash": "7d9f8c6b5"},
				[]ownerRef{{Kind: "ReplicaSet", Name: "frigate-7d9f8c6b5", Controller: true}},
				"ghcr.io/blakeblackshear/frigate:0.18.3"),
			pod("renovate", "renovate-29384756-x7k2p", "uid-2", "kube2.kasil.cloud",
				map[string]string{"app": "renovate", "job-name": "renovate-29384756"},
				[]ownerRef{{Kind: "Job", Name: "renovate-29384756", Controller: true}},
				"ghcr.io/renovatebot/renovate:41.1.0"),
			pod("hermes", "hermes-0", "uid-3", "kube1.kasil.cloud",
				map[string]string{"app.kubernetes.io/name": "hermes"},
				[]ownerRef{{Kind: "StatefulSet", Name: "hermes", Controller: true}},
				"ghcr.io/snbuback/hermes:1.2.3"),
			pod("default", "debug-shell", "uid-4", "kube4.kasil.cloud", map[string]string{"run": "debug"}, nil, "busybox:1.36"),
		},
		"/apis/apps/v1/deployments":  {deploy, idle},
		"/apis/apps/v1/statefulsets": {sts},
		"/apis/apps/v1/daemonsets":   {},
		"/apis/apps/v1/replicasets":  {rs},
		"/apis/batch/v1/jobs":        {job},
		"/apis/batch/v1/cronjobs":    {cronjob},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items, ok := lists[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"continue": ""},
			"items":    items,
		})
	}))
}

func TestIndexResolve(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()

	c, err := New(Config{Server: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	idx := NewIndex(c)
	if err := idx.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	tests := []struct {
		ns, pod string
		kind    string
		name    string
	}{
		{"frigate", "frigate-7d9f8c6b5-abcde", "Deployment", "frigate"},
		{"renovate", "renovate-29384756-x7k2p", "CronJob", "renovate"},
		{"hermes", "hermes-0", "StatefulSet", "hermes"},
		{"default", "debug-shell", "Pod", "debug-shell"},
	}
	for _, tt := range tests {
		w, ok := idx.Resolve(tt.ns, tt.pod)
		if !ok {
			t.Fatalf("resolve %s/%s: not found", tt.ns, tt.pod)
		}
		if w.Kind != tt.kind || w.Name != tt.name {
			t.Errorf("resolve %s/%s = %s/%s, want %s/%s", tt.ns, tt.pod, w.Kind, w.Name, tt.kind, tt.name)
		}
		if len(w.Selector) == 0 {
			t.Errorf("resolve %s/%s produced an empty selector", tt.ns, tt.pod)
		}
		for k := range w.Selector {
			if k == "pod-template-hash" || k == "job-name" {
				t.Errorf("selector for %s/%s still contains volatile label %q", tt.ns, tt.pod, k)
			}
		}
	}

	// A pod UID resolution must agree with the name-based one.
	if w, ok := idx.ResolveUID("uid-1"); !ok || w.Name != "frigate" {
		t.Errorf("ResolveUID(uid-1) = %+v, %v", w, ok)
	}

	// Suspended/scaled-to-zero workloads are still describable.
	if w, ok := idx.Get("renovate", "CronJob", "renovate"); !ok || w.Kind != "CronJob" {
		t.Errorf("Get(CronJob) = %+v, %v", w, ok)
	}

	if got := len(idx.Workloads()); got < 4 {
		t.Errorf("Workloads() = %d, want at least 4", got)
	}

	// The report header gets its replicas/nodes/images from the index.
	m := idx.Meta(Workload{Namespace: "frigate", Kind: "Deployment", Name: "frigate"})
	if m.Replicas != 2 {
		t.Errorf("frigate replicas = %d, want 2", m.Replicas)
	}
	if got, want := strings.Join(m.Nodes, ","), "kube2.kasil.cloud,kube3.kasil.cloud"; got != want {
		t.Errorf("frigate nodes = %q, want %q", got, want)
	}
	if got, want := strings.Join(m.Images, ","), "ghcr.io/blakeblackshear/frigate:0.18.3"; got != want {
		t.Errorf("frigate images = %q, want %q", got, want)
	}

	// A scaled-to-zero workload still reports its spec.replicas.
	if m := idx.Meta(Workload{Namespace: "default", Kind: "Deployment", Name: "idle"}); m.Replicas != 3 {
		t.Errorf("idle replicas = %d, want 3 (spec.replicas fallback)", m.Replicas)
	}

	// A workload known only from the database has no live facts.
	if m := idx.Meta(Workload{Namespace: "gone", Kind: "Deployment", Name: "gone"}); m.Replicas != 0 || len(m.Nodes) != 0 {
		t.Errorf("unknown workload meta = %+v, want zero value", m)
	}
}
