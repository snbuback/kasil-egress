package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakePolicyAPI(t *testing.T) *httptest.Server {
	t.Helper()
	cnp := map[string]any{
		"metadata": map[string]any{
			"name": "frigate-egress", "namespace": "frigate",
			"annotations": map[string]string{OwnedKey: OwnedValue},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]string{"app": "frigate"}},
			"egress":           []any{map[string]any{"toCIDR": []string{"192.168.31.10/32"}}},
		},
	}
	ccnp := map[string]any{
		"metadata": map[string]any{
			"name":   "baseline-dns-apiserver",
			"labels": map[string]string{OwnedKey: OwnedValue},
		},
		"spec": map[string]any{
			"endpointSelector":  map[string]any{},
			"enableDefaultDeny": map[string]any{"egress": false, "ingress": false},
			"egress":            []any{map[string]any{"toEntities": []string{"kube-apiserver"}}},
		},
	}
	foreign := map[string]any{
		"metadata": map[string]any{"name": "via-vpn-isolation"},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]string{"kasil.cloud/via-vpn": "true"}},
			"egress":           []any{map[string]any{"toEntities": []string{"world"}}},
		},
	}
	lists := map[string][]any{
		"/apis/cilium.io/v2/ciliumnetworkpolicies":            {cnp},
		"/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies": {foreign, ccnp},
		"/apis/cilium.io/v2/ciliumegressgatewaypolicies":      {},
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

func TestFetchPoliciesOwnership(t *testing.T) {
	srv := fakePolicyAPI(t)
	defer srv.Close()

	c, err := New(Config{Server: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ps, err := FetchPolicies(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Policies) != 3 {
		t.Fatalf("policies = %d, want 3", len(ps.Policies))
	}
	want := map[string]bool{
		"CiliumNetworkPolicy/frigate-egress":                    true,  // annotation
		"CiliumClusterwideNetworkPolicy/baseline-dns-apiserver": true,  // label
		"CiliumClusterwideNetworkPolicy/via-vpn-isolation":      false, // foreign
	}
	for _, p := range ps.Policies {
		if got := p.Owned; got != want[p.Ref()] {
			t.Errorf("%s Owned = %v, want %v", p.Ref(), got, want[p.Ref()])
		}
	}
}
