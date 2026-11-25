package k8s

import "testing"

func TestSelectorMatches(t *testing.T) {
	tests := []struct {
		name   string
		sel    Selector
		labels map[string]string
		want   bool
	}{
		{
			name:   "empty selects all",
			sel:    Selector{},
			labels: map[string]string{"a": "b"},
			want:   true,
		},
		{
			name:   "matchLabels subset",
			sel:    Selector{MatchLabels: map[string]string{"app": "frigate"}},
			labels: map[string]string{"app": "frigate", "tier": "edge"},
			want:   true,
		},
		{
			name:   "matchLabels mismatch",
			sel:    Selector{MatchLabels: map[string]string{"via-vpn": "true"}},
			labels: map[string]string{"app": "frigate"},
			want:   false,
		},
		{
			name:   "In",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "env", Operator: "In", Values: []string{"prod", "staging"}}}},
			labels: map[string]string{"env": "staging"},
			want:   true,
		},
		{
			name:   "In rejects other value",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "env", Operator: "In", Values: []string{"prod"}}}},
			labels: map[string]string{"env": "dev"},
			want:   false,
		},
		{
			name:   "NotIn",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}},
			labels: map[string]string{"env": "dev"},
			want:   true,
		},
		{
			name:   "Exists",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "app", Operator: "Exists"}}},
			labels: map[string]string{"app": ""},
			want:   true,
		},
		{
			name:   "Exists missing",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "app", Operator: "Exists"}}},
			labels: map[string]string{"other": "x"},
			want:   false,
		},
		{
			name:   "DoesNotExist",
			sel:    Selector{MatchExpressions: []SelectorRequirement{{Key: "app", Operator: "DoesNotExist"}}},
			labels: map[string]string{"other": "x"},
			want:   true,
		},
		{
			name:   "matchLabels and expressions are ANDed",
			sel:    Selector{MatchLabels: map[string]string{"app": "frigate"}, MatchExpressions: []SelectorRequirement{{Key: "env", Operator: "In", Values: []string{"prod"}}}},
			labels: map[string]string{"app": "frigate", "env": "dev"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sel.Matches(tt.labels); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyConstrainsEgress(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	tests := []struct {
		name   string
		policy Policy
		want   bool
	}{
		{"no rules", Policy{}, false},
		{"rules default enable", Policy{Egress: []EgressRule{{ToEntities: []string{"world"}}}}, true},
		{"rules explicitly enabled", Policy{Egress: []EgressRule{{ToEntities: []string{"world"}}}, EnableDefaultDenyEgress: boolPtr(true)}, true},
		{"rules explicitly disabled", Policy{Egress: []EgressRule{{ToEntities: []string{"world"}}}, EnableDefaultDenyEgress: boolPtr(false)}, false},
		{"gateway never constrains", Policy{Gateway: true, Egress: []EgressRule{{ToEntities: []string{"world"}}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.ConstrainsEgress(); got != tt.want {
				t.Errorf("ConstrainsEgress() = %v, want %v", got, tt.want)
			}
		})
	}
}
