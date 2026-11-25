// Package model holds the data types shared by the storage, policy and
// report layers. It deliberately has no dependencies so that every other
// package can import it without creating cycles.
package model

import "time"

// Workload is a top-level owner of pods.
type Workload struct {
	Namespace string
	Kind      string
	Name      string
	// Selector is the label set used to build a policy endpointSelector.
	Selector map[string]string
	// PodLabels are the full labels of a representative pod.
	PodLabels map[string]string
	Labels    map[string]string
}

// Key is "namespace/kind/name".
func (w Workload) Key() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// Edge is one observed (workload, destination, port, proto) tuple.
type Edge struct {
	ID           int64
	Workload     Workload
	DstKind      string
	DstKey       string
	DstNamespace string
	Port         int
	Proto        string
	FirstSeen    time.Time
	LastSeen     time.Time
	ConnsTotal   int64
	DaysSeen     int
	// ActiveHours is the 24-character hour-of-day bit mask.
	ActiveHours string
	// DstNames are DNS names Cilium knew for the destination when the edge
	// was last written (from egress.dns_name, joined by dst ip).
	DstNames []string
	// Peer is the destination workload when the destination is in-cluster.
	Peer *Workload
}

// Blocked is one denial from egress.blocked_flow.
type Blocked struct {
	ID            int64
	TS            time.Time
	Workload      *Workload
	SrcWorkloadID int64
	SrcNamespace  string
	SrcPod        string
	SrcIP         string
	DstIP         string
	DstNamespace  string
	DstPod        string
	DstNames      []string
	Port          int
	Proto         string
	Direction     string
	Verdict       string
	DropReason    string
	Node          string
	Conns         int64
}

// Review states, as accepted by egress.review.
const (
	ReviewExpected       = "expected"
	ReviewUnexpected     = "unexpected"
	ReviewAllowedForever = "allowed_forever"
	ReviewIgnored        = "ignored"
)

// Destination kinds, mirrored from the flow classifier. Duplicated here so
// the model package stays dependency-free.
const (
	KindWorkload = "workload"
	KindService  = "service"
	KindFQDN     = "fqdn"
	KindCIDR     = "cidr"
	KindEntity   = "entity"
)
