package flow

import (
	"net/netip"
	"regexp"
	"strings"
)

// Destination kinds. They map 1:1 to egress.edge.dst_kind.
const (
	KindWorkload = "workload"
	KindService  = "service"
	KindFQDN     = "fqdn"
	KindCIDR     = "cidr"
	KindEntity   = "entity"
)

// Dest is a classified destination, i.e. the identity a policy rule is later
// built from.
type Dest struct {
	Kind      string
	Key       string
	Namespace string
	// NoOwner is set when the destination sits inside the cluster CIDRs but
	// no workload owns it (a node-local address, a service without a known
	// name). Such edges need a hand-written rule; they are never auto-emitted.
	NoOwner bool
}

// ClusterCIDRs carries the pod and service CIDRs of the cluster being
// observed.
type ClusterCIDRs struct {
	Pod netip.Prefix
	Svc netip.Prefix
}

var svcFQDN = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.([a-z0-9]([-a-z0-9]*[a-z0-9])?)\.svc\.(cluster\.local|[a-z0-9.-]+)$`)

// Classify decides how a flow destination is recorded. The order matters: the
// most specific, most stable identity wins.
func Classify(o *Observation, cidrs ClusterCIDRs) Dest {
	dst := o.Dst
	names := normalizeNames(o.DstNames)

	// 1. A known workload (Cilium resolved the owner from the endpoint).
	if dst.Workload != "" && dst.Namespace != "" {
		return Dest{Kind: KindWorkload, Key: join(dst.Namespace, dst.Kind, dst.Workload), Namespace: dst.Namespace}
	}

	// 2. The API server, by name or by the well-known service address.
	for _, n := range names {
		if n == "kubernetes.default.svc.cluster.local" || n == "kubernetes.default" {
			return Dest{Kind: KindEntity, Key: "kube-apiserver"}
		}
	}
	for _, n := range names {
		if m := svcFQDN.FindStringSubmatch(n); m != nil {
			return Dest{Kind: KindService, Key: m[3] + "/" + m[1], Namespace: m[3]}
		}
	}

	// 3. A pod Cilium could not attribute to an owner: still a real pod.
	if dst.PodName != "" && dst.Namespace != "" {
		return Dest{Kind: KindWorkload, Key: join(dst.Namespace, "Pod", dst.PodName), Namespace: dst.Namespace}
	}

	// 4. Service or pod IP without a name.
	if ip, err := netip.ParseAddr(dst.IP); err == nil {
		if cidrs.Svc.IsValid() && cidrs.Svc.Contains(ip) {
			return Dest{Kind: KindService, Key: ip.String(), NoOwner: true}
		}
		if cidrs.Pod.IsValid() && cidrs.Pod.Contains(ip) {
			return Dest{Kind: KindCIDR, Key: ip.String() + "/32", NoOwner: true}
		}
	}

	// 5. A name Cilium learned from DNS.
	for _, n := range names {
		if isClusterLocal(n) {
			continue
		}
		return Dest{Kind: KindFQDN, Key: n}
	}

	// 6. Bare IP (LAN device, or internet destination with no name).
	if dst.IP != "" {
		return Dest{Kind: KindCIDR, Key: dst.IP + "/32"}
	}
	return Dest{Kind: KindCIDR, Key: "unknown"}
}

func isClusterLocal(name string) bool {
	return strings.HasSuffix(name, ".svc.cluster.local") ||
		strings.HasSuffix(name, ".cluster.local") ||
		strings.HasSuffix(name, ".kasil.cloud")
}

func join(parts ...string) string { return strings.Join(parts, "/") }
