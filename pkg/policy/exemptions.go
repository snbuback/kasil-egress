package policy

import "github.com/snbuback/kasil-egress/pkg/model"

// Exemption is one documented Phase 2 exemption (design §10.4): a namespace or
// a single workload that is deliberately left unpoliced, with the reason a
// reviewer reads in the report. Exemptions are code, not tribal knowledge:
// report, plan, diff and lint consult this one set, so a workload cannot be
// "exempt" in the document and emitted by the generator.
type Exemption struct {
	// Subject is the reviewer-facing identity, e.g. "kube-system",
	// "victoria/vmagent" or "homeassistant/homeassistant-hass".
	Subject string
	// Namespace is the namespace the exemption applies to.
	Namespace string
	// Workload is empty when the whole namespace is exempt, and the workload
	// name otherwise (any kind: a Deployment and a StatefulSet with the same
	// name are both covered).
	Workload string
	// Reason appears in the report and in plan's output.
	Reason string
}

// Exemptions is the documented exemption set shared by every command.
type Exemptions struct{ list []Exemption }

// documentedExemptions mirrors design §10.4 verbatim. The two hostNetwork
// workloads are listed as workloads, not namespaces: the rest of the
// `homeassistant` namespace (alexa-skill, eufy) is audited and policed
// normally.
var documentedExemptions = []Exemption{
	{
		Subject:   "kube-system",
		Namespace: "kube-system",
		Reason:    "CNI/DNS/control plane; a mistake takes the cluster down and there is nothing to gain",
	},
	{
		Subject:   "piraeus-datastore",
		Namespace: "piraeus-datastore",
		Reason:    "LINSTOR/DRBD control plane; replication is kernel-level and unaffected by pod policy",
	},
	{
		Subject:   "victoria/vmagent",
		Namespace: "victoria",
		Workload:  "vmagent",
		Reason:    "cluster-wide scrape fan-out by design; excluded from audit-agg, so there is no inventory to generate from",
	},
	{
		Subject:   "homeassistant/homeassistant-hass",
		Namespace: "homeassistant",
		Workload:  "homeassistant-hass",
		Reason:    "hostNetwork pod: not a Cilium endpoint, cannot be selected by a pod policy — accepted v1 gap",
	},
	{
		Subject:   "homeassistant/music-assistant-server",
		Namespace: "homeassistant",
		Workload:  "music-assistant-server",
		Reason:    "hostNetwork pod: not a Cilium endpoint, cannot be selected by a pod policy — accepted v1 gap",
	},
}

// DefaultExemptions returns the documented §10.4 set.
func DefaultExemptions() *Exemptions {
	return &Exemptions{list: documentedExemptions}
}

// Match reports whether a workload is exempt, and returns the exemption whose
// reason explains why. A nil set matches nothing, which keeps tests and
// library callers explicit. A hostNetwork workload is exempt even when it is
// not named above: its pods are not Cilium endpoints, so no generated policy
// could ever select them (design §10.8).
func (e *Exemptions) Match(w model.Workload) (Exemption, bool) {
	if e == nil {
		return Exemption{}, false
	}
	for _, x := range e.list {
		if x.Namespace != w.Namespace {
			continue
		}
		if x.Workload == "" || x.Workload == w.Name {
			return x, true
		}
	}
	if w.HostNetwork {
		return Exemption{
			Subject:   w.Namespace + "/" + w.Name,
			Namespace: w.Namespace,
			Workload:  w.Name,
			Reason:    "hostNetwork pod: not a Cilium endpoint, cannot be selected by a pod policy — accepted v1 gap",
		}, true
	}
	return Exemption{}, false
}

// List returns the exemptions in declaration order.
func (e *Exemptions) List() []Exemption {
	if e == nil {
		return nil
	}
	return append([]Exemption(nil), e.list...)
}
