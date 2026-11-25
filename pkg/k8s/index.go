package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/snbuback/kasil-egress/pkg/model"
)

// Workload is the top-level owner of a pod. Kind is one of Deployment,
// StatefulSet, DaemonSet, CronJob, Job or Pod.
type Workload struct {
	Namespace string
	Kind      string
	Name      string
	// Selector holds the labels that select this workload's pods, taken from
	// the workload's own spec.selector when the kind has one and derived from
	// the pod template otherwise. It is what a generated policy's
	// endpointSelector is built from, so it is never guessed.
	Selector map[string]string
	// PodLabels are the full labels of a representative pod (or of the pod
	// template for a workload with no running pod). Policy selectors are
	// evaluated against these, not against Selector: a CCNP may select on a
	// label the workload's own selector does not mention.
	PodLabels map[string]string
	// Labels are the workload object's own labels.
	Labels map[string]string
	Node   string
}

// Key returns "namespace/kind/name", the stable identity used in egress.edge.
func (w Workload) Key() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// Model converts the API view into the storage/policy view.
func (w Workload) Model() model.Workload {
	return model.Workload{
		Namespace: w.Namespace,
		Kind:      w.Kind,
		Name:      w.Name,
		Selector:  w.Selector,
		PodLabels: w.PodLabels,
		Labels:    w.Labels,
	}
}

var volatileLabels = map[string]struct{}{
	"pod-template-hash":                  {},
	"controller-revision-hash":           {},
	"statefulset.kubernetes.io/pod-name": {},
	"job-name":                           {},
	"batch.kubernetes.io/job-name":       {},
	"controller-uid":                     {},
	"batch.kubernetes.io/controller-uid": {},
	"apps.kubernetes.io/pod-index":       {},
	"rollouts-pod-template-hash":         {},
}

// Index caches the workload inventory. Refresh is cheap (seven list calls) and
// is expected to run every 30-60 s; nothing here watches.
type Index struct {
	client *Client

	mu       sync.RWMutex
	pods     map[string]podInfo  // "ns/name" -> pod
	byUID    map[string]string   // uid -> "ns/name"
	workload map[string]Workload // "ns/kind/name"
	fetched  time.Time
}

type podInfo struct {
	Namespace string
	Name      string
	UID       string
	Node      string
	Labels    map[string]string
	Owners    []ownerRef
}

type ownerRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller bool   `json:"controller"`
}

type objectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []ownerRef        `json:"ownerReferences"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
}

// NewIndex creates an empty index bound to a client.
func NewIndex(c *Client) *Index {
	return &Index{client: c, pods: map[string]podInfo{}, byUID: map[string]string{}, workload: map[string]Workload{}}
}

// FetchedAt reports when the last successful refresh happened.
func (i *Index) FetchedAt() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.fetched
}

// Refresh reloads pods and their owners from the API server.
func (i *Index) Refresh(ctx context.Context) error {
	podItems, err := i.client.ListAll(ctx, "/api/v1/pods")
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	type rawPod struct {
		Metadata objectMeta `json:"metadata"`
		Spec     struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
	}
	pods := make(map[string]podInfo, len(podItems))
	byUID := make(map[string]string, len(podItems))
	for _, raw := range podItems {
		var p rawPod
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("decode pod: %w", err)
		}
		key := p.Metadata.Namespace + "/" + p.Metadata.Name
		pods[key] = podInfo{
			Namespace: p.Metadata.Namespace,
			Name:      p.Metadata.Name,
			UID:       p.Metadata.UID,
			Node:      p.Spec.NodeName,
			Labels:    p.Metadata.Labels,
			Owners:    p.Metadata.OwnerReferences,
		}
		if p.Metadata.UID != "" {
			byUID[p.Metadata.UID] = key
		}
	}

	// Owner objects, keyed "ns/kind/name".
	owners := map[string]ownerObject{}
	collect := func(path string, kind string) error {
		items, err := i.client.ListAll(ctx, path)
		if err != nil {
			return fmt.Errorf("list %s: %w", kind, err)
		}
		for _, raw := range items {
			var o struct {
				Metadata objectMeta `json:"metadata"`
				Spec     struct {
					Selector *struct {
						MatchLabels map[string]string `json:"matchLabels"`
					} `json:"selector"`
					Template *struct {
						Metadata objectMeta `json:"metadata"`
					} `json:"template"`
					JobTemplate *struct {
						Spec struct {
							Template struct {
								Metadata objectMeta `json:"metadata"`
							} `json:"template"`
						} `json:"spec"`
					} `json:"jobTemplate"`
				} `json:"spec"`
			}
			if err := json.Unmarshal(raw, &o); err != nil {
				return fmt.Errorf("decode %s: %w", kind, err)
			}
			oo := ownerObject{Kind: kind, Name: o.Metadata.Name, Namespace: o.Metadata.Namespace, Labels: o.Metadata.Labels}
			if o.Spec.Selector != nil {
				oo.SpecSelector = o.Spec.Selector.MatchLabels
			}
			if o.Spec.Template != nil {
				oo.TemplateLabels = o.Spec.Template.Metadata.Labels
			}
			if o.Spec.JobTemplate != nil {
				oo.TemplateLabels = o.Spec.JobTemplate.Spec.Template.Metadata.Labels
			}
			oo.Owners = o.Metadata.OwnerReferences
			owners[oo.Namespace+"/"+kind+"/"+oo.Name] = oo
		}
		return nil
	}
	for _, r := range []struct{ path, kind string }{
		{"/apis/apps/v1/deployments", "Deployment"},
		{"/apis/apps/v1/statefulsets", "StatefulSet"},
		{"/apis/apps/v1/daemonsets", "DaemonSet"},
		{"/apis/apps/v1/replicasets", "ReplicaSet"},
		{"/apis/batch/v1/jobs", "Job"},
		{"/apis/batch/v1/cronjobs", "CronJob"},
	} {
		if err := collect(r.path, r.kind); err != nil {
			return err
		}
	}

	wl := map[string]Workload{}
	for key, p := range pods {
		w := resolve(p, owners)
		w.Node = p.Node
		wl[key] = w
	}
	// Also index the templates themselves, so a workload with no running pod
	// (a suspended CronJob, a scaled-to-zero Deployment) can still be
	// described in a report.
	for k, o := range owners {
		switch o.Kind {
		case "ReplicaSet":
			continue
		case "Job":
			if parent, ok := ownerWorkload(o, owners); ok {
				wl[k] = parent
				continue
			}
		}
		wl[k] = workloadOf(o)
	}

	i.mu.Lock()
	i.pods = pods
	i.byUID = byUID
	i.workload = wl
	i.fetched = time.Now()
	i.mu.Unlock()
	return nil
}

type ownerObject struct {
	Kind           string
	Name           string
	Namespace      string
	Labels         map[string]string
	SpecSelector   map[string]string
	TemplateLabels map[string]string
	Owners         []ownerRef
}

// resolve walks the owner chain of a pod to its top-level workload.
func resolve(p podInfo, owners map[string]ownerObject) Workload {
	ns := p.Namespace
	ownersOf := p.Owners
	// Depth is bounded: Pod -> ReplicaSet -> Deployment is the longest chain.
	for depth := 0; depth < 4; depth++ {
		ctrl := controllerRef(ownersOf)
		if ctrl == nil {
			break
		}
		o, ok := owners[ns+"/"+ctrl.Kind+"/"+ctrl.Name]
		if !ok {
			// Owner object already deleted: report the pod as a bare pod, but
			// keep the owner name for context.
			break
		}
		if next := controllerRef(o.Owners); next != nil {
			ownersOf = o.Owners
			continue
		}
		return workloadOf(o)
	}
	// Bare pod: select on its own labels minus the volatile ones.
	return Workload{
		Namespace: ns,
		Kind:      "Pod",
		Name:      p.Name,
		Selector:  stableLabels(p.Labels),
		PodLabels: p.Labels,
		Labels:    p.Labels,
	}
}

func ownerWorkload(o ownerObject, owners map[string]ownerObject) (Workload, bool) {
	if ctrl := controllerRef(o.Owners); ctrl != nil {
		if parent, ok := owners[o.Namespace+"/"+ctrl.Kind+"/"+ctrl.Name]; ok {
			return workloadOf(parent), true
		}
	}
	return Workload{}, false
}

func workloadOf(o ownerObject) Workload {
	sel := o.SpecSelector
	if len(sel) == 0 {
		sel = stableLabels(o.TemplateLabels)
	}
	if len(sel) == 0 {
		sel = stableLabels(o.Labels)
	}
	podLabels := o.TemplateLabels
	if len(podLabels) == 0 {
		podLabels = o.Labels
	}
	return Workload{Namespace: o.Namespace, Kind: o.Kind, Name: o.Name, Selector: sel, PodLabels: podLabels, Labels: o.Labels}
}

func controllerRef(refs []ownerRef) *ownerRef {
	for idx := range refs {
		if refs[idx].Controller {
			return &refs[idx]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

func stableLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if _, bad := volatileLabels[k]; bad {
			continue
		}
		out[k] = v
	}
	return out
}

// Resolve returns the workload that owns a pod.
func (i *Index) Resolve(namespace, pod string) (Workload, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if w, ok := i.workload[namespace+"/"+pod]; ok {
		return w, true
	}
	return Workload{}, false
}

// ResolveUID resolves by pod UID (preferred: pod names are reused, UIDs are not).
func (i *Index) ResolveUID(uid string) (Workload, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	key, ok := i.byUID[uid]
	if !ok {
		return Workload{}, false
	}
	if w, ok := i.workload[key]; ok {
		return w, true
	}
	return Workload{}, false
}

// Get returns a known workload by identity.
func (i *Index) Get(namespace, kind, name string) (Workload, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	w, ok := i.workload[namespace+"/"+kind+"/"+name]
	return w, ok
}

// Workloads returns every known workload, sorted by key.
func (i *Index) Workloads() []Workload {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Workload, 0, len(i.workload))
	seen := map[string]struct{}{}
	for _, w := range i.workload {
		if _, ok := seen[w.Key()]; ok {
			continue
		}
		seen[w.Key()] = struct{}{}
		out = append(out, w)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Key() < out[b].Key() })
	return out
}

// PodNode returns the node of a known pod, or "".
func (i *Index) PodNode(namespace, pod string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.pods[namespace+"/"+pod].Node
}

// SelectorString renders a selector deterministically (for logs and reports).
func SelectorString(sel map[string]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}
