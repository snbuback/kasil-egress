> **Status:** approved (review round 3, contract lens) and implemented in this
> repository. This is the ADR: read it before changing the data model, the
> policy generator or the exporter configuration. Implementation notes live in
> `docs/runbooks/`. The only intentional deviation from this text is that
> `blocked_flow.id` uses an explicit sequence instead of `GENERATED ALWAYS AS
> IDENTITY`, because identity columns are not supported on every PostgreSQL
> version on a partitioned parent.

# Strict egress for the kasil cluster — design

**Status:** proposal, for approval — no cluster change has been made
**Author:** Astro (coder)
**Date:** 2026-11-23
**Revision:** r3 — review round 1 fixes applied (flow `event_type` field mask, no byte counters, complete audit filters, filter-composition semantics, metric label names) and review round 2 fixes (the pre-existing `via-vpn` policy objects are part of the baseline, the report flags them, and generated policies may never widen them); change lists in Appendices G and H
**Target cluster:** kasil k3s, 4 nodes (`kube1`–`kube4.kasil.cloud`), Cilium 1.20.5, k8s v1.36.5+k3s1
**Scope of this document:** design only. Implementation is a separate card, to be created after approval.

**How to read it:** cluster facts are measured, dated and sourced (§2); Cilium behaviour is cited against 1.20.5 source/docs wherever it decides a design choice; anything that could not be verified from this environment is written as an explicit "verify on day 1" item instead of being assumed; cost and volume figures show their arithmetic, because a cluster with no workload policies has no flow history to measure yet.

---

## 0. Summary

The cluster today is effectively a **flat network for running pods**: zero `NetworkPolicy`, zero `CiliumNetworkPolicy`, Hubble disabled, and Cilium agent metrics not scraped. Two policy objects exist — a `CiliumClusterwideNetworkPolicy` egress allowlist and a `CiliumEgressGatewayPolicy` — but both select on the label `kasil.cloud/via-vpn=true`, which **no pod carries**, so in practice every running pod can reach every pod, every node, every LAN device and the internet on any port. That is the single largest blast-radius property of the deployment: any compromised workload — including the agent pod — has unrestricted lateral movement and unrestricted egress. The two objects still matter: they are an egress allowlist waiting for a label, and Phase 2 must treat them as a constraint rather than pretend they are absent (§2.1, §10.1).

The ask has two phases:

* **Phase 1 (audit)** — a detailed, per-namespace / per-workload report of what each service actually talks to, with connection volume (flow counts — bytes are out of scope, see §1), frequency, peer identity, DNS name and port.
* **Phase 2 (enforce)** — allow only what Phase 1 proved, deny everything else by default, and persist every denied flow so that legitimate new needs (e.g. after an upgrade) can be reviewed and promoted into the allowlist.

Cilium already generates the raw material for both phases; what it does **not** have is a place to keep it and a way to turn it into per-workload allowlists. This document proposes:

| Layer | Choice |
|---|---|
| Phase 1 capture | Cilium **Hubble** + Hubble **dynamic flow-log exporter** (aggregated, per node) |
| Phase 1/2 metrics | Cilium agent Prometheus + **Hubble metrics** (`policy`, `drop`, `flows-to-world`, `dns`) → existing **VictoriaMetrics** (30 d retention), Grafana dashboard, `VMRule` alerts |
| System of record | **PostgreSQL** — the existing CNPG cluster `cnpg-system/kasil-postgres`, new database `egress` |
| Collector | **`egressd`** — new DaemonSet, tails the node flow-log files and upserts into Postgres |
| Report / policy generation | **`egressctl`** — new CLI: `report` (Phase 1 deliverable), `plan`/`diff`/`verify` (Phase 2) |
| Enforcement | `CiliumNetworkPolicy` per workload, egress-only, GitOps via `kasil-apps` + the `kasil-cd` pipeline |
| Blocked-traffic review | raw deny/audit rows in Postgres (90 d) + `hubble_policy_verdicts_total{action="dropped"}` alerts + weekly digest |
| OSS tooling | **build it**, publish as `snbuback/kasil-egress` (Apache-2.0); no existing OSS tool covers this stack honestly (§6) |

Approximate cost: **~9 engineer-days** of implementation plus a 7–14 day Phase 1 soak and a 2–3 week ringed Phase 2 rollout. Steady-state resource cost: **~250–400 MiB RAM** across the cluster (Hubble agents + relay + collector), **~0.5–1.0 GiB** of the existing 10 GiB Postgres volume, negligible CPU.

---

## 1. Goals, non-goals, success criteria

### Goals

1. **G1** — Produce, on demand, a report of every observed egress edge, grouped by namespace and by top-level workload (Deployment / StatefulSet / DaemonSet / CronJob / Job), with: destination kind (pod / service / FQDN / CIDR / world), destination port and protocol, connection count, first/last seen, hour-of-day pattern.
2. **G2** — Enforce egress allowlists per workload with Cilium, default-deny, without breaking the cluster.
3. **G3** — Persist every denied (and, during rollout, every *would-be-denied*) flow, with enough context to decide "legit after an upgrade" vs "this is the incident", and a workflow to promote a reviewed flow into the allowlist.
4. **G4** — Make policy state observable: which workloads are enforced, in shadow, or exempt; which allow rules are unused; whether the collector is lagging or the agent dropped events.
5. **G5** — Everything declarative and reproducible in Git; no hand-edited cluster state.

### Non-goals (v1)

* **Ingress** policies. This design is egress-only. (Ingress has a specific trap in this cluster — kubelet probes are classified as identity `world`, so the first ingress policy can break every `httpGet` probe; see §10.5. It deserves its own card.)
* Pod-to-pod **L7** (HTTP method/path) policy. Possible later (`enable-l7-proxy: true` is already on), not needed for the threat model.
* FQDN allowlisting for **hostNetwork** pods (`homeassistant-hass`, `music-assistant-server`). They are not Cilium endpoints; see §10.8.
* Replacing Cilium, or adding a second eBPF agent/mesh.
* **Per-edge byte/packet volume.** Aggregated flow logs carry only flow *counts* (`Aggregate.{ingress,egress,unknown_direction}_flow_count`); `flow.Flow` has no byte or packet counters, and no Cilium/Hubble metric exposes per-edge bytes. The report measures connections, peers and timing, not bytes. Byte accounting would need L7 proxy access logs or a custom eBPF counter — a separate project, not a column we can add to this pipeline.
* **Managing or rewriting the pre-existing policy objects.** `via-vpn-isolation` (CCNP) and `via-vpn-egress` (CEGP) stay as they are; v1 treats them as constraints on generation (§10.1) and as context in the report (§9.2). Changing them is a separate decision with its own card.
* Multi-cluster / ClusterMesh.

### Success criteria

| # | Criterion | How it is proved |
|---|---|---|
| S1 | ≥ 95 % of running workloads have ≥ 7 days of observed edges (excluding exempt namespaces) | `egressctl report --coverage` |
| S2 | Every observed external destination is attributed to a DNS name **or** explicitly marked "IP-only, reviewed" | report column `dst_name_source` |
| S3 | Zero enforced workloads with unexplained `DENIED` flows for > 72 h | `egressctl verify --since 72h` + `EgressDenyUnknown` alert silent |
| S4 | Every denial is queryable for 90 days with workload, pod, node, dst IP/name, port | `egress.blocked_flow` |
| S5 | Deleting any single `CiliumNetworkPolicy` restores the previous (open) behaviour in < 60 s | rollback drill in ring 0 |

---

## 2. Current state (measured 2026-11-23)

All facts below were read live this session through the `kasil-k8s` MCP and the LAN VictoriaMetrics endpoint. They are the evidence base for every decision later in the document.

### 2.1 Cluster / Cilium

| Fact | Value | Source |
|---|---|---|
| Cilium | **1.20.5** (chart `cilium-1.20.5`, agent image `quay.io/cilium/cilium:v1.20.5`), managed by ArgoCD app `cilium` from `kasil-apps/apps/cilium` | DaemonSet + ConfigMap `cilium-config` |
| Datapath | `veth`, **native routing**, `kube-proxy-replacement: true`, IPv4 only, masquerade on | `cilium-config` |
| Pod CIDR | `172.16.0.0/16` (`ipv4-native-routing-cidr`), per-node `/24`s observed: kube2 `172.16.0.x`, kube1 `172.16.1.x`, kube4 `172.16.2.x`, kube3 `172.16.3.x` | Pod list |
| Service CIDR | **`172.30.0.0/16`** — API `172.30.0.1:443`, `kube-dns` **`172.30.0.10:53`** | `Service/kubernetes`, `Service/kube-dns` |
| L7 proxy | `enable-l7-proxy: true` (HTTP/DNS policy possible today) | `cilium-config` |
| FQDN policy | supported; `tofqdns-*` params already present (`tofqdns-dns-reject-response-code: refused`, `preallocate-identities: true`) | `cilium-config` |
| Policy mode | `enable-policy: default` (policies switch endpoints to default-deny **per direction**), `enable-k8s-networkpolicy: true`, `enable-non-default-deny-policies: true`, `policy-default-local-cluster: true` | `cilium-config` |
| Deny response | `policy-deny-response: none` → denied egress **silently drops**, clients see timeouts | `cilium-config` |
| BPF events | `bpf-events-policy-verdict-enabled: true`, `bpf-events-drop-enabled: true` → verdict events already available to Hubble | `cilium-config` |
| **Hubble** | **`enable-hubble: false`** — no relay, no UI, no flow API | `cilium-config`, `apps/cilium/values.yaml` |
| **Agent metrics** | **not enabled and not scraped.** TSDB contains only `envoy_cilium_*` (from `envoy.prometheus.serviceMonitor.enabled: true`); no `cilium_*`, no `hubble_*` | VictoriaMetrics `count by (__name__)` |
| **Policies, per workload** | **`NetworkPolicy`: 0. `CiliumNetworkPolicy`: 0.** No workload is isolated today. | `resources_list` (empty result on both kinds) |
| **Pre-existing cluster policy** | **1 `CiliumClusterwideNetworkPolicy`: `via-vpn-isolation`** — selector `kasil.cloud/via-vpn=true`, egress allowlist (kube-dns `:53` + `world`), no ingress rules. **0 pods match**, inert today. Spec below. | `resources_get` |
| **Pre-existing egress gateway** | **1 `CiliumEgressGatewayPolicy`: `via-vpn-egress`** — same selector; world traffic (RFC1918 excluded) SNATed to `192.168.20.50`. **0 pods match.** Spec below. | `resources_get`; `resources_list Pod -l kasil.cloud/via-vpn=true` (empty) |
| Egress gateway feature | enabled (`enable-egress-gateway`), used only by `via-vpn-egress` above | `cilium-config` |
| Ingress | Cilium ingress controller, shared LB `192.168.20.40`, TLS via `k8s-kasil-cloud-tls` | Ingress list |

Specs as read live (both Valid, both created `2026-07-04T13:44:50Z`, both Git-managed by the `cilium` ArgoCD app from `kasil-apps/apps/cilium/templates/egress-gateway.yaml`, commit `a73a099`):

```yaml
# CiliumClusterwideNetworkPolicy/via-vpn-isolation
spec:
  endpointSelector: {matchLabels: {kasil.cloud/via-vpn: "true"}}
  egress:
    - toEndpoints:
        - matchLabels: {io.kubernetes.pod.namespace: kube-system, k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
    - toEntities: [world]
  ingress: []        # v1.20.5 API: "If omitted or empty, this rule does not apply at ingress"
---
# CiliumEgressGatewayPolicy/via-vpn-egress
spec:
  selectors:
    - podSelector: {matchLabels: {kasil.cloud/via-vpn: "true"}}
  destinationCIDRs: ["0.0.0.0/0"]
  excludedCIDRs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  egressGateway:
    nodeSelector: {matchLabels: {node-role.kubernetes.io/control-plane: "true"}}
    egressIP: "192.168.20.50"
```

**What the two pre-existing objects mean for this design.** They are the cluster's only policy history, and they matter twice.

1. **Truncated ground truth.** Any pod that gains `kasil.cloud/via-vpn=true` is already egress-default-denied with a two-entry allowlist (DNS, world). Its in-cluster attempts are *already dropped*, so they never appear as allowed edges and the audit would show that workload talking only to DNS and the internet. The report therefore marks such workloads `PRE-POLICED` (§9.2) instead of trusting their edge set.
2. **Additive policy can only widen.** Cilium unions every policy that selects an endpoint. A generated `<workload>-egress` CNP does not replace `via-vpn-isolation`; it is combined with it, and since the generated policy is the permit side, the union can only *add* allowed peers — silently re-opening cluster-internal access the isolation deliberately denies. `egressctl plan`/`lint` therefore treat every pre-existing selecting policy as a hard upper bound (§10.1, §10.5).

### 2.2 Nodes (capacity decides whether Hubble fits)

| Node | Role | CPU used | Mem used | Mem total | Swap |
|---|---|---|---|---|---|
| kube1 | control-plane | 857 m (21 %) | 5 073 MiB (65 %) | ~7.8 GiB | 0 |
| kube2 | control-plane | 1 289 m (32 %) | 8 876 MiB (55 %) | ~16 GiB | 0 |
| kube3 | worker | 1 000 m (25 %) | 2 431 MiB (64 %) | **~3.8 GiB** | 0 |
| kube4 | control-plane | 1 082 m (27 %) | 5 166 MiB (66 %) | ~7.8 GiB | 0 |

kube3 is the constraint: ~1.3 GiB free. Hubble relay and UI must therefore be **pinned to kube2**, and the per-node agent increase must stay in the low hundreds of MiB.

### 2.3 Workload inventory (what has to be covered)

28 namespaces; 23 ArgoCD Applications; **40 Deployments, 7 StatefulSets, 9 DaemonSets**. Running workload-bearing namespaces with their top-level resources:

| Namespace | Workloads (kind) | Notes for egress |
|---|---|---|
| `argo` | `kasil-cd-argo-workflows-workflow-controller` (D), `kasil-cd-argo-events-controller-manager` (D) | kube-apiserver, GitHub API, ArgoCD, Discord/SMTP for notify |
| `argo-events` | `eventbus-default-js` (SS, NATS), `github-eventsource-*` (D), `kasil-cd-sensor-*` (D) | inbound GitHub webhooks (no egress need), NATS intra-ns, apiserver |
| `argocd` | `argocd-server`, `argocd-repo-server`, `argocd-redis`, `applicationset-controller` (D), `argocd-application-controller` (SS) | `github.com:443`, Helm OCI/HTTPS registries, `auth.k8s.kasil.cloud`, apiserver |
| `auth` | `auth-authelia` (D) | Postgres `kasil-postgres-rw`, SMTP, OIDC providers |
| `cert-manager` | `cert-manager`, `cainjector`, `webhook` (D) | `acme-v02.api.letsencrypt.org:443` (ACME + DNS-01 API), apiserver |
| `check` | `kasil-check` (CronJob pods) | apiserver, in-cluster services, exa/LLM APIs (see chart) |
| `cloudflare-tunnel` | `cloudflared` (D) | `api.cloudflare.com`, QUIC to Cloudflare edge, ingress LB `192.168.20.40` |
| `cnpg-system` | `cloudnative-pg` (D), `kasil-postgres-{1,2}` (pods) | pod-to-pod replication (intra-ns), S3 if backups configured |
| `ddns-route53` | `ddns-route53` (D) | `route53.amazonaws.com` / AWS APIs |
| `external-secrets` | `external-secrets` (D), `bitwarden-sdk-server` (D) | Bitwarden (cloud or vaultwarden) over 443 |
| `frigate` | `frigate` (D) | cameras `192.168.31.10`, `192.168.31.11` (HTTP-FLV/RTSP), MQTT broker, NTP, in-cluster MQTT |
| `hermes` | `hermes-hermes-agent` (SS) | **wide**: OpenRouter, Anthropic, GitHub, Brave/Exa, Discord, Telegram, Gmail/Graph, Home Assistant, honcho, victoria MCP, k8s MCP … |
| `homeassistant` | `homeassistant-hass` (D, **hostNetwork**), `music-assistant-server` (SS, **hostNetwork**), `alexa-skill` (SS), `eufy-deployment` (D) | mDNS/DHCP/discovery on the LAN, IoT devices, cloud APIs |
| `honcho` | `honcho-api`, `honcho-deriver` (D) | `openrouter.ai:443`, Postgres, possibly pgvector |
| `mcp` | `mcp-kubernetes-mcp-server` (D) | kube-apiserver only (today) |
| `nanomq` | `nanomq` (D) | MQTT intra-cluster + LAN clients |
| `piraeus-datastore` | linstor controller / CSI / 4 satellites / ha-controller | DRBD is **kernel-level** (host netns), not pod egress; LINSTOR API on 3370 intra-ns |
| `rclone` | `rclone` (D) | S3/B2/Drive endpoints over 443 |
| `routers` | chart only (probes `192.168.20.2`, `192.168.20.3`) | LAN ICMP/HTTP |
| `test-cd` | test workload | ring-0 canary for this rollout |
| `victoria` | `vmsingle`, `vmagent`, `vmalert`, `alertmanager`, `grafana`, `kube-state-metrics`, `node-exporter`, `victoria-metrics-mcp` | scrape targets cluster-wide, Grafana data sources, Alertmanager receivers (Discord/SMTP), `grafana.net` (plugin downloads) |
| `vikunja` | `vikunja` (D) | Postgres, SMTP, OIDC (`auth.k8s.kasil.cloud`) |
| `zigbee2mqtt` | `zigbee2mqtt` (SS) | MQTT broker, Zigbee coordinator over TCP (`192.168.1.12:6638` is configured and looks wrong/unreachable — confirm in Phase 1) |
| `kube-system` | `cilium` + `cilium-envoy` (DS), `coredns` (D), `cilium-operator` (D), `metrics-server`, `snapshot-controller` | apiserver, node-local, upstream DNS; **exempt from v1 egress policy** |

### 2.4 Three facts that shape the design

1. **There is almost no policy history to preserve.** The only policy objects are `via-vpn-isolation` (CCNP) and `via-vpn-egress` (CEGP), both scoped to `kasil.cloud/via-vpn=true`, which **no pod carries** (§2.1). For every unlabeled workload Phase 1 captures clean ground truth — every observed flow is, by definition, currently allowed. A workload that acquires the label is the exception: its in-cluster attempts are already dropped and never appear as allowed edges, which is why the report flags it `PRE-POLICED` instead of trusting its edge set (§9.2). This is still the cheapest possible moment to do this.
2. **Postgres already has a shape to follow.** `apps/cnpg` declares databases declaratively (`values.yaml` → `postgresql.cnpg.io/v1 Database` resources, managed roles with `passwordSecret`), so a new `egress` database is a 4-line change plus an `ExternalSecret`. But the volume is **3.2 GiB used of 10 GiB (32 %) for both instances** — the schema below is sized to stay under ~1 GiB steady state.
3. **Two production workloads are invisible to pod-level policy** — `homeassistant-hass` and `music-assistant-server` run `hostNetwork: true` (IPs `192.168.20.12` / `192.168.20.11`, i.e. the node IPs). They are not Cilium endpoints; `CiliumNetworkPolicy` with `endpointSelector` cannot select them. They must be excluded and handled separately (§10.8).

### 2.5 GitOps reality (how policy changes will actually land)

* `argocd/Application apps` (app-of-apps) renders `kasil-apps/apps/apps` (Helm) → one `Application` per entry in `apps/apps/values.yaml`, source path `apps/<path>`, `targetRevision: HEAD`.
* **Auto-sync is OFF by default** — by design: every app is deployed by the `kasil-cd` pipeline (`plan → sync → watch → validate → rollback`), and `deployctl` drops auto-synced apps from the writer check. New egress manifests therefore have to be an app entry, not an auto-synced directory.
* `hermes`, `kasil-cd`, `kasil-check` are separate Applications (different repos).
* ArgoCD health is `Synced/Healthy` for all 23 apps today.

---

## 3. Requirements

| ID | Requirement | Notes |
|---|---|---|
| R1 | Per-workload egress inventory with connection volume (flow counts) and timing | "per namespace and per top resource (like statefulset or deploy)" — the report must aggregate pods up to their owner |
| R2 | Deny-by-default enforcement, per workload | Cilium default-deny per direction once a policy selects the endpoint |
| R3 | Every denied flow persisted and reviewable | includes the *would-be-denied* flows during rollout |
| R4 | No silent breakage | shadow mode + alerting on new denials + rollback in one commit |
| R5 | Fits the hardware | ≤ ~400 MiB cluster-wide for the whole pipeline; ≤ 1 GiB Postgres |
| R6 | Declarative & reversible | CNP in Git; `kubectl delete cnp` = instant rollback |
| R7 | Works for namespaced pods **and** world/LAN/FQDN destinations | cameras, routers, MQTT, cloud APIs |
| R8 | Distinguishes "new legit need" from "attack" | first-seen timestamp + connection volume + review state, not just a log line |
| R9 | Publishable tooling | if we build, it must be generic enough to open-source |

---

## 4. What Cilium already provides (and where it stops)

This is the heart of the design decision, so it is spelled out with sources.

### 4.1 Audit mechanisms — four different things, often confused

| Mechanism | What it does | Granularity | Persistence | Use in this design |
|---|---|---|---|---|
| **Daemon `policyAuditMode: true`** (helm `policyAuditMode`, flag `--policy-audit-mode`) | Policies are evaluated, drops are **logged as `AUDIT`, not enforced** | whole agent / node set | needs agent restart | Time-boxed smoke test of a whole batch (≤ 72 h) |
| **Endpoint `PolicyAuditMode=Enabled`** (`cilium-dbg endpoint config <id> PolicyAuditMode=Enabled`) | same, for one endpoint | per endpoint | **not persisted**; reset by agent restart | not used — non-declarative |
| **`spec.enableDefaultDeny: {egress: false}`** on a CNP | The policy's allow rules exist but the endpoint does **not** enter default-deny for that direction; unmatched traffic is allowed and reported with `policy_match_type == 4` ("implicit allow-all") | per policy / per direction | declarative, survives restarts | **Primary shadow mechanism** for Phase 2 |
| **Plain flow logs (Hubble)** | Every connection with verdict `FORWARDED` / `DROPPED` / `AUDIT` | per flow | until the ring buffer wraps (4095 events/node) or the exporter writes it out | **Phase 1 ground truth** and Phase 2 deny record |

Two consequences that are easy to get wrong:

* **There is almost nothing to audit today.** Audit mode only produces `AUDIT` verdicts for traffic that a policy would deny. The cluster's only egress policy (`via-vpn-isolation`, §2.1) selects no running pod, so turning audit mode on would log nothing. Phase 1 must therefore be built on *flow logs*, not on audit verdicts.
* **`enableDefaultDeny: false` is not "audit".** It is "evaluate and allow-all". To see what *would* have been blocked you filter for `policy_match_type == 4`; Cilium does not emit `AUDIT` for it. The design keeps both: per-policy shadow mode for safety, plus an offline `egressctl diff` that compares observed edges against the shipped rules (precise, no verdict dependency).

### 4.2 Enforcement primitives available in 1.20.5

Verified against the `ciliumnetworkpolicies.cilium.io` CRD shipped with v1.20.5 (`pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml`). All of the following exist as egress rule fields:

| Field | Use |
|---|---|
| `toEndpoints` + `matchLabels` | pod-to-pod inside the cluster (stable across IP churn) |
| `toServices: [{k8sService: {namespace, serviceName}}]` | allow a Service by name — resolves to its current backends. Better than CIDR for `kasil-postgres-rw` etc. |
| `toFQDNs: [{matchName, matchPattern}]` | external names (`openrouter.ai`, `api.cloudflare.com`, `acme-v02.api.letsencrypt.org`). Requires the DNS proxy (`enable-l7-proxy: true` ✓) and pods resolving through `kube-dns` (`dnsPolicy: ClusterFirst` ✓ default) |
| `toCIDR` | LAN devices, camera IPs, routers — anything without a name |
| `toEntities: [kube-apiserver, world, host, cluster]` | apiserver access without hardcoding `172.30.0.1`; `world` = everything outside the cluster+host |
| `toNodes` | node-local traffic when needed |
| `toPorts: [{ports, rules: {dns, http}}]` | port scoping; `rules.dns.matchPattern: "*"` is required for `toFQDNs` to work |
| `egressDeny` | explicit denies (not needed for the allowlist model, useful for e.g. `169.254.169.254` hygiene) |
| `nodeSelector` (on CCNP) | host-level policy — the *only* way to reach hostNetwork pods |
| `enableDefaultDeny` | the shadow switch above |

Notes that matter for this cluster:

* `192.168.0.0/16` is **not** cluster-local. With `ipv4-native-routing-cidr: 172.16.0.0/16`, everything on the LAN (cameras, routers, NAS, `192.168.20.40` ingress LB) is identity `world`. Egress to LAN devices must be expressed with `toCIDR` (or FQDN), not `toEntities: [world]`.
* `policy-deny-response: none` means denied connections **hang until timeout**, which looks like a broken app rather than a policy. Recommended to switch to `icmp` (experimental, IPv4 egress only) once Phase 2 starts, so failures are immediate — with the caveat that if ingress policies are ever added, ICMP must be allowed in.

### 4.3 Observability primitives

Cilium agent metrics (`prometheus.enabled=true`, port 9962) — the ones that matter here:

| Metric | Why |
|---|---|
| `cilium_drop_count_total{direction, reason}` | node-level drop counter; `reason="Policy denied"` is the aggregate sanity check |
| `cilium_endpoint_state`, `cilium_policy_count`, `cilium_identity_count` | policy applied? endpoints healthy? identity churn |
| `cilium_policy_implementation_delay` | how long a new policy takes to be in the datapath |
| `cilium_network_policies_total`, `cilium_clusterwide_network_policies_total` | ingestion counters (config accepted ≠ enforced) |

Hubble metrics (`hubble.metrics.enabled`, port 9965) — **this is the important set**, because it carries workload context:

| Metric group | Metric | Labels |
|---|---|---|
| `policy` | `hubble_policy_verdicts_total` | `direction`, `match` (lowercased `L3-L4` / `all` / `l7/<proto>`), `action` (lowercased flow verdict: `forwarded`, `dropped`, `audit`, `redirected`), **plus** `sourceContext`/`destinationContext`/`labelsContext` labels |
| `drop` | `hubble_drop_total` | `reason` (protobuf enum name, e.g. `POLICY_DENIED` — note the agent metric `cilium_drop_count_total` uses the human form `Policy denied`), `protocol`, + context |
| `flows-to-world` | `hubble_flows_to_world_total` | `protocol`, `verdict`, optional `port`; option `syn-only`, `any-drop` |
| `dns` | `hubble_dns_queries_total` / `hubble_dns_responses_total` | + `query` option adds the queried name |
| `flow` | `hubble_flows_processed_total` | `protocol`, `type`, `subtype`, `verdict` |
| `tcp` | `hubble_tcp_flags_total` | flags |

`hubble_policy_verdicts_total` with `sourceContext=workload-name|reserved-identity` and `destinationContext=workload-name|dns|reserved-identity` is what makes a per-workload denied-traffic alert possible **without** reading flow logs. (Label names/values verified in `pkg/hubble/metrics/policy/handler.go` at v1.20.5: `direction`, `match`, `action`.) Three naming traps, all fixed in §11.2: a denial is `action="dropped"` (there is no `DENIED` verdict — the policy-verdict parser maps a denied event to `Flow.verdict = DROPPED`, and `action` is the lowercased verdict); the workload label is `source` (from `sourceContext`), **not** `source_workload` (that only exists if added to `labelsContext`); and `direction` is the lowercase traffic direction (`egress`), not the request/response distinction.

Hubble **flow-log exporter** (the piece that makes Phase 1 possible):

* **Static** (`hubble.export.static.*`) — one filter set, bound to agent lifecycle, needs an agent restart to change.
* **Dynamic** (`hubble.export.dynamic.*`) — **multiple named exporters, hot-reloaded from a ConfigMap in ≤ 60 s**, no restart. Each has `includeFilters`/`excludeFilters`, `fieldMask`, `fieldMaxSizeMb`/`fileMaxBackups`/`fileCompress`.
* **`fieldAggregate` + `aggregationInterval`** (new in 1.19, present in 1.20.5 — CFP-37472) — group flows by fields (any valid `Flow` proto path, because `FieldAggregate` wraps `FieldMask`) and emit **counts** per interval: `flow.aggregate.{ingress_flow_count, egress_flow_count, unknown_direction_flow_count}`. When `fieldAggregate` is set, `fieldMask` is ignored. Aggregation is **per node**, so a pod-to-pod flow across nodes appears on both nodes (once as egress on the source, once as ingress on the destination) — count `traffic_direction == EGRESS` only.
* Files are written **inside the agent container** under `/var/run/cilium/hubble/` (which is a host path mount, `/run` → tmpfs), so a DaemonSet can tail them from the host without touching the agent's API.

### 4.4 Where Cilium stops — the four gaps this design fills

| Gap | Consequence | Filled by |
|---|---|---|
| The ring buffer holds ~4095 flows **per node** (minutes), not days | can't answer "what did X talk to last week" | durable export → Postgres |
| Aggregated flow logs are counts, not an inventory | a row per (src,dst,port) is not a *workload-level* answer | `egressd` resolves pod → owner workload, keeps `edge` state |
| No "what would the shipped policy block" offline check | shadow-mode verdicts are indirect and racy | `egressctl diff` (edges vs rules) |
| Deny verdicts are nodes-local events | no history, no review queue | `blocked_flow` table + alerts + digest |

---

## 5. Options considered

Three coherent options, not ten features.

### Option A — Cilium-native + thin tooling (recommended)

Hubble (flow logs + metrics) → Postgres (inventory, edges, denies) → `egressctl` → CNP in GitOps.

* **Pros:** single source of truth (Cilium already sees every packet); no second agent; FQDN/entity/service semantics available; deny history in a database the user already runs; everything publishable; lowest steady-state RAM (agent bump + one 30 MiB DaemonSet + relay 60 MiB).
* **Cons:** ~9 days of build; we own the collector; must handle the pod→workload mapping ourselves.
* **Cost:** ~250–400 MiB RAM, ≤ 1 GiB Postgres, ~1 000 lines of Go.

### Option B — Glue an existing generator (fastest)

Use an existing Hubble→CNP generator (`SoulKyu/cpg`, `onzack/cf2cnp`) plus hubble metrics only; no database.

* **Pros:** 1–2 days to first policy; `cpg` even automates the audit window.
* **Cons:** fails R1 (no durable per-workload inventory), fails R3 (deny history is whatever the tool printed), single-maintainer projects, and `cpg`'s drip-feed model ("let the app break, then generate the missing rule") is exactly the "silent breakage" R4 forbids. Useful as **prior art and as a fallback generator**, not as the system of record.
* **Cost:** ~1–2 days, but recurring manual work.

### Option C — Buy into an OSS network mapper (Otterize)

`network-mapper` (sniffer DaemonSet + mapper) + `intents operator` (ClientIntents → NetworkPolicy).

* **Pros:** product-shaped, has a UI, handles DNS-based intents, generates Kubernetes NetworkPolicy.
* **Cons:** upstream OSS last pushed **2025-06-10** and the recent releases are all "report to Otterize Cloud"; it generates **standard** `NetworkPolicy` (no `toFQDNs`, no entities, no `toServices`), so the interesting external destinations degrade to CIDRs; adds a second eBPF/packet sniffer on four Raspberry Pis that must be kept in sync with Cilium's view of the world.
* **Cost:** ~2 days to deploy, plus an ongoing risk of an unmaintained dependency in the security path.

### Rejected for the same reason (second sniffer, wrong CNI, or no ARM64)

`KubeArmor`/`karmor discover` (LSM runtime security; network visibility is a by-product), `Inspektor Gadget advise_networkpolicy` (excellent one-shot diagnostic, no history, produces `NetworkPolicy` not CNP — keep as a cross-check), `Pixie` (no ARM64), Tetragon (process/file security, not L3/L4 egress allowlists), Calico tooling (different CNI).

### Decision

**Option A.** Rationale in one line: Cilium already produces strictly more information than any third-party tool could, the cluster already has a database and a metrics stack, and the missing piece is a few hundred lines of glue — buying it would add a second source of truth to a security control.

---

## 6. Architecture

```
                     ┌────────────── per node (kube1..kube4) ──────────────┐
  hubble CLI ───────▶│ cilium-agent + Hubble                               │
  (port-forward)     │   · ring buffer, 4095 events                        │
                     │   · exporter audit-agg : 60 s aggregates, egress    │
                     │   · exporter deny-raw  : DROPPED / AUDIT / ERROR    │
                     │   · exporter dns-raw   : port 53, queries+answers   │
                     │   · metrics :9965 (policy, drop, flows-to-world)    │
                     └──────────┬───────────────────────┬──────────────────┘
                                │ files in /var/run/cilium/hubble
                                ▼
                  ┌──────────────────────────┐      ┌────────────────────────────────┐
                  │ egressd (DaemonSet)      │      │ vmagent (ServiceMonitors)      │
                  │  tail → parse → upsert   │      │   └─▶ VictoriaMetrics (30 d)   │
                  │  pod → workload resolve  │      │        ├─ Grafana dashboard    │
                  └───────────┬──────────────┘      │        └─ VMRule ─▶ vmalert ─▶ │
                              │ SQL, batched        │             Alertmanager ─▶ chat│
                              ▼                     └────────────────────────────────┘
                  ┌──────────────────────────┐
                  │ CNPG kasil-postgres      │◀──── egressctl (CronJob or laptop)
                  │ database "egress"        │       report · plan · diff · verify
                  │ edge / blocked_flow / …  │
                  └──────────────────────────┘
                                                         │ generated YAML
                                                         ▼
                              kasil-apps/apps/egress/policies/<ns>/<workload>.yaml
                                                         │ git push
                                                         ▼
                                     kasil-cd pipeline → ArgoCD → CNP enforced
```

### 6.1 Why two planes (metrics **and** flow rows)

They answer different questions and neither replaces the other:

| Question | Answered by |
|---|---|
| "Is anything being denied right now?" | `hubble_policy_verdicts_total{action="dropped",direction="egress"}` (cheap, alertable, per workload) |
| "What did `frigate` talk to in the last 14 days?" | `egress.edge` / `egress.flow_hourly` (inventory, names, timing) |
| "What exactly was blocked at 03:12?" | `egress.blocked_flow` (raw tuple, pod, node, dst IP + names, reason) |
| "Which rule is unused?" | `egressctl diff` (policy vs observed) |

Metric cardinality is bounded (workload × workload × port), so metrics go to VictoriaMetrics with 30 d retention; flow rows go to Postgres because the report needs ad-hoc SQL and long retention.

### 6.2 Data flow: what is captured where

| Signal | Source | Filter | Destination | Retention |
|---|---|---|---|---|
| Allowed edges (counts) | dynamic exporter `audit-agg` | one AND-ed include entry (`traffic_direction=egress`, `reply=false`); exclude destination `kube-system/` and `piraeus-datastore/`, exclude source `victoria/vmagent` scrape fan-out (separate OR-ed exclude entries, §7.1) | `egress.edge` (upsert) + `egress.flow_raw_agg` | edge: forever (bounded set); raw: 48 h |
| Hourly rollup | `egressd`/CronJob from `flow_raw_agg` | — | `egress.flow_hourly` | 180 d |
| Denied + audited flows | dynamic exporter `deny-raw` | `verdict in (DROPPED, AUDIT, ERROR)` | `egress.blocked_flow` | 90 d |
| DNS answers | dynamic exporter `dns-raw` | port 53 (queries + responses); yields names only because step §9.1 1.2a puts DNS through the Cilium DNS proxy | `egress.dns_name` | 90 d |
| Denied counts per workload | hubble `policy` metric | — | VictoriaMetrics | 30 d |
| Agent health | cilium metrics | — | VictoriaMetrics | 30 d |

---

## 7. Cilium configuration to add

All of this is a diff to `kasil-apps/apps/cilium/values.yaml` — the file nests every key under `cilium:` and `cilium.hubble.enabled` is `false` today. Full values block in Appendix A.

```yaml
hubble:
  enabled: true
  relay:
    enabled: true
    resources:                    # chart default is {} — must be explicit
      requests: {cpu: 30m, memory: 64Mi}
      limits:   {cpu: 300m, memory: 192Mi}
    nodeSelector:                 # keep it off the tight node
      kubernetes.io/hostname: kube2.kasil.cloud
  ui:
    enabled: false                # v1: port-forward hubble CLI; see §13 Q2
  metrics:
    enabled:
      - "policy:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|dns|reserved-identity;labelsContext=source_namespace,destination_namespace,traffic_direction"
      - "drop:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|dns|reserved-identity"
      - "dns"                     # counts only (no `query` label: cardinality); names come from dns-raw
      - "flows-to-world:port;syn-only"
      - "flow"
    serviceMonitor:
      enabled: true
  export:
    dynamic:
      enabled: true
      config:
        createConfigMap: true
        content: []               # replaced by the three exporters in §7.1

prometheus:
  enabled: true
  serviceMonitor:
    enabled: true

policyAuditMode: false            # flipped to true only inside a smoke window (§10.3)
# policyDenyResponse: icmp        # enable from Phase 2 ring 0 onwards (§10.6)
```

* `prometheus.serviceMonitor.enabled: true` **will be scraped** — proved by the existing `envoy.prometheus.serviceMonitor.enabled: true` producing live `envoy_cilium_*` series with `job="cilium-envoy"`.
* Agent memory increase from Hubble is the flow ring buffer (4095 events) + exporter buffers: budget **40–80 MiB per node**; measure after rollout on kube3 first.
* Relay is a Deployment pinned to kube2 (16 GiB, 55 % used); UI is off in v1 (port-forward + Grafana instead).

### 7.1 Dynamic exporter content (three flow logs per node)

```yaml
hubble:
  export:
    dynamic:
      enabled: true
      config:
        createConfigMap: true
        content:
          - name: audit-agg                 # Phase 1 ground truth, 60 s aggregates
            filePath: /var/run/cilium/hubble/audit-agg.log
            aggregationInterval: 60s
            fieldAggregate:
              - source.namespace
              - source.pod_name
              - source.workloads
              - destination.namespace
              - destination.pod_name
              - destination.workloads
              - IP.destination
              - destination_names           # FQDN attribution for world traffic
              - l4                          # protocol + ports (oneof, keeps proto)
              - verdict
              - traffic_direction
            includeFilters:
              # Fields inside ONE entry are AND-ed; separate entries are OR-ed (note 2 below).
              - traffic_direction: [EGRESS]
                reply: [false]                      # request direction only; evaluated against Flow.is_reply
            excludeFilters:
              # Separate entries on purpose: each entry excludes on its own (OR).
              - destination_pod: ["kube-system/"]        # DNS + control-plane chatter
              - destination_pod: ["piraeus-datastore/"]  # LINSTOR/DRBD control traffic
              - source_pod: ["victoria/vmagent"]         # scrape fan-out; vmagent is exempt in Phase 2 (§10.4)
            fileMaxSizeMb: 8
            fileMaxBackups: 3
            fileCompress: true

          - name: deny-raw                  # phase 2 review queue, raw events
            filePath: /var/run/cilium/hubble/deny-raw.log
            fieldMask:
              - time
              - node_name
              - source
              - destination
              - destination_names
              - IP
              - l4
              - verdict
              - drop_reason_desc
              - event_type            # Flow.event_type {type, sub_type}; Flow has no `type` field
              - traffic_direction
            includeFilters:
              - verdict: [DROPPED, AUDIT, ERROR]
            fileMaxSizeMb: 8
            fileMaxBackups: 5
            fileCompress: true

          - name: dns-raw                   # name → IP inventory
            filePath: /var/run/cilium/hubble/dns-raw.log
            fieldMask: [time, source.namespace, source.pod_name, destination, l7.dns, event_type, traffic_direction]
            includeFilters:
              - destination_port: ["53"]    # queries — port 53 catches proxied and unproxied DNS
              - source_port: ["53"]          # responses carry the answers we care about
            fileMaxSizeMb: 8
            fileMaxBackups: 3
            fileCompress: true
```

Implementation notes / things to verify on day 1 of the implementation card (they are cheap to check and would be expensive to assume):

1. **Both `fieldMask` and `fieldAggregate` are validated against the `flow.Flow` protobuf schema** (`fieldmaskpb.New(&flowpb.Flow{}, …)`), and an invalid path fails exporter *creation*, not config parsing: `dynamicExporter.applyUpdatedConfig` logs `Failed to create exporter for config` and skips that exporter, while `hubble_dynamic_exporter_config_hash` / `_config_last_applied` still advance. A typo here is therefore silent unless it is checked: `hubble_dynamic_exporter_up{name=…}` must be `1` and `hubble_dynamic_exporter_exporters_total{status="active"}` must be `3` on every node (alert `EgressExporterMissing` in §11.2, commands in Appendix E). That is exactly the failure mode a non-existent `Flow` field such as `type` would cause — the real field is `event_type`. `l4` as an aggregate key groups by the whole L4 oneof, so TCP and UDP ports stay distinct; verify the emitted record actually contains `aggregate.egress_flow_count`.
2. **Filter composition (v1.20.5, `pkg/hubble/filters`):** all fields inside one `includeFilters` entry must match (`BuildFilterList` wraps each `FlowFilter` with `MatchAll`), and the entries of the list are OR-ed (`FilterFuncs.MatchOne` in `Apply`). The same holds for `excludeFilters`; `Apply` requires `whitelist.MatchOne && blacklist.MatchNone`, so each exclude entry excludes on its own. Consequences: `traffic_direction` and `reply` go in the **same** entry (AND), while the three exclusions are **separate** entries (OR) — an entry containing two selectors would mean "exclude only if both match". All filter fields used above exist in `FlowFilter` at v1.20.5 (`traffic_direction`, `verdict`, `reply`, `source_port`, `destination_port`, `source_pod`, `destination_pod`). `reply` is the `FlowFilter` field name but it is evaluated against `Flow.is_reply` (the deprecated `Flow.reply` bool is ignored; a dropped flow with no `is_reply` is treated as non-reply). There is no dedicated "flow is DNS" *boolean*, but `protocol` does accept the L7 protocol names: `protocol: ["dns"]` matches every flow whose `l7.dns` is set, and `protocol: ["http"]` likewise. Port 53 is still what the design selects on, because it also catches plain L3/L4 DNS that never reached the proxy (useful diagnostics on day 1); once the proxy path is confirmed (§9.1 step 1.2a), `protocol: ["dns"]` is the tighter selector. `dns_query` (RE2 on the query name) exists if name-based narrowing is ever needed.
3. Files live in tmpfs (`/run`), so rotation caps matter for RAM, not flash: total worst case per node = (8 × 4) + (8 × 6) + (8 × 4) ≈ 112 MiB. Reduce `fileMaxSizeMb` to 4 if kube3 gets tight.
4. `deny-raw` is intentionally **not** aggregated: one row per denial is what makes the review actionable (and denials are rare by construction).

---

## 8. Data model (PostgreSQL)

New database `egress` on the existing `cnpg-system/kasil-postgres` cluster, owned by managed role `egress` (password via `ExternalSecret` from Bitwarden, matching the other databases in `apps/cnpg`).

### 8.1 DDL

```sql
CREATE SCHEMA IF NOT EXISTS egress;

-- ── inventory (dimension) ────────────────────────────────────────────────────
CREATE TABLE egress.workload (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  namespace   text  NOT NULL,
  kind        text  NOT NULL,            -- Deployment | StatefulSet | DaemonSet | CronJob | Job | Pod
  name        text  NOT NULL,
  labels      jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (namespace, kind, name)
);

CREATE TABLE egress.pod (
  uid        text PRIMARY KEY,
  workload_id bigint REFERENCES egress.workload(id),
  namespace  text NOT NULL,
  name       text NOT NULL,
  node       text,
  ip         inet,
  created_at timestamptz,
  deleted_at timestamptz
);

CREATE TABLE egress.dns_name (
  fqdn      text NOT NULL,
  ip        inet NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (fqdn, ip)
);

-- ── observed egress, one row per (workload, destination, port) ───────────────
CREATE TABLE egress.edge (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  src_workload_id bigint NOT NULL REFERENCES egress.workload(id),
  dst_kind       text   NOT NULL,        -- workload | service | fqdn | cidr | entity
  dst_key        text   NOT NULL,        -- 'ns/kind/name' | 'ns/svc' | 'fqdn' | 'cidr' | 'world'
  dst_namespace  text,
  port           int    NOT NULL,
  proto          text   NOT NULL,        -- TCP | UDP | ICMP
  first_seen     timestamptz NOT NULL DEFAULT now(),
  last_seen      timestamptz NOT NULL DEFAULT now(),
  conns_total    bigint NOT NULL DEFAULT 0,
  active_hours   bit(24) NOT NULL DEFAULT B'000000000000000000000000', -- hour-of-day union
  days_seen      smallint NOT NULL DEFAULT 1,
  UNIQUE (src_workload_id, dst_kind, dst_key, port, proto)
);

-- ── short-lived raw aggregates (debugging "what happened at 03:12") ──────────
CREATE TABLE egress.flow_raw_agg (
  ts             timestamptz NOT NULL,
  node           text NOT NULL,
  src_workload_id bigint NOT NULL,
  dst_kind       text NOT NULL,
  dst_key        text NOT NULL,
  dst_namespace  text,
  port           int NOT NULL,
  proto          text NOT NULL,
  verdict        text NOT NULL,
  conns          bigint NOT NULL,
  PRIMARY KEY (ts, node, src_workload_id, dst_kind, dst_key, port, proto, verdict)
) PARTITION BY RANGE (ts);

-- ── long-term trend (180 d) ──────────────────────────────────────────────────
CREATE TABLE egress.flow_hourly (
  bucket          timestamptz NOT NULL,
  src_workload_id bigint NOT NULL,
  dst_kind        text NOT NULL,
  dst_key         text NOT NULL,
  port            int NOT NULL,
  proto           text NOT NULL,
  verdict         text NOT NULL,
  conns           bigint NOT NULL,
  PRIMARY KEY (bucket, src_workload_id, dst_kind, dst_key, port, proto, verdict)
) PARTITION BY RANGE (bucket);

-- ── the review queue: every blocked (or would-be-blocked) flow ──────────────
CREATE TABLE egress.blocked_flow (
  id              bigint GENERATED ALWAYS AS IDENTITY,
  ts              timestamptz NOT NULL,
  src_workload_id bigint REFERENCES egress.workload(id),
  src_namespace   text NOT NULL,
  src_pod         text NOT NULL,
  src_ip          inet,
  dst_ip          inet,
  dst_namespace   text,
  dst_pod         text,
  dst_names       jsonb,                 -- names Cilium knew for the destination
  port            int,
  proto           text,
  direction       text NOT NULL,         -- EGRESS | INGRESS
  verdict         text NOT NULL,         -- DROPPED | AUDIT | ERROR (raw Flow.verdict, not a remapped name)
  drop_reason     text,
  node            text,
  conns           bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- ── policy bookkeeping ──────────────────────────────────────────────────────
CREATE TABLE egress.policy (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  namespace   text NOT NULL,
  name        text NOT NULL,
  mode        text NOT NULL,             -- shadow | enforce | exempt
  generation  int  NOT NULL DEFAULT 1,
  applied_at  timestamptz,
  UNIQUE (namespace, name)
);

CREATE TABLE egress.policy_rule (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  policy_id  bigint NOT NULL REFERENCES egress.policy(id) ON DELETE CASCADE,
  edge_id    bigint REFERENCES egress.edge(id),   -- null for hand-written rules
  rule_kind  text NOT NULL,              -- workload|service|fqdn|cidr|entity|dns|apiserver
  rule_value text NOT NULL,
  source     text NOT NULL DEFAULT 'generated',  -- generated | manual
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE egress.review (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  edge_id    bigint NOT NULL REFERENCES egress.edge(id),
  state      text NOT NULL,              -- expected | unexpected | allowed_forever | ignored
  reason     text NOT NULL,
  decided_by text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);

-- ── views the CLI and the digest use ────────────────────────────────────────
CREATE VIEW egress.v_edge AS
SELECT e.*, w.namespace AS src_namespace, w.kind AS src_kind, w.name AS src_name
FROM egress.edge e JOIN egress.workload w ON w.id = e.src_workload_id;

-- observed but not covered by any shipped rule and not reviewed
CREATE VIEW egress.v_uncovered AS
SELECT v.* FROM egress.v_edge v
WHERE NOT EXISTS (SELECT 1 FROM egress.policy_rule r WHERE r.edge_id = v.id)
  AND NOT EXISTS (SELECT 1 FROM egress.review rv
                  WHERE rv.edge_id = v.id
                    AND rv.state IN ('expected','allowed_forever')
                    AND (rv.expires_at IS NULL OR rv.expires_at > now()));

-- shipped rule with no traffic in 30 days
CREATE VIEW egress.v_stale_rule AS
SELECT r.*, p.namespace, p.name AS policy_name
FROM egress.policy_rule r JOIN egress.policy p ON p.id = r.policy_id
LEFT JOIN egress.edge e ON e.id = r.edge_id
WHERE r.edge_id IS NULL OR e.last_seen < now() - interval '30 days';
```

### 8.2 Retention and size budget

Measured: `kasil-postgres-1` uses **3 203 MiB of 10 000 MiB** (32 %), replica 3 153 MiB. Available headroom ≈ 6.7 GiB for both instances.

| Table | Growth assumption | Retention | Steady state |
|---|---|---|---|
| `edge` | ~60 workloads × ~25 destinations × ports ≈ **1 500–3 000 rows**, not time-based | permanent | < 5 MiB |
| `flow_raw_agg` | ~500 active tuples/min × 1 440 min = 720 k rows/day @ ~120 B (heap + index ≈ 250 B/row), **after** the §7.1 filters drop reply-direction duplicates, DNS/control-plane destinations and the `victoria/vmagent` scrape fan-out; re-measure on day 1 and adjust partition count/retention from the real rate | **48 h** (daily partitions) | ~360 MiB |
| `flow_hourly` *(rejected: every known tuple, every hour)* | 3 000 tuples × 24 = 72 k rows/day @ ~200 B → 14 MiB/day | 180 d | ~2.5 GiB — rejected |
| `flow_hourly` (chosen variant) | only tuples **active in that hour** (≈ 600/h → 14 k rows/day) | 180 d | **~0.5 GiB** |
| `blocked_flow` | 1 k rows/day steady, 20 k/day during incidents | 90 d (monthly partitions) | 30–250 MiB |
| `dns_name` | few hundred names × IPs | 90 d (pruned) | < 5 MiB |

Total ≈ **0.9–1.3 GiB**. Two mitigations already in the design: (a) `flow_hourly` only stores hours with actual traffic, (b) a `VMRule` warning at `kubelet_volume_stats_used_bytes / capacity > 70 %` for the CNPG PVCs, with the fallback of dropping `flow_raw_agg` retention to 24 h, then `flow_hourly` to 90 d. If it still grows, the egress DB moves to its own CNPG cluster on `piraeus-hdd` (7 TiB, kube2) — a 30-minute change, not part of v1.

Retention is enforced by a single `CronJob` (`egress-maintenance`, hourly):
`create next partitions → roll up flow_raw_agg → flow_hourly → drop partitions older than retention → prune dns_name → ANALYZE`.

---

## 9. Phase 1 — audit mode

**Duration:** 7–14 days. **Output:** a markdown report per namespace plus one global summary, generated on demand (and attached to the implementation card when Phase 1 is closed).

### 9.1 Sequence

| Step | Action | Evidence of success |
|---|---|---|
| 1.0 | Baseline snapshot committed: namespace/workload inventory, node capacity, **policy inventory** (§2.1: 0 `CiliumNetworkPolicy`/`NetworkPolicy`; 2 pre-existing cluster objects `via-vpn-isolation`/`via-vpn-egress`; 0 pods matching their selector) | report appendix "before" |
| 1.1 | Enable Hubble (agent + relay) with the values in §7; `hubble.enabled: true` only — **no workload policies yet** (the cluster-wide baseline arrives at 1.2a) | `hubble observe` returns flows; relay pod Running on kube2 |
| 1.2 | Enable `prometheus.enabled` + hubble `policy`/`drop`/`dns`/`flows-to-world`/`flow` metrics + ServiceMonitors | `count(cilium_endpoint_state)`, `hubble_flows_processed_total` and `hubble_dns_queries_total` appear in VictoriaMetrics |
| 1.2a | Apply the **baseline policy now** (`baseline-dns-apiserver`, §10.1). It carries `enableDefaultDeny: false`, so it denies nothing; in Phase 1 its job is the `rules.dns` block, which is what makes Cilium proxy DNS — without an L7 DNS rule on an endpoint, DNS never reaches the proxy and flow logs carry no `l7.dns`, so S2/FQDN attribution would stay empty | `hubble_dns_queries_total` non-zero; a test lookup (`kubectl exec … -- getent hosts api.telegram.org`) appears in `dns-raw` **with its `l7.dns.ips`** |
| 1.3 | Apply the three dynamic exporters (§7.1) | **all three** are instantiated on every node (`hubble_dynamic_exporter_up{name="audit-agg"\|"deny-raw"\|"dns-raw"} == 1`), their files advance, `aggregate.egress_flow_count` is present |
| 1.4 | Deploy P1 infrastructure: `egress` namespace, CNPG `Database` + role + `ExternalSecret`, schema migration Job, `egressd` DaemonSet | `SELECT count(*) FROM egress.edge` grows; `egressd_lines_dropped_total` flat |
| 1.5 | Soak 7–14 days **and actively drive rare paths** (§9.3) | coverage report ≥ 95 % of workloads |
| 1.6 | Generate `egressctl report --all --out reports/` | S1/S2 met; report reviewed by Silvano |

### 9.2 What the report contains

Per namespace (one file), per workload (one table block):

1. **Header** — namespace, workload kind/name, image(s), replicas, node(s), owner, `observed_from`/`observed_to`, first/last flow.
2. **Peers** — table: `destination | kind | port/proto | conns | conns/day | first seen | last seen | hours-of-day | verdict`.
   * `kind` is one of `workload`, `service`, `fqdn`, `cidr`, `entity:kube-apiserver`, `world`.
   * External rows carry both the resolved name and the IP (`dst_name_source = dns | none`).
3. **Fan-out summary** — distinct peers, distinct external peers, distinct ports, top-3 by connections, unusual ports (< 1024 vs > 32768).
4. **Flags** (the part a human reads first):
   * `NO-DNS` — external destination observed by IP only (no name ever resolved).
   * `BROAD` — connects to ≥ 3 distinct external /24s or ≥ 10 external IPs.
   * `CRON-ONLY` — traffic only in one hour-of-day (hidden periodic job → would break silently).
   * `LOW-VOLUME` — < 1 connection/day (the classic "forgot to allow it, only noticed a month later").
   * `UNLABELED` — pod has no `app.kubernetes.io/*` labels (cannot be targeted by a label-selecting policy; needs a label fix first).
   * `PRE-POLICED` — the workload is already selected by a policy this pipeline did not generate (`egressctl` resolves existing `CiliumClusterwideNetworkPolicy`/`CiliumNetworkPolicy` endpoint selectors and `CiliumEgressGatewayPolicy` pod selectors at report time — today only `via-vpn-isolation`/`via-vpn-egress`, §2.1). Its observed edges may be **truncated** (in-cluster attempts already dropped), and a generated policy can only *widen* what that policy allows. Not a blocker, but the allowlist must be reviewed against the existing policy before it is applied (§10.1, §10.5). Expected to be empty at Phase 1 (no pod carries the label); it exists so a newly labelled workload can never be silently mis-audited.
5. **Suggested allowlist** — the `egressctl plan` output for that workload, as a fenced YAML block (not applied).

Global summary: matrix `namespace × destination-kind`, total edges, world-destination top-20, and the gap list.

### 9.3 Driving rare paths (Phase 1 is only as good as the coverage)

A 7-day soak of a homelab misses the weekly/monthly jobs. Before closing Phase 1, deliberately exercise:

* `kasil-cd` reconcile CronWorkflow + a real deploy (touches GitHub, ghcr, Discord/SMTP).
* Renovate/dependabot PR flow (argocd repo-server pulls Helm OCI charts).
* cert-manager renewal (`cmctl renew`, or delete a test Certificate) → ACME out to Let's Encrypt.
* ExternalSecret refresh (`kubectl annotate es … force-sync` timestamp) → Bitwarden.
* rclone/piraeus snapshot job, CNPG backup (if configured).
* Frigate camera reconnect (restart camera or the pod) + a Home Assistant restart (mDNS/discovery).
* A `kasil-check` run, plus one manual `egressctl report` per namespace.

Record the exercised list in the report appendix so a later reader knows what "covered" means.

### 9.4 Acceptance for Phase 1

* S1, S2 from §1 met.
* Every workload has either an allowlist candidate **or** an explicit exemption with a reason (hostNetwork, infra).
* Zero `egressd` ingestion errors over the last 48 h; `hubble_lost_events_total` flat.
* The report is committed (and attached to the card) so Phase 2 diffs against a frozen baseline.

---

## 10. Phase 2 — enforcement

### 10.1 Policy model

One `CiliumNetworkPolicy` per workload, egress-only, named `<workload>-egress`, living in `kasil-apps/apps/egress/policies/<namespace>/<workload>.yaml`. Plus a small set of cluster-wide policies.

**Always-allowed baseline (applied first, cluster-wide — at the start of Phase 1, §9.1 step 1.2a):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: baseline-dns-apiserver
spec:
  description: >-
    DNS to kube-dns and apiserver access for every pod. Applied before any
    workload policy so a new default-deny never breaks DNS or the API.
  endpointSelector: {}          # all pods
  enableDefaultDeny:
    egress: false               # baseline never switches endpoints to deny by itself
    ingress: false
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - {port: "53", protocol: UDP}
            - {port: "53", protocol: TCP}
          rules:
            dns:
              - matchPattern: "*"
    - toEntities: [kube-apiserver]
      toPorts:
        - ports: [{port: "443", protocol: TCP}]
```

Why `enableDefaultDeny: false` on the baseline: a cluster-wide policy selecting *all* pods would otherwise put the entire cluster into default-deny egress in one apply — the exact outage this design exists to avoid. Individual workload policies enable default-deny.

Why it is applied in Phase 1 rather than Phase 2: the `rules.dns` block is what makes Cilium redirect an endpoint's DNS to the DNS proxy. Without an L7 DNS rule, DNS is not proxied, no flow carries `l7.dns`, and the DNS inventory (`egress.dns_name`, S2) is empty. Applying the baseline on day 1 installs the proxy path early — with `enableDefaultDeny: false` nothing is denied — so Phase 1 gets real names and Phase 2 does not introduce the proxy as a new risk.

**Per-workload policy (the shape `egressctl plan` emits):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: frigate-egress
  namespace: frigate
  annotations:
    egress.kasil.io/generated-from: "edge-set 2026-12-07T10:00Z"
    egress.kasil.io/review: "approved by silvano 2026-12-07"
spec:
  description: "egress allowlist for frigate (Deployment/frigate)"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/instance: frigate
      app.kubernetes.io/name: frigate
  enableDefaultDeny:
    egress: true                 # false during the shadow window
  egress:
    # in-cluster peers, addressed by workload labels
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: nanomq
            app.kubernetes.io/name: nanomq
      toPorts:
        - ports: [{port: "1883", protocol: TCP}]
    # LAN devices (identity world) — cameras, no DNS name
    - toCIDR:
        - 192.168.31.10/32
        - 192.168.31.11/32
      toPorts:
        - ports:
            - {port: "80",   protocol: TCP}
            - {port: "554",  protocol: TCP}
            - {port: "1935", protocol: TCP}
    # named external services
    - toFQDNs:
        - matchName: api.telegram.org
      toPorts:
        - ports: [{port: "443", protocol: TCP}]
```

Rule-generation rules (deterministic, so reviewers can trust the output):

| Observed | Emitted |
|---|---|
| dst is a pod/workload in the same or another namespace | `toEndpoints` with that workload's selector labels (`app.kubernetes.io/name` + `instance` when present, else `app`/`k8s-app`) |
| dst resolves to a Service and the peer is a workload in another ns | `toServices: [{k8sService: {namespace, serviceName}}]` when the service name is known from the flow, else `toEndpoints` |
| dst IP ∈ cluster CIDR but no workload (e.g. node-local service) | flagged `NO-OWNER`, needs manual rule |
| dst has a DNS name | `toFQDNs.matchName` (exact), or `matchPattern` only after human approval |
| dst is an IP in `192.168.0.0/16` or RFC1918 outside the cluster | `toCIDR /32` + review flag |
| dst is `world` with no name | **never auto-emitted**; the workload stays in shadow until a human decides CIDR or drops it |
| apiserver | covered by the baseline; not repeated per workload |

**Policies this pipeline did not generate — a hard upper bound.** The cluster already runs `CiliumClusterwideNetworkPolicy/via-vpn-isolation` and `CiliumEgressGatewayPolicy/via-vpn-egress` (§2.1). Cilium policy is additive: the effective policy of an endpoint is the union of every policy that selects it. A generated `<workload>-egress` CNP therefore never replaces `via-vpn-isolation`; for a labeled workload it is combined with it, and because the generated policy is the permit side, the union can only **add** allowed peers — re-opening precisely the cluster-internal egress the isolation denies. The tooling treats every pre-existing selecting policy as a constraint:

| Command | Behaviour with pre-existing policies |
|---|---|
| `plan` | Resolves all `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy` and `CiliumEgressGatewayPolicy` objects that select the workload. With none, generation is unchanged. With one, the plan emits rules **only** for peers that policy already permits; observed edges outside it are printed as `pre-policed-dropped` (traffic that was already denied, never a rule). If the existing policy does not enable egress default-deny (so it constrains nothing), generation is skipped and the workload is reported `PRE-POLICED` for a human decision. The generated file carries `egress.kasil.io/pre-policed: <kind>/<name>`. |
| `lint` | Fails when a candidate CNP's egress rules are not a subset of what **every** existing selecting policy allows — i.e. when the union would widen the endpoint's allowed set. The only escape is explicit: `--ack-pre-policed <kind>/<name>` records the acknowledgement in the policy header and requires the reviewed diff to show the widening. Default is fail. |
| `diff` | Prints the pre-existing policy as a constraint block: its allowed peers/ports, the observed edges inside it, and the observed edges outside it (already dropped — they are evidence, not candidates for allow). |

In practice `via-vpn-isolation`'s `toEntities: [world]` (all ports) leaves external traffic essentially unconstrained; the part that bites is its DNS-only in-cluster half — so the widening risk this rule exists to stop is **peer-to-peer**, not FQDN.

The egress gateway is **reported, not policed**: `via-vpn-egress` does not filter traffic, it decides which source IP the world sees (`192.168.20.50`) for pods labelled `kasil.cloud/via-vpn=true`, with RFC1918 excluded. For any such pod the report annotates its world edges `via-egress-gateway=192.168.20.50`, and the gateway IP itself is never turned into a policy rule. A gateway that shows up as an anomaly in the inventory is a reporting bug, not a destination.

### 10.2 Rollout rings

Every ring follows: **generate → shadow → soak → enforce → verify**.

| Ring | Namespaces | Shadow | Why this order |
|---|---|---|---|
| 0 | `test-cd`, `check` | 24 h | canary, no user impact |
| 1 | `mcp`, `auth`, `vikunja`, `honcho`, `zigbee2mqtt`, `nanomq`, `homeassistant` (pod workloads only) | 3–7 d | stateless / single-dependency apps |
| 2 | `frigate`, `victoria` (vmagent excepted, §10.4), `argocd`, `argo`, `argo-events`, `cert-manager`, `external-secrets`, `cloudflare-tunnel`, `ddns-route53`, `rclone`, `cnpg-system` | 7 d | platform: a mistake here breaks deploys, certs, DNS or monitoring |
| 3 (opt) | `hermes` | 7 d | widest external surface; do it last, with a long shadow |
| exempt | `kube-system`, `piraeus-datastore`, `victoria/vmagent` | — | CNI/storage control plane + scrape fan-out; documented in §10.4 |

`hermes` deserves a note: it is the workload with the largest and most volatile external dependency set (every LLM provider, GitHub, email, messaging, Home Assistant, MCP endpoints). Doing it last is deliberate; its policy will be mostly `toFQDNs` and it will need the longest shadow window.

### 10.3 Shadow mechanics

**Per-policy shadow (primary).** Commit the generated policy with `enableDefaultDeny.egress: false`. The rules exist, traffic is allowed, and anything that does *not* match is forwarded with `policy_match_type == 4`. Two ways to see the gaps:

* `egressctl diff --ns <ns>` — compares the live `edge` table with the shipped `policy_rule` rows. Deterministic, instant, no verdict dependency. **This is the gate for flipping to enforce.**
* `hubble observe --verdict FORWARDED --cel-expression '_flow.policy_match_type == uint(4)'` (or the equivalent `edge` rows when `policy_match_type` is retained) — the live cross-check.

**Cluster-wide audit (once, optional).** For the very first batch only, `policyAuditMode: true` for ≤ 72 h gives `AUDIT` verdicts for *everything* that would be dropped, including policies written by someone else later — which is also its danger: audit mode disables enforcement for the whole agent. Rules: time-boxed, announced, and followed by an explicit `policyAuditMode: false`. Do not leave it on as a "safety net" — an alert (`EgressAuditModeLeftOn`) fires if it is still enabled after 72 h.

**Flip to enforce** = `enableDefaultDeny.egress: true` in one commit, `mode: enforce` recorded in `egress.policy`, then 24 h of deny watch on `hubble_policy_verdicts_total{action="dropped",direction="egress"}` for that namespace.

### 10.4 Exemptions (documented, not forgotten)

| Subject | Policy | Rationale |
|---|---|---|
| `kube-system` (cilium, coredns, operator, metrics-server, snapshot-controller) | allow-all egress CCNP with `endpointSelector` on the namespace label, `enableDefaultDeny: {egress: false}` — i.e. an explicit, visible no-op | CNI/DNS control plane; a mistake takes the cluster down and there is nothing to gain |
| `piraeus-datastore` | same | LINSTOR/CSI; DRBD replication is kernel-level (host netns) and unaffected either way |
| `homeassistant-hass`, `music-assistant-server` (**hostNetwork**) | **not policed** by v1; documented in the report as a gap | they are not Cilium endpoints; pod policies cannot select them (§10.8) |
| `victoria/vmagent` (**the scraper**) | exempt from a generated policy in v1 | its egress is the cluster-wide scrape fan-out by design (every ServiceMonitor target, node-exporter and kubelet): it is excluded from `audit-agg` (§7.1), so there is no inventory to generate from, and "allowlist the scraper" degenerates into allow-all anyway. The rest of `victoria` (grafana, vmalert, vmsingle, kube-state-metrics, operators) is audited and policed normally |

Exemptions are *files in Git* with a comment explaining why, not tribal knowledge.

### 10.5 Failure modes to design against

| Failure | Symptom | Guard |
|---|---|---|
| DNS blocked | everything times out; coredns unreachable | baseline CCNP applied **before** any workload policy; `EgressDnsBroken` alert on `hubble_dns_queries_total` drop |
| DNS never proxied (no L7 rule on the endpoint) | `dns-raw` rows exist but carry no `l7.dns`; every external destination shows `NO-DNS` and `egress.dns_name` stays empty | baseline DNS rule applied at Phase 1 start (§9.1 1.2a); day-1 check `hubble_dns_queries_total > 0` and a test lookup visible with its IPs |
| FQDN rule without DNS rule | the name is never resolved, `toFQDNs` never matches | `egressctl plan` always emits the DNS rule alongside `toFQDNs`; `egressctl lint` rejects a policy with `toFQDNs` and no `rules.dns` |
| Peer addressed by pod IP | new pod IP after restart → denied | generator never emits pod-IP rules; only `toEndpoints`/`toServices`/`toFQDNs`/`toCIDR` |
| Policy selects a CronJob pod that no longer exists | rule silently unused | `v_stale_rule` weekly digest |
| One policy per workload drift (two policies same workload) | rules combine, default-deny flag precedence surprises | `egressctl lint` fails if > 1 CNP selects the same workload |
| **A pre-existing policy selects the workload** (`via-vpn-isolation`) | the inventory reads as flat, but the workload's edges are truncated (in-cluster attempts already dropped); a generated CNP unions with the isolation and **widens** it, re-opening cluster-internal egress | `PRE-POLICED` flag in the report (§9.2); `plan` treats existing selectors as an upper bound and skips unless every rule is a subset; `lint` fails on widening; `diff` prints the constraint; override only with `--ack-pre-policed` and a reviewed diff (§10.1) |
| **Egress gateway mistaken for a destination** (`via-vpn-egress`) | a labeled pod's world traffic is SNATed to `192.168.20.50`; the peer sees the gateway, and RFC1918 is excluded from it | report annotates affected workloads `via-egress-gateway=192.168.20.50` and groups them under `PRE-POLICED`; the gateway IP is never emitted as a rule (§10.1) |
| kubelet probes (ingress, future) | pod never Ready | out of scope here; documented in §13 Q/A and in the skill's pitfall list |
| Rollback needed | app broken | `kubectl delete cnp <name>` (or revert the commit) — default-deny disappears with the last policy, verified in ring 0 |

### 10.6 `policy-deny-response`

From ring 0 onwards set `policyDenyResponse: icmp`. Default `none` makes a denied connection hang until the app's own timeout (curl: "Connection timed out"), which is indistinguishable from a network fault. With `icmp`, clients fail fast ("Packet filtered" / `curl: (7)`), which shortens MTTR and makes the deny visible in application logs too. Caveat: experimental, IPv4 egress only, and **if ingress policies are ever added, ICMP ingress must be allowed** or the ICMP rejection itself is dropped.

### 10.7 Verification per namespace

```bash
# 1. what is denied right now (workload labels attached)
egressctl verify --ns frigate --since 1h

# 2. the same from metrics (`source` is the workload label from sourceContext;
#    `action` is the lowercased flow verdict, so a policy denial is "dropped")
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode \
  'query=sum by (source_namespace,source,destination,direction,match) (
     rate(hubble_policy_verdicts_total{action="dropped",direction="egress"}[5m]))'

# 3. live drops from the datapath (per node)
kubectl -n kube-system exec ds/cilium -- cilium-dbg monitor --type drop

# 4. did the policy land in the datapath
kubectl -n kube-system exec ds/cilium -- cilium-dbg endpoint get <ep> -o json | jq .status.policy
```

### 10.8 hostNetwork workloads — the documented gap

`homeassistant-hass` and `music-assistant-server` run in the node network namespace (`hostNetwork: true`, IPs equal to kube4/kube2). Consequences:

* `CiliumNetworkPolicy.endpointSelector` cannot select them (they are the `host`/`remote-node` identity, not pod endpoints).
* Policing them requires `CiliumClusterwideNetworkPolicy` + `nodeSelector` **with host firewall** (`enable-host-firewall: true`), which also polices kubelet, CNI and storage traffic on that node — a much bigger hammer, and it would affect every hostNetwork pod on those nodes.
* v1 therefore leaves them unpoliced and **says so in the report**, so the gap is visible rather than assumed.

Follow-up option (separate card): move Home Assistant off `hostNetwork` (needs `hostPort` for discovery/mDNS or a `macvlan`/L2 announcement design) before attempting host-level policy. That is a real project on its own, not a footnote.

### 10.9 Threat model: what actually changes

This is the *why*, in concrete terms. Today, from inside any pod on the cluster, a compromised process can reach all of the following without a workload policy in the way — the only egress policy in the cluster, `via-vpn-isolation`, selects no running pod (§2.1):

| Target | What an attacker gets today | After egress allowlists |
|---|---|---|
| `cnpg-system/kasil-postgres-rw:5432` | every database whose password sits in a mounted secret or env of the compromised pod; a brute-force target for the rest | only the workloads whose allowlist names it (auth, vikunja, honcho, grafana, …) |
| `argocd/argocd-server:443` | the deploy control plane, with the app controller's cluster-wide RBAC behind it | argocd's own pods and the pipeline only |
| `kube-apiserver:443` | whatever the *attacker's* service account permits — from any pod, including ones that should never speak to the API | still the SA's RBAC, but only for pods that need the API at all; every other attempt is logged |
| `192.168.31.10/.11` (cameras) | live video and, on many consumer cameras, admin credentials | frigate only |
| `192.168.20.2/.3` (routers) | the network edge — the most valuable lateral target in a home LAN | the routers probe only |
| the internet, any port | C2, exfiltration, crypto-mining, scanning | only the named FQDNs/ports each workload actually uses |
| every other pod | flat lateral movement — no workload policy selects any pod | nothing, unless the allowlist says so |

The realistic incident in this cluster is not an APT: it is a compromised container image, a malicious chart, or a prompt-injected agent. All three land as *one workload on a flat network*. Egress allowlisting is the control that turns that from "whole cluster + whole LAN" into "one workload's own dependencies" — and it produces the inventory that any further segmentation (ingress policy, host firewall, moving Home Assistant off `hostNetwork`) will need.

---

## 11. Blocked-traffic logging and the review loop

This is requirement R3/R8 and deserves its own section because "log the blocks" is where these rollouts usually rot.

### 11.1 Three layers, deliberately

| Layer | Mechanism | Latency | Question answered |
|---|---|---|---|
| L1 raw | `deny-raw` exporter → `egress.blocked_flow` | seconds | "what exactly was blocked, from which pod/node, to which IP/name/port?" |
| L2 aggregate | `hubble_policy_verdicts_total{action="dropped",direction="egress"}` + `hubble_drop_total{reason="POLICY_DENIED"}` | 30 s scrape | "is this happening now, how bad, on which workload?" |
| L3 digest | weekly SQL report → `EgressDenyDigest` | 7 d | "what is new since I last looked, and is anything still unreviewed?" |

### 11.2 Alert rules (concrete)

```yaml
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMRule
metadata:
  name: egress-alerts
  namespace: egress
spec:
  groups:
    - name: egress
      rules:
        - alert: EgressDenyUnknown
          # Fires on ANY denial, on purpose: whether it is a new legitimate need
          # or a rule/precedence bug is decided in SQL by `egressctl verify`
          # (blocked_flow joined with policy_rule). Keeping the PromQL free of
          # joins means the alert cannot silently stop working on a label drift.
          expr: |
            sum by (source_namespace, source, destination, direction) (
              increase(hubble_policy_verdicts_total{action="dropped", direction="egress"}[15m])
            ) > 0
          for: 10m
          labels: {severity: warning}
          annotations:
            summary: "egress denied for {{ $labels.source_namespace }}/{{ $labels.source }} → {{ $labels.destination }}"
            runbook: "docs/runbooks/egress-deny.md"

        - alert: EgressDenySpike
          expr: |
            sum by (source_namespace, source) (
              increase(hubble_policy_verdicts_total{action="dropped", direction="egress"}[5m])
            ) > 30
          for: 5m
          labels: {severity: critical}
          annotations: {summary: "deny spike for {{ $labels.source_namespace }}/{{ $labels.source }} (possible compromise or broken dependency)"}

        - alert: EgressExporterMissing
          # A bad fieldMask/filter makes dynamicExporter.applyUpdatedConfig log
          # "Failed to create exporter for config" and skip that exporter while
          # config_hash/_config_last_applied still advance. Only these gauges show it.
          expr: min by (instance) (hubble_dynamic_exporter_exporters_total{status="active"}) < 3
          for: 15m
          labels: {severity: critical}
          annotations:
            summary: "{{ $labels.instance }} has {{ $value }} of 3 egress flow-log exporters active — capture (and the review queue) is incomplete"

        - alert: EgressCollectorStale
          expr: time() - max(egressd_last_write_timestamp_seconds) > 300
          for: 5m
          labels: {severity: critical}
          annotations: {summary: "egressd has not written to Postgres for >5m — deny history is being lost"}

        - alert: EgressExporterDrops
          expr: increase(hubble_lost_events_total[15m]) > 0
          for: 15m
          labels: {severity: warning}
          annotations: {summary: "Hubble ring buffer overflowed on {{ $labels.instance }} — raise eventBufferCapacity or narrow the exporter filters"}

        # Guard for the one global switch that disables enforcement everywhere.
        # Implemented as a CronJob (`egress-audit-guard`) that reads the effective
        # agent configuration and exits non-zero once policyAuditMode has been
        # enabled for more than 72 h; the stack already pages on failed Jobs
        # (KubeJobFailed / kube_cronjob_status_last_successful_time).
        # Cilium 1.20.5 exposes no verified per-agent Prometheus metric for audit
        # mode, so no metric is invented here.

        - alert: EgressPostgresFillingUp
          expr: |
            max(kubelet_volume_stats_used_bytes{namespace="cnpg-system"}
                / kubelet_volume_stats_capacity_bytes{namespace="cnpg-system"}) > 0.70
          for: 1h
          labels: {severity: warning}
          annotations: {summary: "CNPG volume >70% — review egress retention (§8.2)"}
```

Alert design notes:

* `EgressDenyUnknown` pages on **any** denial. In a healthy enforced namespace there are none, so the noise floor is zero by construction; if it fires every day the policy is under-specified, which is exactly the signal wanted.
* Suppression lives in the digest, not in the alert: `egressctl verify --since 7d` joins `blocked_flow` with `policy_rule` and `review` and prints three buckets — *uncovered* (new need), *covered-but-denied* (rule/precedence bug), *reviewed/ignored* (expected).
* `EgressCollectorStale` protects the **record**, not the traffic: if `egressd` stops writing, denials still happen but the review queue silently empties.

### 11.3 Review workflow

1. `EgressDenyUnknown` fires (or the weekly digest lists new denies).
2. `egressctl explain <id>` prints the `blocked_flow` row with workload, pod, node, dst IP, dst names, port, first/last, count, and the nearest existing rules.
3. Decide with `egressctl review <edge> --state expected|unexpected|allowed_forever|ignored --reason "renovate now uses api.github.com"`:
   * `expected` → a rule was *supposed* to allow it → bug in the policy → open a commit.
   * `allowed_forever` → legit permanent need → add the rule (and the review row stops the alert from re-firing).
   * `ignored` → known-benign noise (e.g. a health-check IP) → suppressed for `expires_at`.
   * `unexpected` → **security event**: keep it denied, escalate (this is the case the whole design exists to make visible).
4. `egressctl plan --ns <ns>` regenerates the delta into a staging directory; a human reviews the diff and commits.

The review state lives in `egress.review` keyed by edge, so the decision survives pod restarts and is auditable ("who allowed this, when, why").

### 11.4 Weekly digest

CronJob (Mondays 07:00, Europe/Dublin) → SQL:
new denies (7 d), unreviewed edges (sorted by first_seen), stale rules (30 d unused), denied-but-covered anomalies, collector/agent health, coverage % per namespace → markdown → `hermes` mail tool / Discord webhook. Cheap, and it turns "periodically review" into an inbox item rather than a good intention.

---

## 12. Implementation plan (for the follow-up card)

| # | Work item | Deliverable | Days |
|---|---|---|---|
| 1 | Cilium values: Hubble on, relay pinned to kube2, metrics + ServiceMonitors, exporters | PR to `kasil-apps/apps/cilium`; verified in TSDB | 0.5 |
| 2 | `egress` database + role + `ExternalSecret` + schema migration Job | PR to `kasil-apps/apps/cnpg` + `apps/egress` | 0.5 |
| 3 | `egressd` MVP: tailer, JSON envelope parser, pod→workload resolver, batched upserts, `/metrics`, offsets checkpoint | repo `kasil-egress` (Go, arm64, distroless) | 2.0 |
| 4 | Schema + partitioning + `egress-maintenance` CronJob + retention | SQL migrations + Job | 1.0 |
| 5 | `egressctl report` (markdown/CSV/JSON, flags, coverage, live policy-inventory lookup for `PRE-POLICED`) | CLI + report templates | 1.5 |
| 6 | `egressctl plan` / `diff` / `lint` / `verify`, including the **never-widen** constraint against pre-existing selecting policies (§10.1) | CLI + golden-file tests | 1.8 |
| 7 | Grafana dashboard + `VMRule` alerts + digest CronJob | JSON dashboard, VMRule, CronJob | 1.0 |
| 8 | GitOps wiring (`apps/egress` app entry, namespace, RBAC) + baseline CCNP (§10.1, needed from Phase 1 step 1.2a) + runbooks | PR + `docs/runbooks/*` | 0.5 |
| | **Engineering total** | | **~8.8** |
| — | Phase 1 soak (calendar) | report | 7–14 d |
| — | Phase 2 rings 0–2 (calendar, ~3 d of work) | enforced policies | 2–3 wk |

Sequencing constraint: item 1 must land before 3 (the exporter has to produce something to parse); item 2 before 3 as well. 5 and 6 can be developed against a fixture set of exported flow files (the test suite must not require a live cluster).

Rollback: every step is reversible — Cilium values revert to `hubble.enabled: false`; the app can be removed from `apps/apps/values.yaml` (ArgoCD prune); the database can be dropped without touching other databases.

---

## 13. Risks, and the decisions I need from you

### Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| kube3 runs out of memory after enabling Hubble | medium | node eviction / cluster flakiness | measure after enabling on kube3 first; cap `fileMaxSizeMb`, keep relay off kube3, set relay/agent resource limits, watch `KubeMemoryPressure` |
| Flow volume higher than modelled (DRBD/camera/reconciliation) | medium | Postgres growth, CPU on agents | exclude `kube-system`/`piraeus-datastore` destinations and the `victoria/vmagent` scraper, drop reply-direction flows, aggregate at 60 s, 48 h raw retention; re-measure day 1 (§8.2) |
| An app breaks after enforcement and is only noticed hours later | medium | user-visible outage | shadow per policy + `egressctl diff` gate + rings + immediate `kubectl delete cnp` rollback + deny alert |
| FQDN policies fail silently after a DNS outage | low-medium | app can't reach external service after DNS blip | Cilium keeps the last resolved IP set; alert on `hubble_dns_queries_total` drop; reviewers see `NO-DNS` flags in Phase 1 |
| Someone leaves `policyAuditMode: true` | medium | **security control silently off** | `egress-audit-guard` CronJob fails after 72 h (pages on the existing failed-Job alert) + it is a one-line diff in Git, reviewable |
| hostNetwork workloads remain unpoliced | certain | accepted gap | documented in the report; separate follow-up card |
| The tool becomes unmaintained (like Otterize's OSS) | low (it's ours) | n/a | it is ~1 kLOC with fixtures; publish so it can outlive the homelab |
| Reviewer fatigue → blanket `world` allows | medium | policy becomes theatre | `egressctl lint --no-world-broad` fails CI on `/0` or wide CIDRs; weekly digest shows the ratio of `world` rules |

### Decisions I need from you before implementation (Q1–Q7)

1. **Retention defaults** — raw 48 h, hourly 180 d, blocked 90 d, DNS 90 d. OK, or do you want longer/shorter anywhere? (Longer `blocked_flow` is the cheap one to extend.)
2. **Hubble UI** — off in v1 (CLI + Grafana via port-forward/ingress)? Enabling it adds a browser-facing service and a `backend`+`frontend` pod (~120 MiB).
3. **kube3 memory** — accept ~40–80 MiB per agent node and pin relay to kube2? Or keep Hubble off kube3 (which would blind that node's flows — I do not recommend it)?
4. **hostNetwork workloads** — confirm "out of scope for v1, documented gap" is acceptable, and whether you want a follow-up card to move Home Assistant onto the pod network.
5. **Exemptions** — OK that `kube-system` and `piraeus-datastore` get a documented allow-all (visible no-op policies) in v1?
6. **Publishing** — create a new repo `snbuback/kasil-egress` (Apache-2.0: `egressd`, `egressctl`, Helm chart, docs) when implementation starts, or keep the code inside `kasil-apps` (as a chart + a `tools/` dir)? I recommend the separate repo — it is generic tooling, and the design doc becomes its ADR.
7. **Phase 1 window** — 14 days with the "drive rare paths" checklist (§9.3) before any enforcement, or shorter (7 days) accepting a higher chance of one surprise in Phase 2?

Defaults if you don't want to answer each: 48 h / 180 d / 90 d · UI off · relay on kube2 · hostNetwork documented gap · infra exemptions yes · separate repo · 14 days.

---

## 14. Publishing (if we build)

Repo layout for `snbuback/kasil-egress`:

```
README.md                  # what/why/quickstart, screenshot of a report
LICENSE                    # Apache-2.0
docs/design.md             # this document, cleaned up as the ADR
docs/runbooks/egress-deny.md
cmd/egressd/               # DaemonSet collector
cmd/egressctl/             # report/plan/diff/lint/verify/review
pkg/flow/                  # Hubble envelope → normalized Edge (with fixtures)
pkg/k8s/                   # pod→workload resolution (informer + ownerRefs)
pkg/pg/                    # schema, migrations, batched upsert
pkg/policy/                # CNP generator + linter
deploy/helm/egress/        # egressd DaemonSet, CronJobs, ServiceMonitor, VMRule, dashboard
testdata/flows/            # real (redacted) exporter fixtures for tests
```

What makes it worth publishing rather than keeping private:

* It is **not kasil-specific**: any Cilium cluster with Postgres and a flow-log exporter can use it. Only the Helm values reference our CIDRs/labels.
* The existing generators (§5 Option B) either forget history (`cpg` streams drops), forget FQDNs (`cf2cnp` has them but is 8 stars and file-only), or need Loki (`hubble-audit2policy`). The gap — *durable per-workload inventory + FQDN/LAN attribution + a review queue* — is real and unoccupied.
* Prior art to credit and reuse ideas from: `SoulKyu/cpg` (audit-window ergonomics, `kubectl krew` packaging), `onzack/cf2cnp` (FQDN + DNS-rule pairing), Cilium CFP-37472 (the aggregation feature this design leans on).

Not publishing: the kasil-specific policy set (namespace list, camera IPs, internal hostnames) stays in `kasil-apps`.

---

## Appendix A — full Cilium values diff

```yaml
# apps/cilium/values.yaml — add/change only these keys.
# The file nests everything under the chart root `cilium:`; today it ends at
# `cilium.hubble.enabled: false`, so this diff indents the whole block by two.
cilium:
  hubble:
    enabled: true                      # was false
    relay:
      enabled: true
      resources:
        requests: {cpu: 30m, memory: 64Mi}
        limits:   {cpu: 300m, memory: 192Mi}
      nodeSelector:
        kubernetes.io/hostname: kube2.kasil.cloud
    ui:
      enabled: false
    metrics:
      enabled:
        - "policy:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|dns|reserved-identity;labelsContext=source_namespace,destination_namespace,traffic_direction"
        - "drop:sourceContext=workload-name|reserved-identity;destinationContext=workload-name|dns|reserved-identity"
        - "dns"
        - "flows-to-world:port;syn-only"
        - "flow"
      enableOpenMetrics: false
      serviceMonitor:
        enabled: true
    export:
      dynamic:
        enabled: true
        config:
          createConfigMap: true
          content:                      # full blocks (filters, fieldMask) in §7.1
            - name: audit-agg
              filePath: /var/run/cilium/hubble/audit-agg.log
            - name: deny-raw
              filePath: /var/run/cilium/hubble/deny-raw.log
            - name: dns-raw
              filePath: /var/run/cilium/hubble/dns-raw.log

  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true

  policyAuditMode: false                # temporarily true only inside a smoke window
  # policyDenyResponse: icmp            # uncomment from Phase 2 ring 0
```

## Appendix B — `egressd` behaviour contract

| Aspect | Contract |
|---|---|
| Input | files under `/var/run/cilium/hubble/` on the host (read-only hostPath), one JSON object per line |
| Envelope | `{"flow": {...}}` (dynamic exporter) and bare flow objects (static exporter) — both accepted |
| Dedup | only `traffic_direction == EGRESS` contributes to `edge`; ingress-side records are discarded (per-node duplication, CFP-37472 non-goal) |
| Identity | pod → workload by `flow.source.workloads` when present, else by informer lookup of the pod UID; unresolved pods land in `workload(kind='Pod')` and are flagged |
| Batching | 500 rows / 2 s, `INSERT … ON CONFLICT DO UPDATE` (edge counters additive, `active_hours` bitwise OR, `last_seen` max) |
| Offsets | checkpoint per (node, file, inode) every 5 s in `egress.ingest_offset`; on restart resumes at the offset, on rotation starts at 0 |
| Backpressure | bounded channel (10 k events); on overflow increment `egressd_lines_dropped_total` and **do not block the tail** (losing lines is visible; blocking the agent's disk writes is not) |
| Metrics | `egressd_lines_read_total{file}`, `egressd_lines_dropped_total{reason}`, `egressd_upsert_seconds` (histogram), `egressd_last_write_timestamp_seconds`, `egress_edge_allowlisted{namespace,source_workload,allowed}` (dashboard: coverage per workload) |
| Resources | requests 20m/48Mi, limits 300m/160Mi |
| Failure mode | if Postgres is down: buffer to a 32 MiB on-disk spool under `/var/lib/egressd` (emptyDir→hostPath), replay on reconnect, then alert if the spool exceeds 8 MiB |

## Appendix C — report mock (shape only; numbers are illustrative, not measured)

```markdown
## namespace: frigate

### Deployment/frigate  (replicas 1, node kube2, image ghcr.io/blakeblackshear/frigate:0.18.x)
observed 2026-11-24T09:12Z → 2026-12-08T09:12Z

| destination | kind | port/proto | conns | conns/day | first seen | last seen | hours | flags |
|---|---|---|---|---|---|---|---|---|
| nanomq/nanomq | workload | 1883/TCP | 41 233 | 2 945 | 11-24 09:12 | 12-08 09:10 | 00-23 | |
| 192.168.31.10 (camera-east) | cidr | 80/TCP | 1 988 | 142 | 11-24 09:14 | 12-08 09:11 | 00-23 | NO-DNS |
| 192.168.31.10 | cidr | 1935/TCP | 1 970 | 141 | 11-24 09:14 | 12-08 09:11 | 00-23 | NO-DNS |
| api.telegram.org → 149.154.x.x | fqdn | 443/TCP | 412 | 29 | 11-24 10:02 | 12-08 08:55 | 05-23 | |
| pool.ntp.org → 162.159.x.x | fqdn | 123/UDP | 28 | 2 | 11-24 09:20 | 12-08 09:00 | 00-23 | LOW-VOLUME |

fan-out: 6 peers (3 external) · top: nanomq 41 k · flags: NO-DNS (2)

suggested policy (review, not applied):
  (fenced CNP YAML as in §10.1)
```

## Appendix D — static hypothesis of external dependencies (to be confirmed by Phase 1)

Derived from the manifests in `kasil-apps` today — **not** from flows. Useful as a sanity check: if Phase 1 does not see these, something is misconfigured; if it sees more, that is exactly the point of the exercise.

| Namespace | Expected external/LAN destination | Source |
|---|---|---|
| `argocd` | `github.com:443`, Helm chart registries (HTTPS/OCI), `auth.k8s.kasil.cloud` | Application repoURLs, OIDC config |
| `cert-manager` | `acme-v02.api.letsencrypt.org:443`, DNS-01 provider API | ClusterIssuer |
| `cloudflare-tunnel` | `api.cloudflare.com`, Cloudflare edge (QUIC 7844), ingress LB `192.168.20.40:443` | chart values |
| `ddns-route53` | AWS Route53 API `:443` | chart values |
| `external-secrets` | `bitwarden-sdk-server` (in-cluster) → Bitwarden cloud `:443` | ClusterSecretStore |
| `frigate` | cameras `192.168.31.10`, `192.168.31.11` (80/554/1935), NTP, internet (telemetry) | `values.yaml` |
| `hermes` | every configured provider (OpenRouter, Anthropic, GitHub, Exa/Brave, Discord, Telegram, Google/Microsoft APIs, Home Assistant, honcho, MCP endpoints) | `/opt/data/.env`, `config.yaml` |
| `honcho` | `openrouter.ai:443`, Postgres `kasil-postgres-rw:5432` | chart values |
| `routers` | `192.168.20.2`, `192.168.20.3` | `values.yaml` |
| `rclone` | object-storage providers `:443` | chart values |
| `vikunja`, `auth` | Postgres, SMTP, `auth.k8s.kasil.cloud` | chart values |
| `zigbee2mqtt` | MQTT broker, coordinator `192.168.1.12:6638` (suspicious — likely the wrong subnet) | `values.yaml` comment |
| `victoria` | `grafana.net` (plugin downloads), Alertmanager receivers (Discord/SMTP) | chart values |
| `homeassistant` | LAN devices (mDNS/SSDP/DHCP), cloud integrations — **hostNetwork, unpoliced** | `values.yaml` |

## Appendix E — verification commands (day-1 checks for the implementation card)

```bash
# Hubble is really on and the relay sees all four nodes
kubectl -n kube-system exec ds/cilium -- cilium-dbg status --all-health | grep -i hubble
kubectl -n kube-system exec deploy/hubble-relay -- hubble status

# exporters are writing and aggregating — check all three, per node
# (a bad fieldMask/filter silently skips an exporter: "Failed to create exporter for config")
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode \
  'query=hubble_dynamic_exporter_up{name=~"audit-agg|deny-raw|dns-raw"}'
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode \
  'query=hubble_dynamic_exporter_exporters_total'
kubectl -n kube-system logs ds/cilium -c cilium-agent --since=30m | grep -i 'Failed to create exporter'
for f in audit-agg deny-raw dns-raw; do
  kubectl -n kube-system exec ds/cilium -- sh -c "tail -1 /var/run/cilium/hubble/$f.log | wc -c"
done

# metrics landed in VictoriaMetrics
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode 'query=count(cilium_endpoint_state)'
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode 'query=label_set(hubble_policy_verdicts_total)'

# DNS really goes through the proxy (otherwise dns-raw has port-53 flows but no l7.dns, so no names)
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode 'query=sum(rate(hubble_dns_queries_total[5m]))'
kubectl -n kube-system exec ds/cilium -- sh -c 'grep -m1 "\"dns\"" /var/run/cilium/hubble/dns-raw.log' \
  || echo 'NO l7.dns in dns-raw — DNS proxy is not in the path, see §9.1 step 1.2a'

# collector is keeping up
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode 'query=egressd_last_write_timestamp_seconds'
psql "$EGRESS_DSN" -c "select count(*), max(last_seen) from egress.edge;"
psql "$EGRESS_DSN" -c "select verdict, count(*) from egress.blocked_flow group by 1;"

# policy inventory: what already selects what (the via-vpn objects must match 0 pods at day 1)
kubectl get ccnp,cnp -A -o custom-columns=KIND:.kind,NAME:.metadata.name,CREATED:.metadata.creationTimestamp
kubectl get cegp -o custom-columns=KIND:.kind,NAME:.metadata.name,CREATED:.metadata.creationTimestamp
kubectl get pods -A -l kasil.cloud/via-vpn=true
# egressctl must agree with the API server, not with a cached list
egressctl report --coverage --show-policy-inventory

# a policy is really enforced (ring 0 canary)
kubectl get cnp -n test-cd -o yaml | yq '.items[].spec.enableDefaultDeny'
kubectl -n kube-system exec ds/cilium -- cilium-dbg policy get | grep -A3 test-cd
```

## Appendix F — glossary

| Term | Meaning here |
|---|---|
| **edge** | one `(source workload, destination, port, protocol)` tuple that was observed at least once |
| **workload** | the top-level owner of a pod: Deployment, StatefulSet, DaemonSet, CronJob, Job, or a bare Pod |
| **shadow mode** | policy rules shipped with `enableDefaultDeny.egress: false` — evaluated, not enforced |
| **ring** | a batch of namespaces that go through generate → shadow → enforce together |
| **exempt** | a namespace/workload deliberately not policed, recorded as a file with a reason |
| **`world`** | Cilium identity for everything outside the cluster and the node — in this cluster that includes the whole LAN `192.168.x` |

## Appendix G — review round 1 changes (r2)

The five defects raised in review, plus two found while fixing them (rows 6 and the Appendix A minor). Everything else — measured cluster facts, CRD/source claims, options analysis, cost model — is unchanged.

| # | Defect | Fix |
|---|---|---|
| 1 | `deny-raw`/`dns-raw` `fieldMask` used `type`, which is not a `flow.Flow` field. `fieldmaskpb.New` rejects the path, `dynamicExporter.applyUpdatedConfig` logs `Failed to create exporter for config` and skips the exporter → `blocked_flow`/`dns_name` never fill, silently | replaced with `event_type` (§7.1); added the missing *detection*: `hubble_dynamic_exporter_up` / `_exporters_total` day-1 checks (Appendix E) and the `EgressExporterMissing` alert (§11.2), because `config_hash`/`config_last_applied` keep advancing and cannot reveal a skipped exporter |
| 2 | Report promised per-edge `bytes`, which aggregated flow logs cannot produce | removed from G1 and §9.2; declared an explicit non-goal with the reason (only flow *counts* exist: `Aggregate.*_flow_count`) |
| 3 | `audit-agg` YAML lacked the `reply: [false]`, `piraeus-datastore` and victoria-scrape exclusions that §6.2/§12 claimed it had | added. The scrape exclusion is narrowed to the actual scraper pod (`source_pod: ["victoria/vmagent"]`) so the rest of the namespace stays audited, and `victoria/vmagent` is now an explicit Phase-2 exemption (§10.4) instead of a hidden gap |
| 4 | §7.1 note 2 inverted Cilium's filter composition | rewritten from source (`BuildFilterList` → `MatchAll` per entry; `MatchOne` across entries; `Apply` = `whitelist.MatchOne && blacklist.MatchNone`), with the `reply` vs `is_reply` and `protocol`/DNS filter facts corrected (`protocol` accepts L7 names, so `protocol: ["dns"]` is a valid tighter selector) |
| 5 | Deny alerts and the §10.7 query grouped by `source_workload`, a label the configured metric does not expose | switched to `source` (from `sourceContext=workload-name…`); added `direction="egress"`; **also corrected `action="denied"` → `action="dropped"`** (the metric's `action` is the lowercased flow verdict; a policy denial arrives as `Flow.verdict=DROPPED`), and `hubble_drop_total`'s reason to `POLICY_DENIED` |
| 6 | `dns-raw` can only produce names when DNS traverses the Cilium DNS proxy, and the proxy is only installed for endpoints with an L7 DNS rule — Phase 1 had none, so S2 was unattainable | the baseline CCNP (`rules.dns`, `enableDefaultDeny: false`) now lands at the **start of Phase 1** (§9.1 step 1.2a); `dns` metric group added (§7); day-1 check that a lookup appears with `l7.dns.ips` (Appendix E); failure mode recorded in §10.5 |
| — | Appendix A was presented as a diff to `apps/cilium/values.yaml` but omitted the file's `cilium:` root | re-indented under `cilium:` and noted the current state (`cilium.hubble.enabled: false`) |

## Appendix H — review round 2 changes (r3)

The baseline in r2 claimed the cluster had no policy objects. It has two, both Git-managed since 2026-07-04 and both currently registering zero pods. Nothing else in the document changed.

| # | Defect | Fix |
|---|---|---|
| 1 | §2.1 inventoried only `NetworkPolicy`/`CiliumNetworkPolicy` and concluded "flat network"; §2.4 fact 1, §0, §4.1 and §10.9 repeated the claim that the cluster "has never had a policy" | §2.1 now lists `CiliumClusterwideNetworkPolicy/via-vpn-isolation` (selector `kasil.cloud/via-vpn=true`, egress = kube-dns `:53` + `world`, empty ingress, **0 matching pods**, source `kasil-apps/apps/cilium/templates/egress-gateway.yaml` @ `a73a099`) and `CiliumEgressGatewayPolicy/via-vpn-egress` (same selector, `0.0.0.0/0` minus RFC1918 → egressIP `192.168.20.50`, 0 pods), plus a paragraph on the two consequences (truncated edges, additive policy can only widen). §0, §2.4, §4.1, §9.1 step 1.0 and §10.9 corrected to "flat for running pods" with the two objects named |
| 2 | The report had no way to say a workload was already constrained, so a labeled workload's truncated edge set would have been treated as ground truth | new `PRE-POLICED` flag in §9.2, defined as "selected by a policy this pipeline did not generate", with the truncation and widening caveats and the requirement to resolve existing selectors at report time |
| 3 | A generated per-workload CNP would union with `via-vpn-isolation` and widen it, with nothing in `plan`/`lint`/`diff` stopping it | §10.1 gained the never-widen rule: `plan` emits only peers the existing policy already permits and skips (with `PRE-POLICED`) when the existing policy constrains nothing; `lint` fails on any non-subset and requires `--ack-pre-policed` for an explicit override; `diff` prints the existing policy as a constraint block and marks out-of-policy edges `pre-policed-dropped`. §10.5 gained the corresponding failure modes, including the egress-gateway SNAT note; §12 item 6 widened to cover the constraint (est. 1.5 → 1.8 days) |
| — | §2.5 said "all 24 apps"; the live Application count is 23 (§2.3 already said so) | corrected to 23 |
| — | Appendix E had no policy-inventory check | added `kubectl get ccnp,cnp,cegp` + `kubectl get pods -l kasil.cloud/via-vpn=true` + `egressctl report --show-policy-inventory` day-1 checks |
