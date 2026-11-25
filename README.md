# kasil-egress

Audit and restrict pod egress on a Cilium cluster: **see what every workload
actually talks to, then allow only that, and log every block for review.**

Built for a small homelab Cilium cluster, generic enough for any Cilium +
PostgreSQL setup. The design (and the reasoning behind every decision) is
[`docs/design.md`](docs/design.md).

## Why

Cilium can enforce egress policy, but it cannot tell you *what the policy
should say*. `hubble observe` is a live stream, not an inventory; and the
off-the-shelf generators either forget history (`cpg`), forget FQDNs
(`cf2cnp`), or need Loki. The gap is durable per-workload inventory, FQDN and
LAN attribution, and a review queue for the traffic a policy blocks later.

Two phases, deliberately separated:

| Phase | What it does | What it changes |
|---|---|---|
| **1 — audit** | Hubble flow logs → `egressd` → PostgreSQL → `egressctl report` | nothing is denied |
| **2 — enforce** | `egressctl plan` emits one egress-only `CiliumNetworkPolicy` per workload, shadowed first | one workload at a time, ring by ring |

```
 Cilium agents (4 nodes)
   └── dynamic flow-log exporter ──► audit-agg.log / deny-raw.log / dns-raw.log
                                          │  (hostPath, read-only)
                                          ▼
                                    egressd (DaemonSet)
                                          │  batched upserts, offsets checkpointed
                                          ▼
                              PostgreSQL  egress.*  (edge, blocked_flow, dns_name)
                                          │
                     ┌────────────────────┴─────────────────────┐
                     ▼                                          ▼
             egressctl report                          Grafana / VMRule alerts
        (markdown · CSV · JSON per namespace)          (deny · exporter · lag)
                     │
                     ▼
             egressctl plan  ──►  CiliumNetworkPolicy (one per workload)
```

## Install (with Helm)

```sh
helm repo add kasil-egress oci://ghcr.io/snbuback/charts
helm install egress kasil-egress/egress -n egress --create-namespace \
  --set cluster.podCIDR=172.16.0.0/16 \
  --set cluster.svcCIDR=172.30.0.0/16 \
  --set cluster.timezone=Europe/Dublin \
  --set postgres.dsnSecretName=egress-dsn
```

The chart installs the collector, the maintenance/digest/audit-guard CronJobs,
the ServiceMonitor, the alerts, the dashboard, and the cluster-wide baseline
policy (`baseline-dns-apiserver`) that makes Cilium proxy DNS so FQDNs can be
attributed.

Prerequisites:

1. Cilium **1.19+** (flow aggregation) with Hubble enabled and three dynamic
   exporters — see `docs/runbooks/egress-phase1-operations.md` for the exact
   values and the day-1 checks.
2. PostgreSQL reachable with a DSN in a secret (`EGRESS_DSN_FILE`).
3. Nothing else. The collector never sits in the traffic path.

## Use

```sh
# Phase 1: what does everything talk to?
egressctl report --all --out reports/
egressctl report --coverage
egressctl report --show-policy-inventory     # pre-existing Cilium policies, live

# Phase 2: propose allowlists (shadow mode: nothing is denied yet)
egressctl plan --ns frigate --out /tmp/plan
egressctl lint /tmp/plan
egressctl diff --ns frigate                  # exits non-zero if any edge is uncovered

# After promotion: review what is being blocked
egressctl verify --ns frigate --since 24h
egressctl explain 12345
egressctl review 12345 --state allowed_forever --reason "renovate now uses api.github.com"
```

`egressctl plan` never guesses:

* a public destination with no DNS name is **not** emitted (`world-unnamed`) —
  a human decides;
* pod IPs are never emitted (they change on restart);
* a `toFQDNs` rule always carries the companion L7 DNS rule, without which
  Cilium never resolves the name;
* if an existing policy already constrains the workload, its allowed set is a
  **ceiling**: a generated policy can only add peers, so rules outside it are
  dropped (`pre-policed-dropped`) and `lint` fails unless the widening is
  explicitly acknowledged;
* the pipeline's own objects (the chart's baseline and exemptions, and every
  generated policy — `egress.kasil.io/owned: "true"`) are never a ceiling: they
  are replaced wholesale on the next plan, so a committed shadow policy cannot
  block its own regeneration.

## Components

| Path | What |
|---|---|
| `cmd/egressd` | per-node collector: tails the exporter files, normalizes flows, batches upserts, spools to disk when Postgres is away |
| `cmd/egressctl` | `report`, `plan`, `diff`, `lint`, `verify`, `explain`, `review`, `digest`, `schema`, `maintain`, `audit-guard` |
| `pkg/flow` | decoder for the real Cilium protobuf schema, plus destination classification |
| `pkg/k8s` | just enough Kubernetes REST for pod → workload resolution and the policy inventory (no client-go) |
| `pkg/pg` | schema, partitions, retention, batched upserts |
| `pkg/policy` | the generator, the never-widen constraint and the linter |
| `pkg/report` | markdown / CSV / JSON rendering |
| `deploy/helm/egress` | the chart |
| `testdata/flows` | fixtures generated from Cilium's own protobuf types |

## Development

```sh
make test        # unit tests, no cluster and no database needed
make chart       # helm lint + render with the CRD groups the chart uses
make build       # bin/egressd, bin/egressctl
```

The test suite is hermetic on purpose: the flow fixtures are produced by
`go run testdata/gen/gen.go`, which marshals real `flowpb.Flow` values through
the same encoder Cilium's exporter uses, so a schema change shows up as a test
failure rather than as silently empty tables.

## License

Apache-2.0. See [LICENSE](LICENSE). Prior art credited in `docs/design.md` §14
(`SoulKyu/cpg`, `onzack/cf2cnp`, Cilium CFP-37472).
