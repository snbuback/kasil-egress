# Runbook — Phase 2 rollout (per ring)

Every ring follows the same five steps: **generate → shadow → soak → enforce →
verify**. Never skip the shadow window, and never promote a namespace whose
`egressctl diff` reports uncovered edges.

## 0. Preconditions

- Phase 1 closed: 14-day soak done, report committed.
- `baseline-dns-apiserver` CCNP applied (the chart does this) and
  `hubble_dns_queries_total > 0`.
- Ring 0 (`test-cd`, `check`) is the canary. If a mistake is going to happen,
  it happens there.

## 1. Generate (shadow)

```sh
egressctl plan --ns <namespace> --out /tmp/plan
```

`plan` emits one file per workload. Read the exit summary: workloads listed
under "needs a human decision" have no rules — usually a peer that could not be
resolved, or a public IP with no DNS name (`world-unnamed`), which the
generator deliberately refuses to guess.

If a workload is `PRE-POLICED` (selected by a policy this pipeline did not
generate, today only `via-vpn-isolation`), the generated policy only contains
peers that policy already allows, and everything else is printed as
`pre-policed-dropped`. Do not "fix" that by adding the missing peers: it would
re-open the isolation. Review the diff and, if the widening is genuinely
intended, use `--ack-pre-policed <kind>/<name>`.

The baseline and exemption CCNPs shipped by the chart, and every policy this
pipeline generated, carry `egress.kasil.io/owned: "true"`. They are never
treated as constraints and never raise `PRE-POLICED`: the pipeline replaces its
own output on the next `plan`, so a committed shadow policy must not block its
regeneration or make `diff` report a gap. Do not strip the marker when copying
a policy file.

## 2. Commit and lint

```sh
# into the GitOps repo
cp /tmp/plan/<ns>/*.yaml kasil-apps/apps/egress/files/policies/<ns>/

# offline checks
egressctl lint apps/egress/files/policies --live=false
# with the cluster (checks the never-widen rule against live policies)
egressctl lint apps/egress/files/policies

# render what ArgoCD will apply
helm template egress apps/egress --namespace egress \
  --api-versions monitoring.coreos.com/v1 \
  --api-versions external-secrets.io/v1 \
  --api-versions operator.victoriametrics.com/v1beta1 | yq 'select(.kind=="CiliumNetworkPolicy")'
```

The lint fails on: FQDN rules without a DNS rule, pod-IP CIDRs, CIDRs broader
than /8, a pattern instead of a name, two policies selecting the same pods, and
any rule outside a pre-existing policy's ceiling.

## 3. Shadow soak

Merge with `enableDefaultDeny.egress: false`. Traffic is allowed; the policy is
evaluated and anything not matching is forwarded with
`policy_match_type == 4`.

Gate for flipping (deterministic, no verdict dependency):

```sh
egressctl diff --ns <namespace>     # exits non-zero if any edge is uncovered
```

Cross-check live:

```sh
kubectl -n kube-system exec ds/cilium -- \
  hubble observe --verdict FORWARDED --cel-expression '_flow.policy_match_type == uint(4)' --last 100
```

Ring-specific soak: 24 h for ring 0, 3–7 d for ring 1, 7 d for ring 2, 7 d for
ring 3 (`hermes`).

## 4. Flip to enforce

One commit per namespace: `enableDefaultDeny.egress: true`, and record the
mode so `verify` can tell coverage from noise:

```sh
egressctl plan --ns <namespace> --enforce --record
```

Then watch for 24 h:

```sh
egressctl verify --ns <namespace> --since 24h
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query --data-urlencode \
  'query=sum by (source_namespace,source,destination) (rate(hubble_policy_verdicts_total{action="dropped",direction="egress"}[5m]))'
```

`EgressDenyUnknown` firing here is expected for a few minutes if the shadow
window missed a rare path — see `egress-deny.md`. A deny spike after an upgrade
is the classic "legitimate new need" case.

## 5. Verify the datapath, not the YAML

```sh
kubectl get cnp -n <namespace> -o json | yq '.items[].spec.enableDefaultDeny'
kubectl -n kube-system exec ds/cilium -- cilium-dbg endpoint get <endpoint-id> -o json | yq '.status.policy'
# want: "egress": {"enforcing": true, ...}
```

## Rings

| Ring | Namespaces | Shadow |
|---|---|---|
| 0 | `test-cd`, `check` | 24 h |
| 1 | `mcp`, `auth`, `vikunja`, `honcho`, `zigbee2mqtt`, `nanomq`, `homeassistant` (pod workloads only) | 3–7 d |
| 2 | `frigate`, `victoria` (vmagent excepted), `argocd`, `argo`, `argo-events`, `cert-manager`, `external-secrets`, `cloudflare-tunnel`, `ddns-route53`, `rclone`, `cnpg-system` | 7 d |
| 3 (optional) | `hermes` | 7 d |
| exempt | `kube-system`, `piraeus-datastore`, `victoria/vmagent` | — |

## Exemptions (files with a reason, not tribal knowledge)

`kube-system`, `piraeus-datastore` and `victoria/vmagent` are exempt in the
chart (`policies.exemptions`). `homeassistant-hass` and
`music-assistant-server` run hostNetwork and cannot be selected by a pod
policy: an accepted v1 gap, reported by `egressctl report` every time so it
stays visible.
