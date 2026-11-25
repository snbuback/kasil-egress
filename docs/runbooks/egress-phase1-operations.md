# Runbook — Phase 1 (audit mode) operations

Phase 1 makes egress visible without restricting anything. Nothing in this
runbook denies traffic: the only policy applied is the baseline, and its
`enableDefaultDeny.egress` is `false`.

## 1. Enable Hubble and the exporters (cilium chart)

Land the `cilium` values change (§7 of `docs/design.md`). Then verify, in this
order — each check catches a different failure mode.

```sh
# Hubble is on and the relay runs on the pinned node.
kubectl -n kube-system exec ds/cilium -- cilium-dbg status --all-health | grep -i hubble
kubectl -n kube-system get deploy hubble-relay -o wide      # NODE must be kube2

# All three exporters exist on EVERY node. A bad fieldMask or filter makes
# dynamicExporter log "Failed to create exporter for config" and skip that
# exporter while config_hash keeps advancing — so check the gauge, not the hash.
kubectl -n kube-system exec ds/cilium -- sh -c \
  'grep -c . /var/run/cilium/hubble/audit-agg.log /var/run/cilium/hubble/deny-raw.log /var/run/cilium/hubble/dns-raw.log' || true
curl -sG https://metrics.k8s.kasil.cloud/api/v1/query \
  --data-urlencode 'query=min by (instance) (hubble_dynamic_exporter_exporters_total{status="active"})'
# want: 3 on every instance

# Aggregated records actually carry counts.
kubectl -n kube-system exec ds/cilium -- sh -c 'tail -1 /var/run/cilium/hubble/audit-agg.log' | head -c 400
# want: an "aggregate":{"egress_flow_count":N} field
```

If `dns-raw` has port-53 records but no `l7.dns` block, DNS is not going
through the proxy: the baseline CCNP is missing (step 1.2a in the design).

### 1.1 kube3 memory gate (measure before Hubble lands there)

`#354` turns Hubble and the three dynamic exporters on for **every** node in
one merge. kube3 is the tight node (~1.3 GiB free, per design §7.1/§13), and
the card is explicit: nothing may be enabled on kube3 before its memory use is
measured. Record the baseline **before** the PR merges and paste it into the PR
description; re-measure after the sync.

```sh
# Pre-merge baseline (kube3).
kubectl top node kube3.kasil.cloud
kubectl describe node kube3.kasil.cloud | sed -n '/Allocated resources/,/Events/p'
kubectl -n kube-system top pod -l k8s-app=cilium \
  --field-selector spec.nodeName=kube3.kasil.cloud --containers
kubectl get --raw /api/v1/nodes/kube3.kasil.cloud/proxy/stats/summary \
  | jq '.node.memory.availableBytes/1048576'

# Post-rollout: the same four commands, once ArgoCD reports cilium Synced and
# the cilium pods on kube3 are Running (the dynamic-exporter ring buffer is
# what grows).
```

Pass criteria (design §7.1, budget 40–80 MiB per node):

- the `cilium-agent` RSS on kube3 grows by **no more than ~80 MiB**;
- `node.memory.availableBytes` on kube3 stays above **256 MiB**;
- no memory pressure or eviction appears within 24 h:

```sh
kubectl get events -A --field-selector reason=Evicted --since=24h
kubectl get node kube3.kasil.cloud \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}'
```

If the gate fails, lower `fileMaxSizeMb` for the exporters from 8 to 4 in
`apps/cilium/values.yaml` (halves the per-file buffer), re-sync and re-measure.
If it still fails, `hubble.enabled=false` is the rollback — a node under memory
pressure is worse than a blind audit window.

### 1.2 Confirm the weekly digest is delivered

The digest is the review loop's inbox item (§11.4), so a digest that only
exists in a completed Job's log does not count. The chart renders the webhook
as an `ExternalSecret` from the same Bitwarden item the Alertmanager uses
(`victoria.discord_webhook`), and posts to Discord.

```sh
kubectl -n egress get externalsecret egress-digest-webhook   # SecretSynced=True
kubectl -n egress get secret egress-digest-webhook
kubectl -n egress create job --from=cronjob/egress-digest egress-digest-manual
kubectl -n egress logs job/egress-digest-manual | tail -40
# want: the markdown digest, no "webhook returned" error, and the message in
# the Discord channel within a minute.
```

The CronJob runs Mondays 07:00 **Europe/Dublin** (`digest.timeZone`); a cluster
in UTC would otherwise fire it at 08:00 local in winter.

## 2. Check the collector

```sh
kubectl -n egress get ds && kubectl -n egress logs ds/egress --tail=50
kubectl -n egress exec ds/egress -- /usr/local/bin/app -version   # if the image has no shell, use kubectl describe
curl -s http://<pod-ip>:9110/metrics | grep -E 'egressd_(lines_read|lines_dropped|last_write|database_up)'
```

Expected: `egressd_database_up 1`, `egressd_last_write_timestamp_seconds`
advancing, `egressd_lines_dropped_total` flat.

Query the database directly (through any pod with a psql client, or a port
forward):

```sql
select count(*) as edges, max(last_seen) from egress.edge;
select verdict, count(*) from egress.blocked_flow group by 1;
select file, offset, updated from egress.ingest_offset order by file;
```

## 3. Drive the rare paths (do not skip this)

A 14-day soak of a homelab still misses monthly jobs. Before closing Phase 1,
deliberately exercise (§9.3):

- [ ] a real `kasil-cd` deploy (GitHub, ghcr, Discord)
- [ ] a Renovate/dependabot PR (argocd repo-server pulls Helm OCI charts)
- [ ] cert-manager renewal → Let's Encrypt ACME
- [ ] an ExternalSecret force-sync → Bitwarden
- [ ] the rclone/piraeus snapshot job and a CNPG backup
- [ ] a Frigate camera reconnect + a Home Assistant restart (mDNS)
- [ ] a `kasil-check` run
- [ ] `egressctl report` for every namespace

Record the list, with dates, in the report appendix. "Covered" means something
only if it names what was driven.

## 4. Generate the report

```sh
export EGRESS_DSN='postgres://egress:...@kasil-postgres-rw.cnpg-system.svc.cluster.local:5432/egress'
egressctl report --all --out reports/            # markdown, one file per namespace
egressctl report --all --out reports/ --format csv
egressctl report --coverage
egressctl report --show-policy-inventory         # the pre-existing objects, live
```

Acceptance (§9.4): S1 and S2 met; every workload has an allowlist candidate or
an explicit exemption; zero ingestion errors over 48 h; the report is
committed so Phase 2 diffs against a frozen baseline. Close-out checklist:
the digest has posted to Discord at least once (§1.2), and the kube3 memory
gate from §1.1 was recorded pre-merge and re-measured after the rollout.

`--coverage` prints two percentages over **running** workloads outside the
exempt namespaces (a scaled-to-zero Deployment or a suspended CronJob is
audited but not counted):

- `coverage` — §9.4: generated candidate **or** documented exemption;
- `seven_day` — S1: at least 7 days of observed edges (the actual gate,
  `seven_day >= 95.0`).

`no_edges` and `unresolved` are the two ways a workload can be uncovered:
nothing observed at all, or edges the generator could not turn into a rule
(a public IP with no DNS name, an unresolved peer).

Read them together: an exemption covers a workload in the §9.4 sense without
proving that its traffic was captured, which is exactly the gap S1 measures.
`not_running` and `exempt_namespace` are printed too, so a denominator that
shrinks because indexing broke is visible rather than flattering.

## 5. Watch for these symptoms

| Symptom | Cause | Fix |
|---|---|---|
| `egressd_lines_dropped_total{reason="channel_full"}` rising | collector slower than the flow volume | raise `collector.batchSize`, or narrow the exporter filters |
| `egressd_lines_dropped_total{reason="no_database"}` | Postgres unreachable; batches are spooled under `/var/lib/egressd` | fix the DSN/CNPG; the connector replays the spool automatically |
| `egress_edge_allowlisted` all `allowed="false"` | no policy has been recorded yet (Phase 2 not started) | expected before Phase 2 |
| `EgressExporterMissing` firing | one of the three exporters was skipped | check the agent log for `Failed to create exporter` |
| edges missing for a namespace | that namespace's traffic never reaches an exporter (hostNetwork pods!) | check `pod.spec.hostNetwork`; hostNetwork workloads are a documented gap |
