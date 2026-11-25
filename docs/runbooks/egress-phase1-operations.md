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
committed so Phase 2 diffs against a frozen baseline.

## 5. Watch for these symptoms

| Symptom | Cause | Fix |
|---|---|---|
| `egressd_lines_dropped_total{reason="channel_full"}` rising | collector slower than the flow volume | raise `collector.batchSize`, or narrow the exporter filters |
| `egressd_lines_dropped_total{reason="no_database"}` | Postgres unreachable; batches are spooled under `/var/lib/egressd` | fix the DSN/CNPG; the connector replays the spool automatically |
| `egress_edge_allowlisted` all `allowed="false"` | no policy has been recorded yet (Phase 2 not started) | expected before Phase 2 |
| `EgressExporterMissing` firing | one of the three exporters was skipped | check the agent log for `Failed to create exporter` |
| edges missing for a namespace | that namespace's traffic never reaches an exporter (hostNetwork pods!) | check `pod.spec.hostNetwork`; hostNetwork workloads are a documented gap |
