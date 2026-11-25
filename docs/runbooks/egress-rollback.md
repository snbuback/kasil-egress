# Runbook — rollback

Every step is reversible, and the order matters: remove the restriction before
removing the visibility, never the other way round.

## A single workload is broken after enforcement

Fastest, no Git change:

```sh
kubectl delete cnp -n <namespace> <workload>-egress
```

Default-deny disappears with the last policy selecting the endpoint, so this is
immediate. Then commit the same change (delete the file under
`apps/egress/files/policies/<ns>/`) so ArgoCD does not recreate it on the next
sync.

If the policy was applied but you cannot tell what broke:

```sh
kubectl -n kube-system exec ds/cilium -- cilium-dbg monitor --type drop | head -50
egressctl verify --ns <namespace> --since 15m
```

## A whole ring regresses

1. Set `enableDefaultDeny.egress: false` on every policy in that namespace (one
   commit). The rules stay, the enforcement stops — the shadow state.
2. If it is still broken, delete the files for that namespace.
3. Investigate with the data you still have: `egress.edge`, `egress.blocked_flow`
   and the audit report are unaffected by policy changes.

## Disable the collector

Remove the `egress` entry from `kasil-apps/apps/apps/values.yaml` (ArgoCD
prunes the app). The database and its history stay; the data simply stops
growing. This is safe at any time: the collector never affects traffic.

## Turn Hubble off

Revert `cilium.hubble.enabled` to `false` in `apps/cilium/values.yaml`. This
removes the flow logs, the relay and the hubble metrics. Do it only if the
agents cannot cope: without it there is no inventory and no review queue.

## Drop the egress database

Last resort, and destructive — the audit history is what Phase 2 is based on.

```sh
# 1. remove the app so nothing connects
# 2. remove the database from apps/cnpg/values.yaml (name: egress)
# 3. after ArgoCD prunes the Database object, drop it manually if it lingers:
kubectl -n cnpg-system exec -it kasil-postgres-1 -- \
  psql -U postgres -c 'DROP DATABASE IF EXISTS egress;'
```

Then remove the Bitwarden item and the `ExternalSecret` (`egress-dsn`).

## What must never be the rollback

- Never `kubectl edit` a live policy: the next sync reverts it and you will not
  know which state you were debugging.
- Never widen a CIDR to `/0` to "make it work". That is the failure mode this
  design exists to prevent; the lint rule rejects it on purpose.
- Never leave `policyAuditMode: true` as a safety net. `egress-audit-guard`
  fails the job after 72 h and pages.
