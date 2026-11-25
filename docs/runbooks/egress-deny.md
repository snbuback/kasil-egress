# Runbook — a denial fired (`EgressDenyUnknown` / `EgressDenySpike`)

A denial means a connection was attempted and Cilium stopped it. There are
exactly three explanations, and the workflow exists to tell them apart before
anyone weakens a policy.

## 1. Triage (5 minutes)

```sh
egressctl verify --ns <namespace> --since 1h
```

Three buckets:

| Bucket | Meaning | Action |
|---|---|---|
| **uncovered** | no shipped rule mentions this destination | a new need → step 2 |
| **covered-but-denied** | a rule should have allowed it | a policy bug → step 4 |
| **reviewed** | a human already decided | nothing, unless the review expired |

For one specific denial:

```sh
egressctl explain <blocked-id>
```

It prints the blocked row (workload, pod, node, dst IP, DNS names, port,
verdict) plus the shipped rules for that namespace, which is usually enough to
see whether the destination was meant to be covered.

## 2. Decide, and record the decision

```sh
# Legitimate permanent need (e.g. renovate now uses api.github.com):
egressctl review <edge-id> --state allowed_forever --reason "renovate now uses api.github.com"

# Known-benign noise for a bounded window:
egressctl review <edge-id> --state ignored --reason "camera health check" --expires 720h

# A rule was supposed to allow it (policy bug):
egressctl review <edge-id> --state expected --reason "frigate -> nanomq:1883 already allowed"

# Security event: keep it denied.
egressctl review <edge-id> --state unexpected --reason "unknown destination, escalating"
```

The decision is keyed to the edge, so it survives pod restarts and is
auditable. `--reason` is mandatory: "who allowed this, when, and why" is the
point of the table.

## 3. Turn an `allowed_forever` into a rule

```sh
egressctl plan --ns <namespace> --out /tmp/plan        # shadow by default
git diff /tmp/plan                                      # review the diff
# copy the changed files into kasil-apps/apps/egress/files/policies/<ns>/
```

The policy is committed with `enableDefaultDeny.egress: false` while it is
being validated, then flipped to `true` (see `egress-rollout.md`).

## 4. Covered-but-denied: find the precedence bug

Usually one of:

- the rule selects the peer by a label the peer pod does not carry (a chart
  upgrade renamed a label) — `kubectl get pod -n <ns> --show-labels`;
- the port/protocol differs (`UDP` vs `TCP`, or an ephemeral source port);
- the destination moved to a new IP and the FQDN was not re-resolved — check
  `egress.dns_name` for the name's current addresses;
- two policies select the same workload and the union is not what you think —
  `egressctl lint --live` fails on that condition.

## 5. Escalate

`unexpected` means an attempt that no rule should ever have allowed. Keep it
denied, capture the evidence and escalate. That case is the reason the whole
pipeline exists; it must never be "fixed" by widening a CIDR.

## Alert-specific notes

- `EgressDenySpike` (>30 denials/5 min for one workload): more urgent than a
  single denial. Either a dependency broke (every retry is now denied) or
  something is scanning. `egressctl verify --ns <ns> --since 15m` shows which.
- `EgressCollectorStale`: denials still happen, but the review queue is
  silently emptying. Fix the collector first — you are blind until it writes.
- `EgressPostgresFillingUp`: shorten retention (`maintenance` CronJob flags) or
  roll `flow_raw_agg` up to 24 h.
