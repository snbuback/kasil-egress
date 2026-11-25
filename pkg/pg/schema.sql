-- Schema for the egress database. Applied by `egressctl schema apply` and by
-- the chart's migration Job; every statement is idempotent.
--
-- Deviations from the design doc, all deliberate:
--   * blocked_flow uses an explicit sequence instead of GENERATED ALWAYS AS
--     IDENTITY: identity columns are not supported on every PostgreSQL
--     version this tool may meet on a partitioned parent, sequences are.
--   * active_hours is a text-castable bit(24); the collector writes it as a
--     bit string with hour 0 as the right-most bit.

CREATE SCHEMA IF NOT EXISTS egress;

CREATE TABLE IF NOT EXISTS egress.workload (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  namespace   text  NOT NULL,
  kind        text  NOT NULL,
  name        text  NOT NULL,
  labels      jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (namespace, kind, name)
);

CREATE TABLE IF NOT EXISTS egress.pod (
  uid         text PRIMARY KEY,
  workload_id bigint REFERENCES egress.workload(id),
  namespace   text NOT NULL,
  name        text NOT NULL,
  node        text,
  ip          inet,
  created_at  timestamptz,
  deleted_at  timestamptz
);

CREATE TABLE IF NOT EXISTS egress.dns_name (
  fqdn       text NOT NULL,
  ip         inet NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (fqdn, ip)
);

CREATE TABLE IF NOT EXISTS egress.edge (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  src_workload_id bigint NOT NULL REFERENCES egress.workload(id),
  dst_kind        text   NOT NULL,
  dst_key         text   NOT NULL,
  dst_namespace   text,
  port            int    NOT NULL,
  proto           text   NOT NULL,
  first_seen      timestamptz NOT NULL DEFAULT now(),
  last_seen       timestamptz NOT NULL DEFAULT now(),
  conns_total     bigint NOT NULL DEFAULT 0,
  active_hours    bit(24) NOT NULL DEFAULT B'000000000000000000000000',
  days_seen       smallint NOT NULL DEFAULT 1,
  UNIQUE (src_workload_id, dst_kind, dst_key, port, proto)
);

CREATE INDEX IF NOT EXISTS edge_workload_idx ON egress.edge (src_workload_id);

CREATE TABLE IF NOT EXISTS egress.flow_raw_agg (
  ts              timestamptz NOT NULL,
  node            text NOT NULL,
  src_workload_id bigint NOT NULL,
  dst_kind        text NOT NULL,
  dst_key         text NOT NULL,
  dst_namespace   text,
  port            int NOT NULL,
  proto           text NOT NULL,
  verdict         text NOT NULL,
  conns           bigint NOT NULL,
  PRIMARY KEY (ts, node, src_workload_id, dst_kind, dst_key, port, proto, verdict)
) PARTITION BY RANGE (ts);

CREATE TABLE IF NOT EXISTS egress.flow_hourly (
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

CREATE SEQUENCE IF NOT EXISTS egress.blocked_flow_id_seq;

CREATE TABLE IF NOT EXISTS egress.blocked_flow (
  id              bigint NOT NULL DEFAULT nextval('egress.blocked_flow_id_seq'),
  ts              timestamptz NOT NULL,
  src_workload_id bigint REFERENCES egress.workload(id),
  src_namespace   text NOT NULL,
  src_pod         text NOT NULL,
  src_ip          inet,
  dst_ip          inet,
  dst_namespace   text,
  dst_pod         text,
  dst_names       jsonb,
  port            int,
  proto           text,
  direction       text NOT NULL,
  verdict         text NOT NULL,
  drop_reason     text,
  node            text,
  conns           bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE TABLE IF NOT EXISTS egress.policy (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  namespace   text NOT NULL,
  name        text NOT NULL,
  mode        text NOT NULL,
  generation  int  NOT NULL DEFAULT 1,
  applied_at  timestamptz,
  UNIQUE (namespace, name)
);

CREATE TABLE IF NOT EXISTS egress.policy_rule (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  policy_id  bigint NOT NULL REFERENCES egress.policy(id) ON DELETE CASCADE,
  edge_id    bigint REFERENCES egress.edge(id),
  rule_kind  text NOT NULL,
  rule_value text NOT NULL,
  source     text NOT NULL DEFAULT 'generated',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS policy_rule_edge_idx ON egress.policy_rule (edge_id);

CREATE TABLE IF NOT EXISTS egress.review (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  edge_id    bigint NOT NULL REFERENCES egress.edge(id),
  state      text NOT NULL,
  reason     text NOT NULL,
  decided_by text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);

CREATE TABLE IF NOT EXISTS egress.ingest_offset (
  node     text NOT NULL,
  file     text NOT NULL,
  inode    bigint NOT NULL,
  offset   bigint NOT NULL,
  updated  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node, file)
);

CREATE OR REPLACE VIEW egress.v_edge AS
SELECT e.*, w.namespace AS src_namespace, w.kind AS src_kind, w.name AS src_name
FROM egress.edge e JOIN egress.workload w ON w.id = e.src_workload_id;

CREATE OR REPLACE VIEW egress.v_uncovered AS
SELECT v.* FROM egress.v_edge v
WHERE NOT EXISTS (SELECT 1 FROM egress.policy_rule r WHERE r.edge_id = v.id)
  AND NOT EXISTS (SELECT 1 FROM egress.review rv
                  WHERE rv.edge_id = v.id
                    AND rv.state IN ('expected','allowed_forever')
                    AND (rv.expires_at IS NULL OR rv.expires_at > now()));

CREATE OR REPLACE VIEW egress.v_stale_rule AS
SELECT r.*, p.namespace, p.name AS policy_name
FROM egress.policy_rule r JOIN egress.policy p ON p.id = r.policy_id
LEFT JOIN egress.edge e ON e.id = r.edge_id
WHERE r.edge_id IS NULL OR e.last_seen < now() - interval '30 days';
