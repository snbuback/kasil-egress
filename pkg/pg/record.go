package pg

import (
	"context"
	"fmt"
	"time"
)

// RuleRef is one generated rule to record for the diff/verify bookkeeping.
type RuleRef struct {
	Kind    string
	Value   string
	EdgeIDs []int64
}

// RecordPolicy upserts a policy row and replaces its rule set. This is what
// makes `verify` able to tell "traffic nobody allowed" (a genuine new need)
// from "traffic a shipped rule should have allowed" (a policy bug).
func (d *DB) RecordPolicy(ctx context.Context, namespace, name, mode string, rules []RuleRef) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var policyID int64
	err = tx.QueryRow(ctx, `
INSERT INTO egress.policy (namespace, name, mode, generation, applied_at)
VALUES ($1, $2, $3, 1, now())
ON CONFLICT (namespace, name) DO UPDATE
SET mode = EXCLUDED.mode, generation = egress.policy.generation + 1, applied_at = now()
RETURNING id`, namespace, name, mode).Scan(&policyID)
	if err != nil {
		return fmt.Errorf("record policy %s/%s: %w", namespace, name, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM egress.policy_rule WHERE policy_id = $1`, policyID); err != nil {
		return err
	}
	for _, r := range rules {
		if len(r.EdgeIDs) == 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO egress.policy_rule (policy_id, rule_kind, rule_value) VALUES ($1,$2,$3)`,
				policyID, r.Kind, r.Value); err != nil {
				return err
			}
			continue
		}
		for _, edgeID := range r.EdgeIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO egress.policy_rule (policy_id, edge_id, rule_kind, rule_value) VALUES ($1,$2,$3,$4)`,
				policyID, edgeID, r.Kind, r.Value); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// Review records a human decision about an edge.
func (d *DB) Review(ctx context.Context, edgeID int64, state, reason, by string, expiresAt *time.Time) error {
	_, err := d.pool.Exec(ctx, `
INSERT INTO egress.review (edge_id, state, reason, decided_by, expires_at)
VALUES ($1,$2,$3,$4,$5)`, edgeID, state, reason, by, expiresAt)
	return err
}

// UncoveredEdges returns edges with no shipped rule and no active review.
func (d *DB) UncoveredEdges(ctx context.Context, namespace string) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM egress.v_uncovered WHERE ($1 = '' OR src_namespace = $1)`, namespace).Scan(&n)
	return n, err
}
