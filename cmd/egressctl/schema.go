package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/snbuback/kasil-egress/pkg/pg"
)

// openDB opens only the database. verify/explain/review/digest/schema do not
// need the API server.
func openDB(ctx context.Context, e env) (*pg.DB, error) {
	if err := e.requireDSN(); err != nil {
		return nil, err
	}
	db, err := pg.Open(ctx, e.dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return db, nil
}

func cmdSchema(args []string) error {
	fs := flag.NewFlagSet("schema", flag.ExitOnError)
	load := registerEnv(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 || pos[0] != "apply" {
		return fmt.Errorf("usage: egressctl schema apply")
	}
	if err := noPositional(pos[1:]); err != nil {
		return err
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	fmt.Println("schema applied")
	return nil
}

func cmdMaintain(args []string) error {
	fs := flag.NewFlagSet("maintain", flag.ExitOnError)
	load := registerEnv(fs)
	dryRun := fs.Bool("dry-run", false, "report what would be done without writing")
	raw := fs.Duration("retention-raw", 48*time.Hour, "flow_raw_agg retention")
	hourly := fs.Duration("retention-hourly", 180*24*time.Hour, "flow_hourly retention")
	blocked := fs.Duration("retention-blocked", 90*24*time.Hour, "blocked_flow retention")
	dns := fs.Duration("retention-dns", 90*24*time.Hour, "dns_name retention")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := noPositional(pos); err != nil {
		return err
	}
	e, err := load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := openDB(ctx, e)
	if err != nil {
		return err
	}
	defer db.Close()

	ret := pg.Retention{Raw: *raw, Hourly: *hourly, Blocked: *blocked, DNS: *dns}
	if *dryRun {
		fmt.Printf("would apply retention %+v\n", ret)
		return nil
	}
	stats, err := db.Maintain(ctx, time.Now(), ret)
	if err != nil {
		return err
	}
	out, _ := json.Marshal(stats)
	fmt.Println(string(out))
	return nil
}
