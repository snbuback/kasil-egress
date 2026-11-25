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
	_ = fs.Parse(args)
	if fs.NArg() == 0 || fs.Arg(0) != "apply" {
		return fmt.Errorf("usage: egressctl schema apply")
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
	_ = fs.Parse(args)
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
