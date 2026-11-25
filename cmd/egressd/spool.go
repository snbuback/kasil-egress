package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/snbuback/kasil-egress/pkg/pg"
)

// replaySpool writes spooled batches back to the database, oldest first. A
// file is deleted only after every row in it was written, so a crash during
// replay re-runs that file (edges are additive, so a partial replay can
// over-count by at most one batch — visible and bounded, unlike losing it).
func replaySpool(ctx context.Context, db *pg.DB, dir string, log *slog.Logger, m *metrics) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var files []string
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		files = append(files, p)
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	if len(files) == 0 {
		m.spoolBytes.Set(0)
		return
	}
	sort.Strings(files)
	if total > 8<<20 {
		log.Warn("spool is larger than 8 MiB", "bytes", total, "files", len(files))
	}
	log.Info("replaying spool", "files", len(files), "bytes", total)

	refs := map[string]pg.WorkloadRef{}
	var edges []pg.EdgeRow
	var raw []pg.RawAggRow
	var blocked []pg.BlockedRow
	var dns []pg.DNSRow
	edgeSrc := []string{}
	rawSrc := []string{}
	blockedSrc := []string{}

	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var rec struct {
				Kind     string          `json:"kind"`
				Workload string          `json:"workload"`
				Row      json.RawMessage `json:"row"`
			}
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			switch rec.Kind {
			case "workload":
				var r pg.WorkloadRef
				if json.Unmarshal(rec.Row, &r) == nil {
					refs[r.Namespace+"/"+r.Kind+"/"+r.Name] = r
				}
			case "edge":
				var r pg.EdgeRow
				if json.Unmarshal(rec.Row, &r) == nil {
					edges = append(edges, r)
					edgeSrc = append(edgeSrc, rec.Workload)
				}
			case "raw":
				var r pg.RawAggRow
				if json.Unmarshal(rec.Row, &r) == nil {
					raw = append(raw, r)
					rawSrc = append(rawSrc, rec.Workload)
				}
			case "blocked":
				var r pg.BlockedRow
				if json.Unmarshal(rec.Row, &r) == nil {
					blocked = append(blocked, r)
					blockedSrc = append(blockedSrc, rec.Workload)
				}
			case "dns":
				var r pg.DNSRow
				if json.Unmarshal(rec.Row, &r) == nil {
					dns = append(dns, r)
				}
			}
		}
		f.Close()
	}

	list := make([]pg.WorkloadRef, 0, len(refs))
	for _, r := range refs {
		list = append(list, r)
	}
	ids, err := db.ResolveWorkloads(ctx, list)
	if err != nil {
		log.Warn("spool replay: resolve workloads failed", "error", err)
		return
	}
	for i := range edges {
		edges[i].SrcWorkloadID = ids[edgeSrc[i]]
	}
	for i := range raw {
		raw[i].SrcWorkloadID = ids[rawSrc[i]]
	}
	for i := range blocked {
		if id, ok := ids[blockedSrc[i]]; ok {
			id := id
			blocked[i].SrcWorkloadID = &id
		}
	}

	if err := db.UpsertEdges(ctx, edges); err != nil {
		log.Warn("spool replay: edges failed", "error", err)
		return
	}
	if err := db.InsertRawAgg(ctx, raw); err != nil {
		log.Warn("spool replay: raw failed", "error", err)
	}
	if err := db.InsertBlocked(ctx, blocked); err != nil {
		log.Warn("spool replay: blocked failed", "error", err)
	}
	if err := db.UpsertDNS(ctx, dns); err != nil {
		log.Warn("spool replay: dns failed", "error", err)
	}
	for _, path := range files {
		if err := os.Remove(path); err != nil {
			log.Warn("cannot remove replayed spool file", "file", path, "error", err)
		}
	}
	m.spoolBytes.Set(0)
	log.Info("spool replayed", "edges", len(edges), "raw", len(raw), "blocked", len(blocked), "dns", len(dns))
	_ = fmt.Sprint(len(files))
}
