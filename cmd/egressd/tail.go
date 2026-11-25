package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/snbuback/kasil-egress/pkg/pg"
)

// tailer follows the exporter files. It never blocks on the consumer: when the
// channel is full the line is dropped and counted, because losing a line is
// visible while blocking the agent's disk writes is not.
type tailer struct {
	dir   string
	node  string
	files []string
	log   *slog.Logger
	out   chan<- []byte
	// offsets is the connector's checkpoint map.
	offsets   func(key string) (pg.Offset, bool)
	metrics   *metrics
	ckptEvery time.Duration
	save      func(context.Context, []pg.Offset)
}

type fileState struct {
	inode  int64
	offset int64
}

func (t *tailer) run(ctx context.Context) {
	states := map[string]fileState{}
	lastCkpt := time.Now()

	// Restore checkpoints: only trust an offset when the inode still matches,
	// otherwise the file was rotated while we were down and we start at 0.
	for _, name := range t.files {
		if o, ok := t.offsets(t.node + "\x00" + filepath.Join(t.dir, name)); ok {
			states[filepath.Join(t.dir, name)] = fileState{inode: o.Inode, offset: o.Offset}
		}
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.checkpoint(ctx, states)
			return
		case <-tick.C:
			for _, name := range t.files {
				t.readFile(ctx, filepath.Join(t.dir, name), states)
			}
			if time.Since(lastCkpt) >= t.ckptEvery {
				t.checkpoint(ctx, states)
				lastCkpt = time.Now()
			}
		}
	}
}

func (t *tailer) readFile(ctx context.Context, path string, states map[string]fileState) {
	st, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.log.Debug("stat failed", "file", path, "error", err)
		}
		delete(states, path)
		return
	}
	ino := inodeOf(st)
	state, known := states[path]
	if !known || state.inode != ino || st.Size() < state.offset {
		// New file, rotation, or truncation.
		state = fileState{inode: ino, offset: 0}
	}
	if st.Size() == state.offset {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		t.log.Debug("open failed", "file", path, "error", err)
		return
	}
	defer f.Close()
	if _, err := f.Seek(state.offset, io.SeekStart); err != nil {
		return
	}
	br := bufio.NewReaderSize(f, 1<<20)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			// Complete line: advance the offset past it.
			state.offset += int64(len(line))
			states[path] = state
			t.metrics.linesRead.WithLabelValues(filepath.Base(path)).Add(1)
			select {
			case t.out <- line:
			default:
				t.metrics.linesDropped.WithLabelValues("channel_full").Add(1)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.log.Debug("read error", "file", path, "error", err)
			}
			return
		}
	}
}

func (t *tailer) checkpoint(ctx context.Context, states map[string]fileState) {
	if len(states) == 0 {
		return
	}
	offs := make([]pg.Offset, 0, len(states))
	for path, s := range states {
		offs = append(offs, pg.Offset{Node: t.node, File: path, Inode: s.inode, Offset: s.offset})
	}
	t.save(ctx, offs)
}

func inodeOf(st os.FileInfo) int64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int64(sys.Ino)
	}
	return 0
}
