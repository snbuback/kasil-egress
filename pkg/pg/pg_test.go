package pg

import (
	"strings"
	"testing"
	"time"
)

func TestHourMask(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Dublin")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		t    time.Time
		loc  *time.Location
		want int // expected hour, read back from the mask
	}{
		{"utc midnight", time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC), time.UTC, 0},
		{"utc 10:00", time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC), time.UTC, 10},
		{"dublin winter is utc", time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC), loc, 10},
		{"dublin summer is utc+1", time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC), loc, 11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mask := HourMask(tt.t, tt.loc)
			if len(mask) != 24 {
				t.Fatalf("mask length = %d", len(mask))
			}
			got := -1
			for i, c := range mask {
				if c == '1' {
					if got != -1 {
						t.Fatalf("more than one bit set: %s", mask)
					}
					got = 23 - i
				}
			}
			if got != tt.want {
				t.Errorf("mask %s decodes to hour %d, want %d", mask, got, tt.want)
			}
		})
	}
}

func TestPartitionCutoff(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
		want string
	}{
		{"flow_raw_agg_p20261125", true, "2026-11-25T00:00:00Z"},
		{"flow_hourly_p202611", true, "2026-11-01T00:00:00Z"},
		{"blocked_flow_p202611", true, "2026-11-01T00:00:00Z"},
		{"edge", false, ""},
		{"flow_raw_agg_pnotadate", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := partitionCutoff(tt.name)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got.Format(time.RFC3339) != tt.want {
				t.Errorf("cutoff = %s, want %s", got.Format(time.RFC3339), tt.want)
			}
		})
	}
}

func TestDefaultRetention(t *testing.T) {
	r := DefaultRetention()
	if r.Raw != 48*time.Hour || r.Hourly != 180*24*time.Hour || r.Blocked != 90*24*time.Hour || r.DNS != 90*24*time.Hour {
		t.Errorf("retention = %+v, want the documented 48h/180d/90d/90d", r)
	}
}

func TestSchemaIsEmbedded(t *testing.T) {
	for _, want := range []string{
		"CREATE SCHEMA IF NOT EXISTS egress",
		"CREATE TABLE IF NOT EXISTS egress.edge",
		"PARTITION BY RANGE (ts)",
		"CREATE OR REPLACE VIEW egress.v_edge",
		"blocked_flow_id_seq",
	} {
		if !strings.Contains(schemaSQL, want) {
			t.Errorf("schema is missing %q", want)
		}
	}
	if n := strings.Count(schemaSQL, "CREATE TABLE IF NOT EXISTS"); n < 8 {
		t.Errorf("schema has %d tables, expected at least 8", n)
	}
}
