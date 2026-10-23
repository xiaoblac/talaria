// Source adapters. Each turns one fuzzer's on-disk coverage time-series
// into []Point (elapsed_sec, cumulative_distinct_PC). No syzkaller
// package is imported — formats are parsed as plain text/JSON so this
// tool stays decoupled and reusable.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Hard-coded syzkaller -bench JSONL field names. Kept here (not in
// logic) so a syzkaller rename is a one-line fix. "coverage" is the
// distinct source-PC count in corpus; "fuzz time ms" is wall time since
// the first fuzz exec (already boot-excluded).
const (
	syzFieldCoverage = "coverage"
	syzFieldFuzzMs   = "fuzz time ms"
)

// ParseSyzBench reads a syz-manager `-bench` file. syz-manager writes
// each periodic snapshot with json.MarshalIndent followed by '\n'
// (manager.go writeBench), so the file is a stream of *pretty-printed*
// (multi-line) JSON objects concatenated — NOT one object per line. We
// therefore decode value-by-value with json.Decoder, which transparently
// handles both the indented form and compact JSONL. Elapsed comes from
// "fuzz time ms"; the value is "coverage". A trailing partial object
// (live tail mid-write) ends the loop without erroring out.
func ParseSyzBench(path, valueField string) ([]Point, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pts []Point
	dec := json.NewDecoder(bufio.NewReader(f))
	dec.UseNumber()
	idx := 0
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			if err == io.EOF {
				break
			}
			// Partial/truncated trailing object during a live tail:
			// stop cleanly with whatever we already decoded.
			break
		}
		cov, okC := asFloat(obj[valueField])
		if !okC {
			idx++
			continue
		}
		var elapsed float64
		if ms, ok := asFloat(obj[syzFieldFuzzMs]); ok {
			elapsed = ms / 1000.0
		} else {
			elapsed = float64(idx * 60) // fallback: bench cadence is 60s
		}
		pts = append(pts, Point{ElapsedSec: elapsed, PC: cov})
		idx++
	}
	// "fuzz time ms" is already elapsed-since-syz-fuzz-start — sort only,
	// do NOT anchor (that would shift the true origin).
	return sortByElapsed(pts), nil
}

// syzLogTSLayout matches the "2006/01/02 15:04:05 " prefix syz-manager puts on
// every log line.
const syzLogTSLayout = "2006/01/02 15:04:05"

// ParseSyzLog reads syz-manager.log heartbeat lines (logged every 10s by
// manager.go heartbeatLoop) of the form:
//
//	2026/06/22 08:09:06 candidates=728 corpus=0 coverage=N exec calls total=..
//
// extracting valueField (default "coverage"). This is a 10s-cadence PC source
// — 6× finer than the 60s -bench — taken straight from syz's own log, WITHOUT
// touching syzkaller code or trusting its "fuzz time ms" accounting.
//
// The leading "2026/06/22 08:09:06" is syz's human-readable wall-clock, handy
// for eyeballing but not a plot axis. We convert it into a plot-friendly
// elapsed-seconds axis: t=0 at the FIRST heartbeat line, every later point =
// (its wall-clock − that first wall-clock). No rows are dropped and no
// value-based filtering is done — the curve is exactly syz's recorded
// timeline, just re-expressed in seconds-from-start.
//
// NOTE: the Console heartbeat carries "coverage" (PC) but NOT "signal" (edge,
// not a Console stat) — the edge series stays on the 60s -bench.
func ParseSyzLog(path, valueField string) ([]Point, error) {
	if valueField == "" {
		valueField = syzFieldCoverage
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(valueField) + `=(\d+)(?:\s|$)`)
	var pts []Point
	var t0 time.Time
	haveT0 := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < len(syzLogTSLayout) {
			continue
		}
		ts, perr := time.Parse(syzLogTSLayout, line[:len(syzLogTSLayout)])
		if perr != nil {
			continue // not a timestamped heartbeat line
		}
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue // no <field>=N on this line
		}
		v, verr := strconv.ParseFloat(m[1], 64)
		if verr != nil {
			continue
		}
		// Anchor the plot axis at the first heartbeat; convert each line's
		// wall-clock into elapsed seconds. Every heartbeat is kept as-is.
		if !haveT0 {
			t0 = ts
			haveT0 = true
		}
		pts = append(pts, Point{ElapsedSec: ts.Sub(t0).Seconds(), PC: v})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sortByElapsed(pts), nil
}

// ParseRefuzzCoverageLog reads the single key=value coverage log emitted by
// CoverageMetricsSink. All four measurement gauges share one file, one row per
// 10s window, self-describing:
//
//	# coverage series — key=value per 10s window: t=<HH:MM:SS>,all_pc,corpus_pc,all_edge,corpus_edge
//	t=13:23:30,all_pc=101,corpus_pc=41,all_edge=203,corpus_edge=73
//
// seriesID selects the value by key name (all_pc/corpus_pc/all_edge/corpus_edge).
// The X axis (ElapsedSec) is derived from the wall-clock t field relative to the
// first row (midnight wrap handled); loadRefuzzFuzzStartSec later re-anchors it
// at fuzz-start, so only the axis being self-consistent matters here.
func ParseRefuzzCoverageLog(path, seriesID string) ([]Point, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)

	var pts []Point
	haveRow := false
	originSet := false
	var originSec float64
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Reject the retired tab-separated format outright: a valid data row is
		// comma-joined key=value and always contains '='.
		if !strings.Contains(line, "=") {
			return nil, fmt.Errorf("invalid reFuzz coverage log line (expected key=value): %q", line)
		}
		kv := parseKeyValueRow(line)
		tRaw, hasT := kv["t"]
		valueRaw, hasV := kv[seriesID]
		if !hasT || !hasV {
			continue
		}
		sec, err1 := parseClockSeconds(tRaw)
		value, err2 := strconv.ParseFloat(valueRaw, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if !originSet {
			originSec = sec
			originSet = true
		}
		elapsed := sec - originSec
		if elapsed < 0 {
			elapsed += 86400 // wall-clock crossed midnight
		}
		pts = append(pts, Point{ElapsedSec: elapsed, PC: value})
		haveRow = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !haveRow {
		return nil, fmt.Errorf("no reFuzz coverage rows for series %q in %s", seriesID, path)
	}
	return sortByElapsed(pts), nil
}

// parseKeyValueRow splits a comma-joined "k=v,k=v,..." row into a map. Malformed
// tokens (no '=') are skipped.
func parseKeyValueRow(line string) map[string]string {
	out := make(map[string]string)
	for _, tok := range strings.Split(line, ",") {
		tok = strings.TrimSpace(tok)
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		out[strings.TrimSpace(tok[:eq])] = strings.TrimSpace(tok[eq+1:])
	}
	return out
}

// parseClockSeconds turns "HH:MM:SS" into seconds-of-day.
func parseClockSeconds(s string) (float64, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid clock %q", s)
	}
	h, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	sec, e3 := strconv.Atoi(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, fmt.Errorf("invalid clock %q", s)
	}
	return float64(h*3600 + m*60 + sec), nil
}

// loadRefuzzFuzzStartSec derives the fuzz-phase origin for a reFuzz curve in
// the SAME projector time axis as the metric-log points, so the curve can
// be re-anchored at first-fuzz-exec (dropping the boot + machine-check
// plateau). It reads run_summary.json sitting next to the metric log (the
// orchestrator writes both to logs_dir) and uses two of its fields:
//
//	fuzz_started_us  — (first-task-produced − session_start), µs
//	elapsed_fuzz_ms  — (final-snapshot − first-task-produced), ms
//	                   = elapsed_ms − fuzz_started_us/1000
//
// Since elapsed_fuzz_ms is the fuzz-phase wall duration up to the final
// snapshot, and the final metric-log sample is taken at shutdown:
//
//	fuzz_start_abs ≈ last_sample_abs − elapsed_fuzz_ms
//
// Returns ok=false (→ caller falls back to anchorToZero) when run_summary.json
// is absent/unparseable or fuzz never started (fuzz_started_us ≤ 0), e.g. a
// live tail before the first produce or a run too short to fuzz.
func loadRefuzzFuzzStartSec(logPath string, pts []Point) (float64, bool) {
	if len(pts) == 0 {
		return 0, false
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(logPath), "run_summary.json"))
	if err != nil {
		return 0, false
	}
	var doc struct {
		Fields map[string]json.Number `json:"fields"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return 0, false
	}
	fuzzUs, ok1 := fieldFloat(doc.Fields, "fuzz_started_us")
	fuzzMs, ok2 := fieldFloat(doc.Fields, "elapsed_fuzz_ms")
	if !ok1 || !ok2 || fuzzUs <= 0 || fuzzMs <= 0 {
		return 0, false
	}
	lastSec := pts[len(pts)-1].ElapsedSec
	return lastSec - fuzzMs/1000.0, true
}

// fieldFloat reads one numeric field from a run_summary.json "fields" map.
func fieldFloat(m map[string]json.Number, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	f, err := v.Float64()
	return f, err == nil
}

// asFloat coerces a JSON value (number or numeric string) to float64.
func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// loadSeries parses one configured source into a Series. Empty path
// means the source is not configured and is skipped by the caller.
func loadSeries(spec sourceSpec) (*Series, error) {
	var (
		pts []Point
		err error
	)
	switch spec.kind {
	case "syz-bench":
		field := spec.benchField
		if field == "" {
			field = syzFieldCoverage
		}
		pts, err = ParseSyzBench(spec.path, field)
	case "syz-log":
		// 10s heartbeat coverage straight from syz-manager.log; its
		// wall-clock timestamps are converted to elapsed seconds in ParseSyzLog.
		pts, err = ParseSyzLog(spec.path, spec.benchField)
	case "refuzz-log":
		var raw []Point
		raw, err = ParseRefuzzCoverageLog(spec.path, spec.seriesID)
		if err == nil {
			// Re-base at first-fuzz-exec (strip boot + machine-check) when
			// run_summary.json gives the fuzz-phase origin; else fall back to
			// anchoring at the earliest sample (back-compat / live tail).
			if startSec, ok := loadRefuzzFuzzStartSec(spec.path, raw); ok {
				pts = anchorAtFuzzStart(raw, startSec)
			} else {
				pts = anchorToZero(raw)
			}
		}
	case "syz-metrics":
		// Single-shot fetch (one point) — only meaningful for a quick
		// finalize peek. The live web/terminal path uses MetricsPoller
		// to accumulate a real series over time instead.
		if cover, fuzzMs, ok := fetchSyzMetrics(spec.url); ok && fuzzMs > 0 {
			pts = []Point{{ElapsedSec: fuzzMs / 1000.0, PC: cover}}
		}
	default:
		return nil, fmt.Errorf("unknown source kind %q", spec.kind)
	}
	if err != nil {
		return nil, err
	}
	return &Series{Label: spec.label, Source: spec.kind, Points: pts}, nil
}
