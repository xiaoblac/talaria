// Coverage time-series model + merge/summary. A Series is a sorted,
// carry-forward (step) function elapsed_sec -> cumulative distinct PC.
package main

import (
	"fmt"
	"sort"
	"strings"
)

// Point is one sample of a coverage curve.
type Point struct {
	ElapsedSec float64 // seconds since the series' own first sample
	PC         float64 // cumulative distinct PC count at this time
}

// Series is one fuzzer's coverage-over-time curve.
type Series struct {
	Label  string  // display name, e.g. "syzkaller" / "refuzz"
	Source string  // adapter kind, e.g. "syz-bench" / "refuzz-log"
	Points []Point // sorted ascending by ElapsedSec
}

// anchorToZero shifts every point so the earliest sample sits at t=0,
// making curves from different clocks (syz fuzz-time-ms vs reFuzz
// steady-clock ns) directly comparable on one X axis.
func anchorToZero(pts []Point) []Point {
	if len(pts) == 0 {
		return pts
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].ElapsedSec < pts[j].ElapsedSec })
	base := pts[0].ElapsedSec
	for i := range pts {
		pts[i].ElapsedSec -= base
	}
	return pts
}

// sortByElapsed sorts points by time WITHOUT shifting the origin. Used
// for syzkaller, whose "fuzz time ms" is already elapsed-since-fuzz-start
// (a true 0 origin) — re-anchoring it would wrongly shift the curve.
func sortByElapsed(pts []Point) []Point {
	sort.Slice(pts, func(i, j int) bool { return pts[i].ElapsedSec < pts[j].ElapsedSec })
	return pts
}

// anchorAtFuzzStart re-bases reFuzz's curve so the FIRST FUZZ EXEC sits at
// t=0 — not the first coverage sample. reFuzz's coverage metric log samples
// start when the telemetry projector begins ticking (≈ VM boot, inside
// registry.StartAll), which is BEFORE the host-driven machine-check phase
// and before any fuzzing. Anchoring at the earliest sample (anchorToZero)
// would therefore leave a flat boot+machine-check prefix that syzkaller's
// curve does NOT have (its "fuzz time ms" is already boot/machine-check-
// excluded). startSec is that fuzz-phase origin in the SAME absolute steady
// seconds as the points' ElapsedSec (derived from run_summary.json — see
// loadRefuzzFuzzStartSec). Points before the origin (the boot + machine-
// check plateau) are dropped; a small tolerance absorbs the sub-tick skew
// between the last coverage sample and the final run_summary snapshot.
func anchorAtFuzzStart(pts []Point, startSec float64) []Point {
	sort.Slice(pts, func(i, j int) bool { return pts[i].ElapsedSec < pts[j].ElapsedSec })
	const tolSec = 2.0 // absorb last-sample ↔ final-summary skew
	out := pts[:0]
	for _, p := range pts {
		e := p.ElapsedSec - startSec
		if e < -tolSec {
			continue // pre-fuzz plateau: boot + machine-check
		}
		if e < 0 {
			e = 0
		}
		p.ElapsedSec = e
		out = append(out, p)
	}
	return out
}

// ValueAt returns the carry-forward PC value at time t: the PC of the
// latest sample whose ElapsedSec <= t. Before the first sample it is 0.
func (s *Series) ValueAt(t float64) float64 {
	if len(s.Points) == 0 || t < s.Points[0].ElapsedSec {
		return 0
	}
	// Points are sorted; find rightmost ElapsedSec <= t.
	lo, hi := 0, len(s.Points)-1
	ans := 0.0
	for lo <= hi {
		mid := (lo + hi) / 2
		if s.Points[mid].ElapsedSec <= t {
			ans = s.Points[mid].PC
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return ans
}

// ValueAtBounded is ValueAt but only within the series' real span
// [first.Elapsed, last.Elapsed]. Outside that span it returns ok=false
// so callers (e.g. the merged CSV used for plotting) can emit a gap
// instead of extrapolating a flat line past where the tool actually ran
// — this is what avoids the misleading "carry forward forever" artifact.
func (s *Series) ValueAtBounded(t float64) (float64, bool) {
	if len(s.Points) == 0 {
		return 0, false
	}
	if t < s.Points[0].ElapsedSec || t > s.Points[len(s.Points)-1].ElapsedSec {
		return 0, false
	}
	return s.ValueAt(t), true
}

// Duration is the elapsed time of the last sample (0 if empty).
func (s *Series) Duration() float64 {
	if len(s.Points) == 0 {
		return 0
	}
	return s.Points[len(s.Points)-1].ElapsedSec
}

// FinalPC is the cumulative PC of the last sample (0 if empty).
func (s *Series) FinalPC() float64 {
	if len(s.Points) == 0 {
		return 0
	}
	return s.Points[len(s.Points)-1].PC
}

// SeriesSummary is the headline stats for one curve.
type SeriesSummary struct {
	Label        string
	Source       string
	Samples      int
	Duration     float64
	FinalPC      float64
	MeanPCPerSec float64 // FinalPC / Duration (overall slope)
}

func (s *Series) Summary() SeriesSummary {
	dur := s.Duration()
	rate := 0.0
	if dur > 0 {
		rate = s.FinalPC() / dur
	}
	return SeriesSummary{
		Label:        s.Label,
		Source:       s.Source,
		Samples:      len(s.Points),
		Duration:     dur,
		FinalPC:      s.FinalPC(),
		MeanPCPerSec: rate,
	}
}

// mergeTimes returns the sorted union of all series' sample timestamps.
func mergeTimes(series []*Series) []float64 {
	seen := map[float64]struct{}{}
	for _, s := range series {
		for _, p := range s.Points {
			seen[p.ElapsedSec] = struct{}{}
		}
	}
	times := make([]float64, 0, len(seen))
	for t := range seen {
		times = append(times, t)
	}
	sort.Float64s(times)
	return times
}

// renderMergedCSV produces a CSV: elapsed_sec,<label1>_pc,<label2>_pc,...
// A cell is left EMPTY when the timestamp is past that series' last real
// sample, so a plotting tool draws each line only over the span the tool
// actually ran (no flat extrapolation). Within a series' span values are
// carry-forward (the cumulative coverage step function).
func renderMergedCSV(series []*Series) string {
	times := mergeTimes(series)
	var b strings.Builder
	b.WriteString("elapsed_sec")
	for _, s := range series {
		b.WriteString(",")
		b.WriteString(sanitizeCol(s.Label) + "_pc")
	}
	b.WriteString("\n")
	for _, t := range times {
		fmt.Fprintf(&b, "%.3f", t)
		for _, s := range series {
			if v, ok := s.ValueAtBounded(t); ok {
				fmt.Fprintf(&b, ",%.0f", v)
			} else {
				b.WriteString(",") // gap: outside this series' real span
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func sanitizeCol(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if s == "" {
		return "series"
	}
	return s
}
