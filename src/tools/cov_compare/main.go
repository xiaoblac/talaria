// cov-compare — unify and compare coverage-over-time curves from
// multiple fuzzers. Standalone reFuzz tool, zero external deps.
//
// It reads each fuzzer's on-disk coverage time-series, normalizes to
// (elapsed_sec, cumulative_distinct_PC), and either:
//   - finalize (default): writes a merged CSV + prints a summary/ratio, or
//   - live (--live): polls the files and prints the latest values,
//     giving reFuzz the real-time view it otherwise lacks (it just tails
//     coverage_series.log; the fuzzer needs no live UI of its own).
//
// Y-axis caveat (by design, prelim): syzkaller "coverage" (corpus
// distinct source PC) and reFuzz "unique" (distinct PC seen) are both
// "distinct PC" but may use different dedup/canonicalization. Curves are
// comparable in shape/slope; absolute-equality claims need alignment
// work first. This is surfaced in the printed summary.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type sourceSpec struct {
	kind       string // "syz-bench" | "syz-log" | "refuzz-log" | "syz-metrics"
	path       string
	label      string
	seriesID   string // refuzz-log only
	url        string // syz-metrics only
	benchField string // syz-bench/syz-log: which value field (default "coverage")
}

func main() {
	var (
		syzBench      = flag.String("syz-bench", "", "path to syz-manager -bench JSONL file")
		syzLog        = flag.String("syz-log", "", "path to syz-manager.log; parses 10s heartbeat 'coverage=' directly from the log, converting its wall-clock timestamps to elapsed seconds (finer than 60s -bench; PC only — no signal)")
		syzLabel      = flag.String("syz-label", "syzkaller", "label for the syzkaller curve")
		refuzzLog     = flag.String("refuzz-log", "", "path to a reFuzz coverage_series.log")
		refuzzLabel   = flag.String("refuzz-label", "refuzz", "label for the reFuzz curve")
		refuzzSeries  = flag.String("refuzz-series", "all_pc", "reFuzz coverage key to keep (all_pc|corpus_pc|all_edge|corpus_edge)")
		syzMetrics    = flag.String("syz-metrics", "", "syz-manager /metrics URL to poll live (e.g. http://127.0.0.1:57541/metrics); finer than -bench for live view")
		syzBenchField = flag.String("syz-bench-field", "coverage", "syz -bench JSON value field: \"coverage\" (corpus cover, primary) or \"max signal\" (all-exec, secondary)")
		out           = flag.String("out", "", "write merged CSV here (default: stdout in finalize mode)")
		live          = flag.Bool("live", false, "poll sources and print latest values until Ctrl-C")
		web           = flag.String("web", "", "serve a live web UI at this addr (e.g. :8080); overrides --live")
		interval      = flag.Duration("interval", time.Second, "live poll interval")
	)
	flag.Parse()

	var specs []sourceSpec
	if *syzBench != "" {
		specs = append(specs, sourceSpec{kind: "syz-bench", path: *syzBench, label: *syzLabel, benchField: *syzBenchField})
	}
	if *syzLog != "" {
		specs = append(specs, sourceSpec{kind: "syz-log", path: *syzLog, label: *syzLabel, benchField: *syzBenchField})
	}
	if *refuzzLog != "" {
		specs = append(specs, sourceSpec{kind: "refuzz-log", path: *refuzzLog, label: *refuzzLabel, seriesID: *refuzzSeries})
	}
	if *syzMetrics != "" {
		specs = append(specs, sourceSpec{kind: "syz-metrics", url: *syzMetrics, label: *syzLabel})
	}
	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "cov-compare: need at least one of --syz-bench / --syz-metrics / --refuzz-log")
		flag.Usage()
		os.Exit(2)
	}

	if *web != "" {
		runWeb(specs, *web, *out, *interval)
		return
	}
	if *live {
		runLive(specs, *interval, *out)
		return
	}
	if err := runFinalize(specs, *out); err != nil {
		fmt.Fprintln(os.Stderr, "cov-compare:", err)
		os.Exit(1)
	}
}

// loadAll parses every configured source. In live mode missing/partial
// files are tolerated (best-effort); in finalize mode a hard error on a
// configured source is fatal.
func loadAll(specs []sourceSpec, tolerant bool) ([]*Series, error) {
	var series []*Series
	for _, sp := range specs {
		s, err := loadSeries(sp)
		if err != nil {
			if tolerant {
				series = append(series, &Series{Label: sp.label, Source: sp.kind})
				continue
			}
			return nil, fmt.Errorf("load %s (%s): %w", sp.label, sp.path, err)
		}
		series = append(series, s)
	}
	return series, nil
}

func runFinalize(specs []sourceSpec, out string) error {
	series, err := loadAll(specs, false)
	if err != nil {
		return err
	}
	csv := renderMergedCSV(series)
	if out == "" {
		fmt.Print(csv)
	} else {
		if err := os.WriteFile(out, []byte(csv), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "merged CSV -> %s\n", out)
	}
	printSummary(os.Stderr, series)
	return nil
}

func runLive(specs []sourceSpec, interval time.Duration, out string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Fprintln(os.Stderr, "cov-compare live (Ctrl-C to stop & write final CSV)")
	for {
		select {
		case <-sig:
			fmt.Fprintln(os.Stderr)
			series, _ := loadAll(specs, true)
			if out != "" {
				_ = os.WriteFile(out, []byte(renderMergedCSV(series)), 0o644)
				fmt.Fprintf(os.Stderr, "merged CSV -> %s\n", out)
			}
			printSummary(os.Stderr, series)
			return
		case <-ticker.C:
			series, _ := loadAll(specs, true)
			fmt.Fprint(os.Stdout, renderLivePanels(series))
		}
	}
}

func printSummary(w *os.File, series []*Series) {
	fmt.Fprintln(w, "\n=== coverage-over-time summary ===")
	fmt.Fprintf(w, "%-14s %-12s %8s %10s %12s %14s\n",
		"label", "source", "samples", "dur(s)", "final_PC", "PC/s(mean)")
	for _, s := range series {
		sm := s.Summary()
		fmt.Fprintf(w, "%-14s %-12s %8d %10.1f %12.0f %14.2f\n",
			sm.Label, sm.Source, sm.Samples, sm.Duration, sm.FinalPC, sm.MeanPCPerSec)
	}
	// Ratio at the common time horizon (min of durations), if exactly two.
	if len(series) == 2 && series[0].Duration() > 0 && series[1].Duration() > 0 {
		h := series[0].Duration()
		if series[1].Duration() < h {
			h = series[1].Duration()
		}
		a := series[0].ValueAt(h)
		b := series[1].ValueAt(h)
		fmt.Fprintf(w, "\nat common horizon t=%.0fs:  %s=%.0f  %s=%.0f", h, series[0].Label, a, series[1].Label, b)
		if b > 0 {
			fmt.Fprintf(w, "  ratio %s/%s=%.3f", series[0].Label, series[1].Label, a/b)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "NOTE: Y axis is each tool's own \"distinct PC\" (syz corpus coverage vs reFuzz unique);")
	fmt.Fprintln(w, "      dedup/canonicalization may differ — compare shape/slope, not absolute equality.")
}
