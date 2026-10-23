// Live /metrics polling source. syzkaller's -bench file only updates
// every 60s, which makes its live curve look frozen next to reFuzz's
// ~1s samples. But syz-manager's Prometheus /metrics endpoint is live,
// so polling it gives matching fine granularity for the live web/terminal
// view — without touching syzkaller. Recorded series: X =
// syz_fuzz_time_ms/1000 (boot-excluded), Y = syz_corpus_cover.
package main

import (
	"bufio"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	metricCover  = "syz_corpus_cover"
	metricFuzzMs = "syz_fuzz_time_ms"
)

// MetricsPoller accumulates a coverage time-series in memory from a
// syz-manager /metrics endpoint. Safe for concurrent Snapshot() reads.
type MetricsPoller struct {
	url   string
	label string
	mu    sync.Mutex
	pts   []Point
}

func NewMetricsPoller(url, label string) *MetricsPoller {
	return &MetricsPoller{url: url, label: label}
}

// Start launches the background poll loop at the given interval.
func (p *MetricsPoller) Start(interval time.Duration) {
	go func() {
		// Poll once immediately, then on the ticker.
		p.pollOnce()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			p.pollOnce()
		}
	}()
}

func (p *MetricsPoller) pollOnce() {
	cover, fuzzMs, ok := fetchSyzMetrics(p.url)
	if !ok || fuzzMs <= 0 {
		return // not fuzzing yet (boot) or endpoint down
	}
	elapsed := fuzzMs / 1000.0
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.pts)
	if n == 0 || elapsed > p.pts[n-1].ElapsedSec {
		p.pts = append(p.pts, Point{ElapsedSec: elapsed, PC: cover})
	} else {
		p.pts[n-1].PC = cover // same fuzz-time tick: refresh value in place
	}
}

// Snapshot returns a copy of the accumulated series, anchored to zero.
func (p *MetricsPoller) Snapshot() *Series {
	p.mu.Lock()
	pts := make([]Point, len(p.pts))
	copy(pts, p.pts)
	p.mu.Unlock()
	// fuzz_time_ms is already elapsed-since-syz-fuzz-start — sort only.
	return &Series{Label: p.label, Source: "syz-metrics", Points: sortByElapsed(pts)}
}

// fetchSyzMetrics pulls the two gauges from a Prometheus text endpoint.
func fetchSyzMetrics(url string) (cover, fuzzMs float64, ok bool) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()
	var gotC, gotF bool
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if v, found := promValue(line, metricCover); found {
			cover, gotC = v, true
		} else if v, found := promValue(line, metricFuzzMs); found {
			fuzzMs, gotF = v, true
		}
	}
	return cover, fuzzMs, gotC && gotF
}

// promValue parses `<name> <value>` (these gauges carry no labels).
func promValue(line, name string) (float64, bool) {
	if !strings.HasPrefix(line, name+" ") {
		return 0, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	f, err := strconv.ParseFloat(fields[len(fields)-1], 64)
	return f, err == nil
}
