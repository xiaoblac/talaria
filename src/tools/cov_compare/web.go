// Web UI live view. Mirrors syzkaller's approach (server holds the data,
// the page renders it) but drops syzkaller's two weaknesses: no CDN
// (the chart is hand-drawn on a <canvas>, embedded via go:embed so it
// works fully offline / behind an SSH tunnel) and it auto-refreshes
// (the page polls /api/series every second instead of needing a manual
// reload). Two separate auto-scaled panels — left reFuzz, right syz; the
// combined two-line figure remains the end-of-run matplotlib artifact.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

type apiSeries struct {
	Label  string       `json:"label"`
	Source string       `json:"source"`
	Points [][2]float64 `json:"points"`
}

func seriesToAPI(s *Series) apiSeries {
	pts := make([][2]float64, len(s.Points))
	for i, p := range s.Points {
		pts[i] = [2]float64{p.ElapsedSec, p.PC}
	}
	return apiSeries{Label: s.Label, Source: s.Source, Points: pts}
}

func runWeb(specs []sourceSpec, addr, out string, interval time.Duration) {
	// File-backed sources are re-read per request; syz-metrics sources run
	// a background poller that accumulates a live series (fine granularity
	// the 60s -bench file can't give).
	var fileSpecs []sourceSpec
	var pollers []*MetricsPoller
	for _, sp := range specs {
		if sp.kind == "syz-metrics" {
			p := NewMetricsPoller(sp.url, sp.label)
			p.Start(interval)
			pollers = append(pollers, p)
		} else {
			fileSpecs = append(fileSpecs, sp)
		}
	}
	collect := func() []*Series {
		series, _ := loadAll(fileSpecs, true)
		for _, p := range pollers {
			series = append(series, p.Snapshot())
		}
		return series
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/series", func(w http.ResponseWriter, r *http.Request) {
		resp := struct {
			Series []apiSeries `json:"series"`
		}{}
		for _, s := range collect() {
			resp.Series = append(resp.Series, seriesToAPI(s))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	// Convenience: let the page (or curl) grab the merged CSV the same
	// shape the matplotlib step consumes.
	mux.HandleFunc("/api/merged.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(renderMergedCSV(collect())))
	})

	fmt.Fprintf(os.Stderr, "cov-compare web UI: http://localhost%s  (Ctrl-C to stop)\n", addr)
	if out != "" {
		fmt.Fprintf(os.Stderr, "(merged CSV also at /api/merged.csv; final static PNG is a separate matplotlib step)\n")
	}
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "cov-compare web:", err)
		os.Exit(1)
	}
}
