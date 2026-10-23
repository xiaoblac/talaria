// Terminal ASCII line charts for live mode. During a run the two tools
// are shown as SEPARATE side-by-side panels (left vs right), each with
// its own auto-scaled Y axis — deliberately NOT overlaid, because their
// magnitudes/timescales differ and a live overlay misleads. The single
// combined two-line figure is produced only at the end, by the static
// matplotlib step. ASCII-only so each rendered line is exactly `width`
// bytes and panels align when joined.
package main

import (
	"fmt"
	"math"
	"strings"
)

const (
	panelWidth  = 50
	panelHeight = 14
	yGutter     = 9 // chars reserved for the Y-axis label column
)

// renderPanel returns fixed-width lines: a title, panelHeight plot rows
// (with a Y-axis label gutter), and an X-axis row. Every line is exactly
// `width` bytes wide.
func renderPanel(s *Series, width, height int) []string {
	title := fmt.Sprintf("%s  PC=%.0f @%.0fs (%d pts)", s.Label, s.FinalPC(), s.Duration(), len(s.Points))
	maxT := s.Duration()
	maxY := s.FinalPC()
	if maxY <= 0 {
		maxY = 1
	}
	if maxT <= 0 {
		maxT = 1
	}
	plotW := width - yGutter
	if plotW < 4 {
		plotW = 4
	}

	grid := make([][]byte, height)
	for r := range grid {
		grid[r] = make([]byte, plotW)
		for c := range grid[r] {
			grid[r][c] = ' '
		}
	}
	for c := 0; c < plotW; c++ {
		t := maxT * float64(c) / float64(plotW-1)
		v, ok := s.ValueAtBounded(t)
		if !ok {
			continue
		}
		rr := int(math.Round((1 - v/maxY) * float64(height-1)))
		if rr < 0 {
			rr = 0
		}
		if rr >= height {
			rr = height - 1
		}
		grid[rr][c] = '*'
	}

	lines := make([]string, 0, height+2)
	lines = append(lines, fitWidth(title, width))
	for r := 0; r < height; r++ {
		lab := strings.Repeat(" ", yGutter)
		switch r {
		case 0:
			lab = fmt.Sprintf("%8.0f ", maxY)
		case height - 1:
			lab = fmt.Sprintf("%8d ", 0)
		}
		if len(lab) != yGutter {
			lab = fitWidth(lab, yGutter)
		}
		lines = append(lines, lab+string(grid[r]))
	}
	xr := fmt.Sprintf("%.0fs", maxT)
	axis := strings.Repeat(" ", yGutter) + "0"
	pad := plotW - 1 - len(xr)
	if pad < 1 {
		pad = 1
	}
	axis += strings.Repeat(" ", pad) + xr
	lines = append(lines, fitWidth(axis, width))
	return lines
}

// fitWidth pads or truncates s to exactly n bytes (ASCII).
func fitWidth(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

// sideBySide joins equal-height panels horizontally with sep.
func sideBySide(panels [][]string, sep string) string {
	h := 0
	for _, p := range panels {
		if len(p) > h {
			h = len(p)
		}
	}
	var b strings.Builder
	for r := 0; r < h; r++ {
		for i, p := range panels {
			if i > 0 {
				b.WriteString(sep)
			}
			if r < len(p) {
				b.WriteString(p[r])
			} else {
				b.WriteString(strings.Repeat(" ", panelWidth))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// orderForDisplay returns series with reFuzz on the left and syzkaller on
// the right (the rest keep their order), matching the requested layout.
func orderForDisplay(series []*Series) []*Series {
	var left, right, other []*Series
	for _, s := range series {
		switch s.Source {
		case "refuzz-log":
			left = append(left, s)
		case "syz-bench", "syz-metrics":
			right = append(right, s)
		default:
			other = append(other, s)
		}
	}
	out := append([]*Series{}, left...)
	out = append(out, other...)
	out = append(out, right...)
	return out
}

// renderLivePanels clears the screen and draws each series as its own
// auto-scaled panel, side by side.
func renderLivePanels(series []*Series) string {
	ordered := orderForDisplay(series)
	panels := make([][]string, 0, len(ordered))
	for _, s := range ordered {
		panels = append(panels, renderPanel(s, panelWidth, panelHeight))
	}
	var b strings.Builder
	b.WriteString("\033[H\033[2J") // home + clear
	b.WriteString("cov-compare live — separate auto-scaled panels (Ctrl-C to stop & write final CSV)\n\n")
	b.WriteString(sideBySide(panels, "  |  "))
	return b.String()
}
