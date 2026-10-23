package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
)

// Phase C C1 — emits a syzkaller-derived choice-table reference report so the
// reFuzz parity test can compare top outgoing edges for anchor calls.
//
// Output path:
//   docs/syzkaller-integration/reports/phase_c_choice_table_<os>-<arch>_<pin>_<utc>.json

const choiceRefTopK = 20

// Default anchor list. Picked to span fd-producing, mmap-style, and
// network/event resource constructors that any non-trivial linux/amd64 fuzzer
// will exercise. Each anchor must exist verbatim in target.Syscalls.
var choiceRefAnchorsLinuxAmd64 = []string{
	"openat",
	"socket",
	"pipe",
	"pipe2",
	"dup",
	"accept",
	"close",
	"read",
	"write",
	"ioctl",
	"mmap",
	"epoll_create1",
	"eventfd2",
	"signalfd4",
	"timerfd_create",
	"inotify_init1",
	"memfd_create",
	"pidfd_open",
}

type choiceEdge struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
	Prio int32  `json:"prio"`
}

type choiceAnchor struct {
	Name       string       `json:"name"`
	ID         int          `json:"id"`
	Selectable bool         `json:"selectable"`
	RowSum     int64        `json:"row_sum"`
	TopEdges   []choiceEdge `json:"top_edges"`
}

type choiceRefReport struct {
	Phase       string         `json:"phase"`
	Step        string         `json:"step"`
	Kind        string         `json:"kind"`
	GeneratedAt string         `json:"generated_at_utc"`
	Syzkaller   choiceRefSyz   `json:"syzkaller"`
	Target      choiceRefTgt   `json:"target"`
	Anchors     []choiceAnchor `json:"anchors"`
}

type choiceRefSyz struct {
	Pin      string `json:"pin"`
	Observed string `json:"observed"`
	Pinned   bool   `json:"pinned"`
}

type choiceRefTgt struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

func runChoiceRef(target *prog.Target, opts options) error {
	pin, observed, pinned, err := pinStatus(opts)
	if err != nil && !opts.unpinned {
		return fmt.Errorf("read pin: %w", err)
	}

	prios, enabled := target.CalculatePriorities(nil, nil)

	anchors := chooseAnchors(opts.osName, opts.arch)
	report := choiceRefReport{
		Phase:       "C",
		Step:        "C1",
		Kind:        "choice_table_reference",
		GeneratedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Syzkaller:   choiceRefSyz{Pin: pin, Observed: observed, Pinned: pinned},
		Target:      choiceRefTgt{OS: opts.osName, Arch: opts.arch},
	}

	syscallByName := make(map[string]*prog.Syscall, len(target.Syscalls))
	for _, c := range target.Syscalls {
		syscallByName[c.Name] = c
	}

	for _, name := range anchors {
		c, ok := syscallByName[name]
		if !ok {
			return fmt.Errorf("anchor syscall %q not found in target %s/%s",
				name, opts.osName, opts.arch)
		}
		row := prios[c.ID]

		var rowSum int64
		var edges []choiceEdge
		for j, p := range row {
			rowSum += int64(p)
			if p == 0 || j == c.ID {
				continue
			}
			dst := target.Syscalls[j]
			if !enabled[dst] {
				continue
			}
			edges = append(edges, choiceEdge{Name: dst.Name, ID: j, Prio: p})
		}
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].Prio != edges[j].Prio {
				return edges[i].Prio > edges[j].Prio
			}
			return edges[i].Name < edges[j].Name
		})
		if len(edges) > choiceRefTopK {
			edges = edges[:choiceRefTopK]
		}

		report.Anchors = append(report.Anchors, choiceAnchor{
			Name:       name,
			ID:         c.ID,
			Selectable: enabled[c],
			RowSum:     rowSum,
			TopEdges:   edges,
		})
	}

	outPath := opts.out
	if outPath == "" {
		outPath = choiceRefDefaultPath(opts.osName, opts.arch, pin, report.GeneratedAt)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(outPath, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("wrote %s (%d anchors)\n", outPath, len(report.Anchors))
	return nil
}

func chooseAnchors(osName, arch string) []string {
	if osName == "linux" && arch == "amd64" {
		return choiceRefAnchorsLinuxAmd64
	}
	// Fallback: re-use the linux/amd64 list. Caller will get a clear error if a
	// name is missing from another target.
	return choiceRefAnchorsLinuxAmd64
}

func choiceRefDefaultPath(osName, arch, pin, utc string) string {
	pinShort := pin
	if pinShort == "" {
		pinShort = "unpinned"
	}
	utcCompact := strings.ReplaceAll(strings.ReplaceAll(utc, "-", ""), ":", "")
	utcCompact = strings.ReplaceAll(utcCompact, "Z", "Z")
	name := fmt.Sprintf("phase_c_choice_table_%s-%s_%s_%s.json",
		osName, arch, pinShort, utcCompact)
	return filepath.Join("docs", "syzkaller-integration", "reports", name)
}
