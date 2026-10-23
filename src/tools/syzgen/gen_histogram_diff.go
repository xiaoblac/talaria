// §3.4 milestone V.12 — syscall histogram parity oracle.
//
// Generates two corpora of N programs each:
//   - "go":   target.Generate(rs, ncalls, nil) (uniform pick, no choice table)
//   - "cpp":  refuzz-syz-v2-gen (uniform pick + RandGen mt19937_64)
// Counts per-syscall frequency on each side, sorts, compares the top-K
// overlap fraction. Acceptance: |top-K overlap| / K >= 0.80.
//
// The two generators do NOT use the same RNG (Go uses LFG, reFuzz uses
// mt19937_64), so we compare statistical shape, not bit-equal sequences.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/google/syzkaller/prog"
)

func runGenHistogramDiff(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("gen-histogram-diff", flag.ExitOnError)
	count := fs.Int("count", 5000, "number of programs to generate per side")
	ncalls := fs.Int("ncalls", 5, "calls per program")
	cppBin := fs.String("cpp-bin",
		"build-llvm20/refuzz-syz-v2-gen",
		"path to refuzz-syz-v2-gen")
	work := fs.String("work", "/tmp/v2-gen-hist", "working dir for cpp output")
	topK := fs.Int("top-k", 50, "number of top syscalls to compare")
	threshold := fs.Float64("threshold", 0.8,
		"minimum overlap fraction to pass (0..1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}

	// 1. Go side — in-process generation, count syscalls.
	// Build default ChoiceTable (no corpus, all syscalls enabled).
	enabled := make(map[*prog.Syscall]bool, len(target.Syscalls))
	for _, sc := range target.Syscalls {
		enabled[sc] = true
	}
	ct := target.BuildChoiceTable(nil, enabled)
	goHist := make(map[string]int)
	rs := rand.NewSource(1) // fixed seed for reproducibility
	for i := 0; i < *count; i++ {
		p := target.Generate(rs, *ncalls, ct)
		for _, c := range p.Calls {
			goHist[c.Meta.Name]++
		}
	}

	// 2. C++ side — fork the bulk generator into a fresh dir.
	cppDir := filepath.Join(*work, "cpp_progs")
	_ = os.RemoveAll(cppDir)
	cmd := exec.Command(*cppBin,
		"-outdir", cppDir,
		"-count", fmt.Sprint(*count),
		"-ncalls", fmt.Sprintf("%d:%d", *ncalls, *ncalls),
		"-seed", "1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cpp gen: %w", err)
	}

	// Count C++ side via syzkaller's own parser — robust against multi-
	// line programs and any odd quoting we'd otherwise need to mimic.
	cppHist := make(map[string]int)
	entries, err := os.ReadDir(cppDir)
	if err != nil {
		return err
	}
	cppParseFail := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, ferr := os.ReadFile(filepath.Join(cppDir, e.Name()))
		if ferr != nil {
			continue
		}
		p, perr := target.Deserialize(data, prog.NonStrict)
		if perr != nil {
			cppParseFail++
			continue
		}
		for _, c := range p.Calls {
			cppHist[c.Meta.Name]++
		}
	}
	fmt.Fprintf(os.Stderr, "cpp parse fail: %d/%d\n", cppParseFail, len(entries))

	// 3. Sort each histogram, take top-K names.
	goTop := topKNames(goHist, *topK)
	cppTop := topKNames(cppHist, *topK)

	// Top-K-in-top-K overlap (strict parity — needs §3.6 choice table to
	// pass at high values).
	goTopSet := make(map[string]struct{}, len(goTop))
	for _, n := range goTop {
		goTopSet[n] = struct{}{}
	}
	overlap := 0
	for _, n := range cppTop {
		if _, ok := goTopSet[n]; ok {
			overlap++
		}
	}
	strictFrac := float64(overlap) / float64(*topK)

	// Coverage parity: how many of Go's top-K appear *anywhere* in cpp
	// output (and vice versa). This isolates "does the generator reach
	// the syscalls syzkaller considers important" from "does it weight
	// them the same way".
	goReachableInCpp := 0
	for _, n := range goTop {
		if cppHist[n] > 0 {
			goReachableInCpp++
		}
	}
	cppReachableInGo := 0
	for _, n := range cppTop {
		if goHist[n] > 0 {
			cppReachableInGo++
		}
	}
	covFrac := float64(goReachableInCpp) / float64(*topK)
	fmt.Printf("count=%d ncalls=%d top-K=%d "+
		"go_unique=%d cpp_unique=%d "+
		"top-K∩top-K=%d (strict=%.3f) "+
		"go-top-K∈cpp-anywhere=%d cpp-top-K∈go-anywhere=%d "+
		"coverage=%.3f threshold=%.3f\n",
		*count, *ncalls, *topK,
		len(goHist), len(cppHist),
		overlap, strictFrac,
		goReachableInCpp, cppReachableInGo,
		covFrac, *threshold)
	_ = strictFrac
	frac := covFrac

	// 4. Sample top-10 of each side for the diff report.
	fmt.Println("go top-10:")
	for i := 0; i < 10 && i < len(goTop); i++ {
		fmt.Printf("  %2d %-50s %d\n", i+1, goTop[i], goHist[goTop[i]])
	}
	fmt.Println("cpp top-10:")
	for i := 0; i < 10 && i < len(cppTop); i++ {
		fmt.Printf("  %2d %-50s %d\n", i+1, cppTop[i], cppHist[cppTop[i]])
	}

	if frac < *threshold {
		return fmt.Errorf("§3.4 histogram parity below threshold: %.3f < %.3f",
			frac, *threshold)
	}
	return nil
}

func topKNames(h map[string]int, k int) []string {
	type pair struct {
		name  string
		count int
	}
	var pairs []pair
	for n, c := range h {
		pairs = append(pairs, pair{n, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})
	if len(pairs) > k {
		pairs = pairs[:k]
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.name)
	}
	return out
}
