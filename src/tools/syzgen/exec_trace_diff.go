// Layer-3 milestone I.4 — trace-equivalence oracle.
//
// Runs the Go reference dumper and the C++ wire-walking dumper on the
// same corpus, then byte-equal compares JSONL line-for-line.
//
// Acceptance: 821/821 match on the L3 filtered corpus (same denominator
// as the §3.2 byte-equal-vs-syzkaller and §3.3 Layer-1 round-trip oracles).

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/prog"
)

func runExecTraceDiff(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("exec-trace-diff", flag.ExitOnError)
	in := fs.String("dir", "", "input corpus directory")
	cppBin := fs.String("cpp-bin", "build-llvm20/refuzz-syz-v2-exec-trace",
		"path to refuzz-syz-v2-exec-trace")
	work := fs.String("work", "/tmp/l3-trace", "working directory for outputs")
	maxLog := fs.Int("max-show", 5, "show up to N diff samples")
	failuresOut := fs.String("failures", "", "if set, write list of mismatched files here")
	filterRequires := fs.Bool("filter-requires", true,
		"filter inputs by `# requires:` (passed through to the Go dumper)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-dir is required")
	}
	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}

	goPath := filepath.Join(*work, "go.jsonl")
	cppPath := filepath.Join(*work, "cpp.jsonl")

	// 1. Go dumper (in-process for speed; reuses already-loaded target).
	goArgs := []string{"-dir", *in, "-out", goPath,
		fmt.Sprintf("-filter-requires=%t", *filterRequires)}
	if err := runExecTraceDump(target, goArgs); err != nil {
		return fmt.Errorf("go dumper: %w", err)
	}

	// 2. C++ dumper as subprocess.
	cmd := exec.Command(*cppBin, *in, "-o", cppPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cpp dumper: %w", err)
	}

	// 3. Build per-file maps from each JSONL.
	goByFile, err := indexByFile(goPath)
	if err != nil {
		return err
	}
	cppByFile, err := indexByFile(cppPath)
	if err != nil {
		return err
	}

	// 4. Diff.
	match := 0
	mismatch := 0
	goOnly := 0
	cppOnly := 0
	var samples []string
	var mismatched []string
	allFiles := make(map[string]struct{}, len(goByFile)+len(cppByFile))
	for f := range goByFile {
		allFiles[f] = struct{}{}
	}
	for f := range cppByFile {
		allFiles[f] = struct{}{}
	}
	for f := range allFiles {
		gline, gOK := goByFile[f]
		cline, cOK := cppByFile[f]
		if gOK && !cOK {
			goOnly++
			continue
		}
		if cOK && !gOK {
			// C++ dumped but Go filter skipped → the requires-filter
			// said this is out-of-scope; don't penalize.
			cppOnly++
			continue
		}
		if bytes.Equal([]byte(gline), []byte(cline)) {
			match++
			continue
		}
		mismatch++
		mismatched = append(mismatched, f)
		if len(samples) < *maxLog {
			samples = append(samples, formatTraceDiff(f, gline, cline))
		}
	}

	fmt.Printf("source=%s match=%d mismatch=%d cpp_only(filtered_by_requires)=%d go_only=%d\n",
		*in, match, mismatch, cppOnly, goOnly)
	if len(samples) > 0 {
		fmt.Println("samples:")
		for _, s := range samples {
			fmt.Println("  " + s)
		}
	}
	if *failuresOut != "" && len(mismatched) > 0 {
		f, ferr := os.Create(*failuresOut)
		if ferr == nil {
			defer f.Close()
			for _, m := range mismatched {
				fmt.Fprintln(f, m)
			}
		}
	}
	if mismatch > 0 || goOnly > 0 {
		return fmt.Errorf("§3.3 Layer-3 trace-equiv: %d mismatches, %d go-only",
			mismatch, goOnly)
	}
	return nil
}

// indexByFile reads JSONL and returns map[file]line.
// Tolerates duplicate file entries (last one wins).
func indexByFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		// Pull `"file":"<name>"` out of the prefix.
		const key = `"file":"`
		idx := strings.Index(line, key)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(key):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			continue
		}
		name := rest[:end]
		out[name] = line
	}
	return out, nil
}

func formatTraceDiff(name, a, b string) string {
	if len(a) != len(b) {
		first := -1
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				first = i
				break
			}
		}
		if first < 0 {
			first = minInt(len(a), len(b))
		}
		return fmt.Sprintf("%s: lengths differ go=%d cpp=%d, first-diff=%d, prefix=%q",
			name, len(a), len(b), first, a[max(0, first-20):minInt(len(a), first+20)])
	}
	for i := range a {
		if a[i] != b[i] {
			lo := max(0, i-20)
			hi := minInt(len(a), i+20)
			return fmt.Sprintf("%s: byte %d differs go=0x%02x cpp=0x%02x, ctx=%q",
				name, i, a[i], b[i], a[lo:hi])
		}
	}
	return name + ": equal"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
