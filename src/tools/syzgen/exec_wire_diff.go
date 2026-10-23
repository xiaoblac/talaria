// §3.2 oracle: byte-equal exec-wire on the L3 corpus.
//
// Single Go process: loads prog.Target once, walks -dir, for each file
// runs manager.ParseSeed (so `# requires:` filtering matches syzkaller's
// own seed-loading semantics), then SerializeForExec, writing bytes to
// <godir>/<basename>. Forks the C++ batch tool once to populate <cppdir>
// from the same input. Compares each output file byte-for-byte and
// reports a per-file diff summary.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/prog"
)

func runExecWireDiff(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("exec-wire-diff", flag.ExitOnError)
	in := fs.String("dir", "", "input corpus directory")
	cppBin := fs.String("cpp-bin", "build-llvm20/refuzz-syz-v2-exec-wire",
		"path to refuzz-syz-v2-exec-wire")
	work := fs.String("work", "/tmp/l3-exec", "working directory for outputs")
	maxLog := fs.Int("max-show", 5, "show up to N diff samples")
	failuresOut := fs.String("failures", "", "if set, write list of diff/failure files here")
	filterRequires := fs.Bool("filter-requires", true,
		"filter inputs by `# requires:` arch/properties (syzkaller-equivalent oracle gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-dir is required")
	}

	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}
	goDir := filepath.Join(*work, "go")
	cppDir := filepath.Join(*work, "cpp")
	for _, d := range []string{goDir, cppDir} {
		if err := os.RemoveAll(d); err != nil {
			return fmt.Errorf("clean %s: %w", d, err)
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	entries, err := os.ReadDir(*in)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)

	// Pass 1: Go side.
	considered := 0
	skipped := 0
	goEncoded := 0
	goSkipKfuzz := 0
	goFail := 0
	for _, name := range files {
		path := filepath.Join(*in, name)
		text, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if *filterRequires {
			p, err := manager.ParseSeed(target, text)
			if errors.Is(err, manager.ErrSkippedTest) {
				skipped++
				continue
			}
			if err != nil {
				goFail++
				continue
			}
			if hasKFuzzTest(p) {
				goSkipKfuzz++
				continue
			}
			considered++
			b, err := p.SerializeForExec()
			if err != nil {
				goFail++
				continue
			}
			if err := os.WriteFile(filepath.Join(goDir, name), b, 0o644); err != nil {
				return err
			}
			goEncoded++
		} else {
			p, err := target.Deserialize(text, prog.NonStrict)
			if err != nil {
				goFail++
				continue
			}
			if hasKFuzzTest(p) {
				goSkipKfuzz++
				continue
			}
			considered++
			b, err := p.SerializeForExec()
			if err != nil {
				goFail++
				continue
			}
			if err := os.WriteFile(filepath.Join(goDir, name), b, 0o644); err != nil {
				return err
			}
			goEncoded++
		}
	}

	// Pass 2: C++ side.
	cmd := exec.Command(*cppBin, *in, cppDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cpp tool: %w", err)
	}

	// Pass 3: byte-diff each pair where Go produced a file. Files Go did
	// not produce (e.g. cross-arch via `# requires:`) are out-of-scope —
	// the Go-side ParseSeed filter is the canonical oracle gate, and the
	// C++ batch tool deliberately doesn't replicate it (its job is
	// "encode every program the codec accepts").
	match := 0
	mismatch := 0
	cppOnly := 0
	goOnly := 0
	var samples []string
	for _, name := range files {
		gpath := filepath.Join(goDir, name)
		cpath := filepath.Join(cppDir, name)
		gd, gerr := os.ReadFile(gpath)
		cd, cerr := os.ReadFile(cpath)
		goPresent := gerr == nil
		cpPresent := cerr == nil
		if !goPresent && !cpPresent {
			continue
		}
		if !goPresent {
			cppOnly++
			continue
		}
		if !cpPresent {
			goOnly++
			if len(samples) < *maxLog {
				samples = append(samples, fmt.Sprintf("[go-only] %s", name))
			}
			continue
		}
		if bytes.Equal(gd, cd) {
			match++
			continue
		}
		mismatch++
		if len(samples) < *maxLog {
			samples = append(samples, formatByteDiff(name, gd, cd))
		}
	}

	fmt.Printf("source=%s files=%d considered=%d skipped(requires)=%d skipped(kfuzz)=%d "+
		"go_fail=%d match=%d mismatch=%d cpp_only(filtered_by_requires)=%d go_only=%d\n",
		*in, len(files), considered, skipped, goSkipKfuzz, goFail, match, mismatch, cppOnly, goOnly)
	if len(samples) > 0 {
		fmt.Println("samples:")
		for _, s := range samples {
			fmt.Println("  " + s)
		}
	}
	if *failuresOut != "" && (mismatch > 0 || goOnly > 0) {
		f, err := os.Create(*failuresOut)
		if err == nil {
			defer f.Close()
			for _, name := range files {
				gpath := filepath.Join(goDir, name)
				cpath := filepath.Join(cppDir, name)
				gd, gerr := os.ReadFile(gpath)
				cd, cerr := os.ReadFile(cpath)
				if gerr == nil && cerr != nil {
					fmt.Fprintf(f, "%s\tgo-only\n", name)
					continue
				}
				if gerr == nil && cerr == nil && !bytes.Equal(gd, cd) {
					fmt.Fprintf(f, "%s\tdiff\n", name)
				}
			}
		}
	}
	if mismatch > 0 || goOnly > 0 {
		return fmt.Errorf("§3.2 oracle: %d mismatches, %d go-only", mismatch, goOnly)
	}
	return nil
}

func hasKFuzzTest(p *prog.Prog) bool {
	for _, c := range p.Calls {
		if c.Meta != nil && c.Meta.Attrs.KFuzzTest {
			return true
		}
	}
	return false
}

// formatByteDiff returns "<name>: differ at offset N (go=0xXX cpp=0xYY) | sizes go=A cpp=B".
func formatByteDiff(name string, a, b []byte) string {
	if len(a) != len(b) {
		first := -1
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				first = i
				break
			}
		}
		if first < 0 {
			first = min(len(a), len(b))
		}
		return fmt.Sprintf("%s: sizes differ go=%d cpp=%d, first-diff=%d", name, len(a), len(b), first)
	}
	for i := range a {
		if a[i] != b[i] {
			return fmt.Sprintf("%s: byte %d differs (go=0x%02x cpp=0x%02x), size=%d",
				name, i, a[i], b[i], len(a))
		}
	}
	return fmt.Sprintf("%s: bytes.Equal returned false but no byte differs (impossible)", name)
}

