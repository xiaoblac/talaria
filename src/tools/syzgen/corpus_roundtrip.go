// L3 corpus round-trip driver.
//
// Single Go process: loads prog.Target once, runs Deserialize → Serialize on
// every file in -dir (or every record materialized from -corpus-db), writes to
// <godir>/<basename>. Then invokes the C++ batch tool once (also single-process
// load) to populate <cppdir>. Finally walks both dirs in-process and compares.
//
// Avoids the per-file process spawn that made the previous shell-loop unusably
// slow (process startup loaded the whole 30706-type Target each iteration).

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	syzdb "github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/prog"
)

func runCorpusRoundtrip(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("corpus-roundtrip", flag.ExitOnError)
	in := fs.String("dir", "", "input corpus directory")
	corpusDB := fs.String("corpus-db", "", "syzkaller corpus.db to materialize and round-trip")
	cppBin := fs.String("cpp-bin", "build-llvm20/refuzz-syz-v2-text-batch", "path to refuzz-syz-v2-text-batch")
	work := fs.String("work", "/tmp/l3", "working directory for outputs")
	failuresOut := fs.String("failures", "", "if set, write list of diff/failure files here")
	maxLog := fs.Int("max-show", 5, "show up to N diff samples")
	fixedPoint := fs.Bool("fixed-point", false, "L4: feed round-trip outputs back through both codecs and check idempotency")
	// Default: filter `# requires:` per syzkaller seed-loading semantics.
	// `sys/linux/test` is an OS-level test superset (mixes amd64-only,
	// arm64-only, manual, threaded variants). syzkaller itself runs every
	// .syz file through manager.ParseSeed, which calls parseRequires +
	// checkArch *before* Deserialize. Without that filter, arm64-only files
	// surface as "unknown syscall" on a linux/amd64 target — these are
	// expected skips, not parser bugs. Set false for raw scan mode.
	filterRequires := fs.Bool("filter-requires", true, "filter inputs by `# requires:` arch/properties (syzkaller-equivalent oracle gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*in == "") == (*corpusDB == "") {
		return fmt.Errorf("exactly one of -dir or -corpus-db is required")
	}
	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}

	// Wipe + recreate workdir so a previous run can't pollute stats via
	// stale outputs or .err sidecars.
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

	sourceDir := *in
	sourceLabel := *in
	if *corpusDB != "" {
		sourceDir = filepath.Join(*work, "db_input")
		version, records, err := materializeCorpusDB(*corpusDB, sourceDir, filepath.Join(*work, "corpus.db.copy"))
		if err != nil {
			return err
		}
		sourceLabel = fmt.Sprintf("%s (corpus.db version=%d records=%d)", *corpusDB, version, records)
	}

	entries, err := os.ReadDir(sourceDir)
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
	fmt.Fprintf(os.Stderr, "[L3] %d files in %s (filter-requires=%t)\n",
		len(files), sourceLabel, *filterRequires)

	// --- Go-side: in-process round-trip via manager.ParseSeed (which honors
	// `# requires:` arch and ErrSkippedTest), then Serialize.
	goOK, goFail, goSkipped := 0, 0, 0
	skipped := make(map[string]bool, 64) // names that should not enter the diff
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			goFail++
			if werr := writeRoundtripError(goDir, name, err); werr != nil {
				return werr
			}
			continue
		}
		var p *prog.Prog
		if *filterRequires {
			p, err = manager.ParseSeed(target, data)
			if errors.Is(err, manager.ErrSkippedTest) {
				goSkipped++
				skipped[name] = true
				// Leave goDir/<name> absent so the comparator treats it as skipped.
				continue
			}
		} else {
			p, err = target.Deserialize(data, prog.NonStrict)
		}
		if err != nil {
			goFail++
			if werr := writeRoundtripError(goDir, name, err); werr != nil {
				return werr
			}
			continue
		}
		out := p.Serialize()
		if err := writeRoundtripOutput(goDir, name, out); err != nil {
			return err
		}
		goOK++
	}
	fmt.Fprintf(os.Stderr, "[L3] go: ok=%d fail=%d skipped=%d\n",
		goOK, goFail, goSkipped)

	// --- C++ side: single batch invocation
	cmd := exec.Command(*cppBin, sourceDir, cppDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cpp batch: %w", err)
	}

	// --- Compare. Files that the Go-side oracle skipped per `# requires:`
	// are excluded from the diff entirely (they shouldn't be compared
	// against linux/amd64 codec output).
	type diffSample struct {
		name string
		go_  string
		cpp  string
	}
	var samples []diffSample
	match, diffCnt, bothFail := 0, 0, 0
	failureList := []string{}
	consideredTotal := 0
	for _, name := range files {
		if skipped[name] {
			continue
		}
		consideredTotal++
		gp := filepath.Join(goDir, name)
		cp := filepath.Join(cppDir, name)
		gErr := roundtripFailed(gp)
		cErr := roundtripFailed(cp)
		if gErr && cErr {
			bothFail++
			failureList = append(failureList, name)
			continue
		}
		gB, _ := os.ReadFile(gp)
		cB, _ := os.ReadFile(cp)
		if bytes.Equal(gB, cB) {
			match++
			continue
		}
		diffCnt++
		failureList = append(failureList, name)
		if len(samples) < *maxLog {
			samples = append(samples, diffSample{
				name: name,
				go_:  readOutputOrError(gp),
				cpp:  readOutputOrError(cp),
			})
		}
	}
	fmt.Printf("=== L3 corpus round-trip ===\n")
	fmt.Printf("total       : %d\n", len(files))
	fmt.Printf("skipped     : %d  (per `# requires:` filter; excluded from diff)\n", goSkipped)
	fmt.Printf("considered  : %d\n", consideredTotal)
	fmt.Printf("match       : %d\n", match)
	fmt.Printf("diff        : %d\n", diffCnt)
	fmt.Printf("both_fail   : %d\n", bothFail)
	denom := consideredTotal
	if denom == 0 {
		denom = 1
	}
	fmt.Printf("match%%      : %.1f%%  (of considered)\n",
		100.0*float64(match)/float64(denom))

	if *failuresOut != "" {
		os.WriteFile(*failuresOut, []byte(strings.Join(failureList, "\n")+"\n"), 0o644)
	}

	if len(samples) > 0 {
		fmt.Printf("\n=== sample diffs (first %d) ===\n", len(samples))
		for _, s := range samples {
			fmt.Printf("--- %s ---\n", s.name)
			showDiff(s.go_, s.cpp)
		}
	}

	if *fixedPoint {
		fmt.Printf("\n=== L4 fixed-point check ===\n")
		runFixedPoint(target, *cppBin, *work, goDir, cppDir, files, skipped)
	}
	return nil
}

func materializeCorpusDB(dbPath, outDir, dbCopyPath string) (uint64, int, error) {
	if err := os.RemoveAll(outDir); err != nil {
		return 0, 0, fmt.Errorf("clean db input dir: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, 0, fmt.Errorf("create db input dir: %w", err)
	}
	if err := copyFile(dbPath, dbCopyPath); err != nil {
		return 0, 0, fmt.Errorf("copy corpus db: %w", err)
	}
	db, err := syzdb.Open(dbCopyPath, false)
	if err != nil {
		return 0, 0, fmt.Errorf("open corpus db copy: %w", err)
	}
	keys := make([]string, 0, len(db.Records))
	for key := range db.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		rec := db.Records[key]
		name := corpusRecordFilename(i, key)
		if err := os.WriteFile(filepath.Join(outDir, name), rec.Val, 0o644); err != nil {
			return 0, 0, fmt.Errorf("write corpus record %s: %w", key, err)
		}
	}
	return db.Version, len(keys), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func corpusRecordFilename(index int, key string) string {
	safe := strings.Builder{}
	for _, ch := range key {
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '_' || ch == '-' {
			safe.WriteRune(ch)
		} else {
			safe.WriteByte('_')
		}
		if safe.Len() >= 80 {
			break
		}
	}
	if safe.Len() == 0 {
		safe.WriteString("record")
	}
	return fmt.Sprintf("%06d_%s.syz", index, safe.String())
}

func writeRoundtripOutput(dir, name string, body []byte) error {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write output %s: %w", path, err)
	}
	if err := os.Remove(path + ".err"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale error %s.err: %w", path, err)
	}
	return nil
}

func writeRoundtripError(dir, name string, cause error) error {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		return fmt.Errorf("write failed output %s: %w", path, err)
	}
	if err := os.WriteFile(path+".err", []byte(cause.Error()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write error sidecar %s.err: %w", path, err)
	}
	return nil
}

// L4: feed round-trip outputs back through both codecs and check that the
// canonical form converges (a second round-trip should be byte-identical).
// Files in `skipped` (from the per-`# requires:` filter) are excluded from
// both Go and C++ fixed-point counts so the two sides have a symmetric
// denominator.
func runFixedPoint(target *prog.Target, cppBin, work, goDir, cppDir string,
	files []string, skipped map[string]bool) {
	goDir2 := filepath.Join(work, "go2")
	cppDir2 := filepath.Join(work, "cpp2")
	for _, d := range []string{goDir2, cppDir2} {
		os.RemoveAll(d)
		os.MkdirAll(d, 0o755)
	}

	// Go side: re-roundtrip godir
	goStable, goDrift, goSkip := 0, 0, 0
	for _, name := range files {
		if skipped[name] {
			continue
		}
		path := filepath.Join(goDir, name)
		if roundtripFailed(path) {
			goSkip++
			continue
		}
		input, err := os.ReadFile(path)
		if err != nil {
			goSkip++
			continue
		}
		p, err := target.Deserialize(input, prog.NonStrict)
		if err != nil {
			goSkip++
			continue
		}
		out := p.Serialize()
		os.WriteFile(filepath.Join(goDir2, name), out, 0o644)
		if bytes.Equal(input, out) {
			goStable++
		} else {
			goDrift++
		}
	}

	// C++ side: re-roundtrip cppdir via batch tool. Note the C++ batch
	// scans cppDir wholesale; entries left there for skipped files would
	// be raw-decoded outputs whose `requires` line we deliberately want
	// to ignore. We post-filter by skipping them in the comparator below.
	cmd := exec.Command(cppBin, cppDir, cppDir2)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	cppStable, cppDrift, cppSkip := 0, 0, 0
	for _, name := range files {
		if skipped[name] {
			continue
		}
		aPath := filepath.Join(cppDir, name)
		bPath := filepath.Join(cppDir2, name)
		if roundtripFailed(aPath) || roundtripFailed(bPath) {
			cppSkip++
			continue
		}
		a, _ := os.ReadFile(aPath)
		b, _ := os.ReadFile(bPath)
		if bytes.Equal(a, b) {
			cppStable++
		} else {
			cppDrift++
		}
	}

	fmt.Printf("Go  fixed-point : stable=%d drift=%d skip(failed)=%d\n",
		goStable, goDrift, goSkip)
	fmt.Printf("C++ fixed-point : stable=%d drift=%d skip(failed)=%d\n",
		cppStable, cppDrift, cppSkip)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func roundtripFailed(p string) bool {
	return !fileExists(p) || fileExists(p+".err")
}

func readOutputOrError(p string) string {
	if errText, err := os.ReadFile(p + ".err"); err == nil {
		return "<ERR> " + string(errText)
	}
	body, _ := os.ReadFile(p)
	return string(body)
}

func showDiff(a, b string) {
	al := strings.Split(strings.TrimRight(a, "\n"), "\n")
	bl := strings.Split(strings.TrimRight(b, "\n"), "\n")
	maxLines := 4
	for i := 0; i < len(al) || i < len(bl); i++ {
		var av, bv string
		if i < len(al) {
			av = al[i]
		}
		if i < len(bl) {
			bv = bl[i]
		}
		if av != bv {
			fmt.Printf("  - go : %s\n", trim(av, 200))
			fmt.Printf("  + cpp: %s\n", trim(bv, 200))
			maxLines--
			if maxLines == 0 {
				break
			}
		}
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
