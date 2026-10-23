// seeds-unpack: enumerate syzkaller's built-in seed files (sys/<os>/test/*),
// sorted by filename, deterministically convert each into a CONCRETE program
// (resolving the seed `AUTO` placeholders via target.Deserialize, the same core
// as pkg/manager ParseSeed) and write `<016d>.syz` text — the same on-disk shape
// corpus-unpack-db produces, so both syz-execprog and the reFuzz replayer consume
// it identically.
//
// This is the STABLE corpus source for scripts/speed_compare/speed_compare.py (replacing the
// nondeterministic syz-manager corpus-triage): the seed files are static, the
// sort is by filename, and target.Deserialize has no randomness — so the same
// tree comes out every run. No execution, no coverage, no filtering.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

// seedRequires / seedArchOK mirror pkg/manager/seeds.go (kept local to avoid a
// heavy pkg/manager import). Only the arch requirement is honored here — seeds
// whose `# requires: arch=...` excludes the target arch can't deserialize and
// are skipped; everything else is parsed regardless of other `requires` (run-time
// applicability like sandbox is not a parse concern).
func seedRequires(data []byte) map[string]bool {
	requires := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		const prefix = "# requires:"
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, req := range strings.Fields(line[len(prefix):]) {
			positive := true
			if len(req) > 0 && req[0] == '-' {
				positive = false
				req = req[1:]
			}
			if req != "" {
				requires[req] = positive
			}
		}
	}
	return requires
}

func seedArchOK(requires map[string]bool, arch string) bool {
	for req, positive := range requires {
		const p = "arch="
		if strings.HasPrefix(req, p) && (arch != req[len(p):]) == positive {
			return false
		}
	}
	return true
}

func runSeedsUnpack(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("seeds-unpack", flag.ExitOnError)
	seedsDir := fs.String("seeds-dir", "", "directory of syzkaller seed files (eg. sys/linux/test)")
	outDir := fs.String("out", "", "output dir for concrete <016d>.syz files (wiped)")
	skipOut := fs.String("skip-out", "", "optional CSV of skipped seeds: seed_id,file,stage,error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seedsDir == "" || *outDir == "" {
		return fmt.Errorf("both -seeds-dir and -out are required")
	}
	ents, err := os.ReadDir(*seedsDir)
	if err != nil {
		return fmt.Errorf("read seeds dir %s: %w", *seedsDir, err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // stable order by filename

	if err := os.RemoveAll(*outDir); err != nil {
		return fmt.Errorf("wipe out dir: %w", err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	// skips: seed_id (assigned to attempted files, 0 for skipped), file, stage, error.
	skips := []string{"seed_id,file,stage,error"}
	idx := 0
	for _, name := range names {
		path := filepath.Join(*seedsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			skips = append(skips, fmt.Sprintf(",%s,read,%s", name, oneLine(err.Error())))
			continue
		}
		if !seedArchOK(seedRequires(data), target.Arch) {
			skips = append(skips, fmt.Sprintf(",%s,arch,requires arch != %s", name, target.Arch))
			continue
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			skips = append(skips, fmt.Sprintf(",%s,deserialize,%s", name, oneLine(err.Error())))
			continue
		}
		idx++
		out := filepath.Join(*outDir, fmt.Sprintf("%016d.syz", idx))
		if err := os.WriteFile(out, p.Serialize(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
	}
	if *skipOut != "" {
		if err := os.WriteFile(*skipOut, []byte(strings.Join(skips, "\n")+"\n"), 0o644); err != nil {
			return fmt.Errorf("write skip-out: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "[seeds-unpack] %s → %s (converted=%d skipped=%d)\n",
		*seedsDir, *outDir, idx, len(skips)-1)
	return nil
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), ",", ";")
}
