// corpus-unpack-db: lift a syzkaller corpus.db into a flat directory of
// .syz text files, one per record. Reuses materializeCorpusDB so the
// on-disk shape matches corpus-roundtrip's db_input/ stage exactly.
//
// Used by scripts/bench_single_worker_compare.py to seed a reFuzz run with
// the corpus a syzkaller run produced: this stage emits raw syz-prog text
// (the same bytes reFuzz materializer kSyzProg already decodes for fuzz
// corpus loading, exec-replayer, and L3 paired-oracle).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/prog"
)

func runCorpusUnpackDB(_ *prog.Target, args []string) error {
	fs := flag.NewFlagSet("corpus-unpack-db", flag.ExitOnError)
	corpusDB := fs.String("corpus-db", "", "syzkaller corpus.db to unpack")
	outDir := fs.String("out", "", "output directory for unpacked .syz files (will be wiped)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusDB == "" || *outDir == "" {
		return fmt.Errorf("both -corpus-db and -out are required")
	}
	if _, err := os.Stat(*corpusDB); err != nil {
		return fmt.Errorf("corpus-db: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(*outDir), 0o755); err != nil {
		return fmt.Errorf("create out parent: %w", err)
	}
	dbCopy := filepath.Join(filepath.Dir(*outDir), filepath.Base(*outDir)+".db.copy")
	defer os.Remove(dbCopy)
	version, records, err := materializeCorpusDB(*corpusDB, *outDir, dbCopy)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[corpus-unpack-db] %s → %s (version=%d records=%d)\n",
		*corpusDB, *outDir, version, records)
	return nil
}
