// Layer-3 milestone I.2 — Go-side reference trace dumper.
//
// Walks `prog.Prog` IR directly (independent of the wire-byte path) and
// emits one JSONL line per program with the dispatch shape that
// SerializeForExec would produce for each call. The C++ counterpart
// (refuzz-syz-v2-exec-trace) walks wire bytes via decode_exec_wire,
// so the two extractors are independent information sources.
//
// Schema is documented in
//   program/include/refuzz/program/syz/exec_trace.hpp
//
// Usage:
//   syzgen exec-trace-dump -dir <corpus> -out <go.jsonl>
//                          [-filter-requires=true]

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/prog"
)

func runExecTraceDump(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("exec-trace-dump", flag.ExitOnError)
	in := fs.String("dir", "", "input corpus directory")
	out := fs.String("out", "", "output JSONL path (default stdout)")
	filterRequires := fs.Bool("filter-requires", true,
		"filter inputs by `# requires:` arch/properties (syzkaller-equivalent oracle gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-dir is required")
	}

	var w *bufio.Writer
	if *out == "" || *out == "-" {
		w = bufio.NewWriter(os.Stdout)
	} else {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = bufio.NewWriter(f)
	}
	defer w.Flush()

	entries, err := os.ReadDir(*in)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Epic 2 step-1: typed Target's SyscallMeta::nr now carries
	// pseudoNrBase+i for syz_*; the C++ trace extractor reads NR via
	// the wire decoder which goes through that synthesized value. The
	// Go trace walks prog.Prog where syz_*.Meta.NR is still 0, so we
	// substitute via the shared SynthesizePseudoNRs helper to keep
	// the diff oracle byte-equal.
	pseudoSynth := SynthesizePseudoNRs(target)

	considered := 0
	skippedReq := 0
	skippedKfuzz := 0
	failParse := 0
	emitted := 0
	for _, name := range files {
		path := filepath.Join(*in, name)
		text, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var p *prog.Prog
		if *filterRequires {
			pp, err := manager.ParseSeed(target, text)
			if errors.Is(err, manager.ErrSkippedTest) {
				skippedReq++
				continue
			}
			if err != nil {
				failParse++
				continue
			}
			p = pp
		} else {
			pp, err := target.Deserialize(text, prog.NonStrict)
			if err != nil {
				failParse++
				continue
			}
			p = pp
		}
		if hasKFuzzTest(p) {
			skippedKfuzz++
			continue
		}
		considered++
		if err := emitProgTrace(w, target, name, p, pseudoSynth); err != nil {
			return err
		}
		emitted++
	}
	fmt.Fprintf(os.Stderr,
		"go trace: files=%d considered=%d emitted=%d skipped(requires)=%d "+
			"skipped(kfuzz)=%d fail_parse=%d\n",
		len(files), considered, emitted, skippedReq, skippedKfuzz, failParse)
	return nil
}

// hasKFuzzTest is shared with exec_wire_diff.go.

func emitProgTrace(w *bufio.Writer, target *prog.Target, name string, p *prog.Prog,
	pseudoSynth map[string]PseudoSynthEntry) error {
	fmt.Fprintf(w, `{"file":%q,"calls":[`, name)
	for i, c := range p.Calls {
		if i != 0 {
			fmt.Fprint(w, ",")
		}
		nr := c.Meta.NR
		if entry, ok := pseudoSynth[c.Meta.Name]; ok {
			nr = entry.NR
		}
		fmt.Fprintf(w, `{"nr":%d,"args":[`, nr)
		for j, a := range c.Args {
			if j != 0 {
				fmt.Fprint(w, ",")
			}
			emitArgTag(w, target, a)
		}
		fmt.Fprint(w, "]}")
	}
	fmt.Fprintln(w, "]}")
	return nil
}

// emitArgTag mirrors prog/encodingexec.go writeArg dispatch.
func emitArgTag(w *bufio.Writer, target *prog.Target, a prog.Arg) {
	switch v := a.(type) {
	case *prog.ConstArg:
		val, pidStride := v.Value()
		typ := v.Type()
		emitConstTag(w, typ.UnitSize(), val,
			typ.BitfieldOffset(), typ.BitfieldLength(), pidStride,
			uint64(typ.Format()))
	case *prog.ResultArg:
		if v.Res == nil {
			emitConstTag(w, v.Size(), v.Val, 0, 0, 0,
				uint64(v.Type().Format()))
			return
		}
		def := uint64(0)
		if rt, ok := v.Type().(*prog.ResourceType); ok {
			def = rt.Default()
		}
		fmt.Fprintf(w,
			`{"k":"R","sz":%d,"f":%d,"d":%d,"a":%d,"def":%d}`,
			v.Size(), uint64(v.Type().Format()), v.OpDiv, v.OpAdd, def)
	case *prog.PointerArg:
		off := target.PhysicalAddr(v) - target.DataOffset
		fmt.Fprintf(w, `{"k":"P","sz":%d,"o":%d}`, v.Size(), off)
	case *prog.DataArg:
		data := v.Data()
		readable := false
		if bt, ok := v.Type().(*prog.BufferType); ok {
			switch bt.Kind {
			case prog.BufferString, prog.BufferFilename, prog.BufferGlob:
				readable = true
			}
		}
		fmt.Fprintf(w, `{"k":"D","h":%q,"r":%t}`, hex.EncodeToString(data), readable)
	case *prog.UnionArg:
		// UnionArg is transparent in the wire — recurse into Option.
		emitArgTag(w, target, v.Option)
	default:
		fmt.Fprint(w, `{"k":"?"}`)
	}
}

func emitConstTag(w *bufio.Writer, sz, v, bo, bl, ps, f uint64) {
	fmt.Fprintf(w,
		`{"k":"C","sz":%d,"v":%d,"f":%d,"bo":%d,"bl":%d,"ps":%d}`,
		sz, v, f, bo, bl, ps)
}
