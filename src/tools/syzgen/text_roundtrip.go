// Go-side text round-trip oracle for the reFuzz v2 text codec.
//
// Reads a .syz file from -in (default stdin), runs prog.Deserialize then
// prog.Serialize, and writes the canonical form to stdout. Compared
// byte-for-byte with refuzz-syz-v2-text output to prove parity.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/syzkaller/prog"
)

func runTextRoundtrip(target *prog.Target, args []string) error {
	fs := flag.NewFlagSet("text-roundtrip", flag.ExitOnError)
	in := fs.String("in", "", "input .syz file (default: stdin)")
	mode := fs.String("mode", "non-strict", "decode mode: strict | non-strict")
	osName := fs.String("os", "", "override target OS (default: linux)")
	arch := fs.String("arch", "", "override target arch (default: amd64)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *osName != "" || *arch != "" {
		o := "linux"
		a := "amd64"
		if *osName != "" {
			o = *osName
		}
		if *arch != "" {
			a = *arch
		}
		t2, err := prog.GetTarget(o, a)
		if err != nil {
			return fmt.Errorf("GetTarget(%s/%s): %w", o, a, err)
		}
		target = t2
	}

	var data []byte
	var err error
	if *in == "" || *in == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(*in)
	}
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	dm := prog.NonStrict
	switch *mode {
	case "strict":
		dm = prog.Strict
	case "non-strict":
		dm = prog.NonStrict
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}

	p, err := target.Deserialize(data, dm)
	if err != nil {
		return fmt.Errorf("deserialize: %w", err)
	}
	out := p.Serialize()
	if _, err := os.Stdout.Write(out); err != nil {
		return err
	}
	return nil
}

