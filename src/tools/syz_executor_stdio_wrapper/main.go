// Layer-3 milestone III.9 — stdio shim for syzkaller's executor.
//
// PROTOCOL CONTRACT (shared with III.10 reFuzz-side harness):
//
//   stdin per program:
//     uint32 (little-endian)  -- wire bytes length
//     <length bytes>          -- syzkaller exec wire (output of
//                                prog.Prog.SerializeForExec / our
//                                program::syz::serialize_for_exec)
//
//   stdout per program:
//     JSON object on a single line:
//       {"status":"ok","results":[{"ret":N,"err":N},...],
//        "kcov_digest":"<16 lowercase hex chars>"}
//     or
//       {"status":"err","msg":"..."}
//
//   The stream may carry multiple programs in sequence; the shim
//   processes one at a time until EOF on stdin.
//
// THIS FILE IS A STUB. It does NOT actually execute programs against a
// kernel. It returns deterministic placeholder ret/err values so the
// paired-VM orchestrator (III.12) can be exercised end-to-end without
// a real VM. Replace this main.go with a real implementation that:
//
//   (a) speaks syzkaller's IPC protocol (pkg/ipc, see syzkaller's
//       cmd/syz-executor for the producer side), or
//   (b) shells out to executor.cc with a minimal stdio adapter, or
//   (c) embeds the syzkaller `prog` package + a thin syscall harness.
//
// Until the swap happens, the orchestrator (III.12) treats this side
// as opaque — it simply diffs the two harnesses' outputs.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	mode := flag.String("mode", "stub",
		"stub | real (real requires syzkaller pkg/ipc — TODO)")
	flag.Parse()
	if *mode != "stub" {
		fmt.Fprintln(os.Stderr, "real mode not yet implemented; see file header")
		os.Exit(2)
	}

	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fmt.Fprintln(os.Stderr, "len read:", err)
			os.Exit(1)
		}
		size := binary.LittleEndian.Uint32(lenBuf[:])
		if size == 0 || size > (4<<20) {
			fmt.Fprintf(os.Stderr, "bad size: %d\n", size)
			os.Exit(1)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(r, body); err != nil {
			fmt.Fprintln(os.Stderr, "body read:", err)
			os.Exit(1)
		}

		// STUB: pretend each call returns ret=0,err=0; kcov_digest is a
		// SHA-256-derived 64-bit token (deterministic per program). A real
		// implementation would actually execute and capture the kernel
		// PC set.
		ncalls, err := countCalls(body)
		if err != nil {
			fmt.Fprintf(w, `{"status":"err","msg":%q}`+"\n", err.Error())
			continue
		}
		digest := sha256.Sum256(body)
		fmt.Fprint(w, `{"status":"ok","results":[`)
		for i := 0; i < ncalls; i++ {
			if i != 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprint(w, `{"ret":0,"err":0}`)
		}
		fmt.Fprintf(w, `],"kcov_digest":"%s"}`+"\n",
			hex.EncodeToString(digest[:8]))
		w.Flush()
	}
}

// countCalls peeks the wire to extract n_calls (the first varint). Used
// by the stub so its result has a plausible per-call shape; a real
// executor wouldn't need to do this.
func countCalls(body []byte) (int, error) {
	v, _, err := readVarint(body)
	if err != nil {
		return 0, err
	}
	if v > (1 << 30) {
		return 0, fmt.Errorf("absurd n_calls %d", v)
	}
	return int(int64(v)), nil
}

// readVarint mirrors binary.Varint (zig-zag).
func readVarint(buf []byte) (uint64, int, error) {
	var ux uint64
	var shift uint
	for i, b := range buf {
		if shift > 63 {
			return 0, 0, fmt.Errorf("varint overflow")
		}
		ux |= uint64(b&0x7F) << shift
		if (b & 0x80) == 0 {
			signedX := int64(ux>>1) ^ -int64(ux&1)
			return uint64(signedX), i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("varint truncated")
}
