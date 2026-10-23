// syz_flatrpc_trace_dump — read a trace file produced by syz_flatrpc_proxy
// and print one record per line. Used to validate trace format manually
// and as the PR1 "re-parseable" acceptance.
//
// See docs/plans/production-exec-paired-oracle.md §5.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	traceMagic     = "REFUZZTR"
	traceHeaderLen = 64
)

const (
	recSessionOpen    uint8 = 0x01
	recFrameH2E       uint8 = 0x02
	recFrameE2H       uint8 = 0x03
	recSessionClose   uint8 = 0x04
	recTraceOverflow  uint8 = 0x05
	recDecodedSummary uint8 = 0x10
)

func main() {
	var (
		flagFile               = flag.String("f", "", "trace file (required)")
		flagJSON               = flag.Bool("json", false, "emit one JSON object per record")
		flagAllowTruncatedTail = flag.Bool("allow-truncated-tail", false, "treat a final partial record as a warning and exit successfully")
	)
	flag.Parse()
	if *flagFile == "" {
		log.Fatalf("syz_flatrpc_trace_dump: -f required")
	}
	f, err := os.Open(*flagFile)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer f.Close()

	var hdr [traceHeaderLen]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		log.Fatalf("read header: %v", err)
	}
	if string(hdr[0:8]) != traceMagic {
		log.Fatalf("bad magic: %q", hdr[0:8])
	}
	offset := int64(traceHeaderLen)
	emit(map[string]any{
		"_kind":             "header",
		"version":           binary.LittleEndian.Uint32(hdr[8:12]),
		"created_unix_ns":   binary.LittleEndian.Uint64(hdr[12:20]),
		"syzkaller_git_rev": nullTrim(hdr[20:60]),
	}, *flagJSON)

	for {
		var sizeBuf [4]byte
		n, err := io.ReadFull(f, sizeBuf[:])
		if err == io.EOF {
			return
		} else if err != nil {
			if *flagAllowTruncatedTail && err == io.ErrUnexpectedEOF {
				emit(map[string]any{
					"_kind":      "truncated_tail",
					"offset":     offset,
					"phase":      "record_size",
					"bytes_read": n,
				}, *flagJSON)
				return
			}
			log.Fatalf("read rec size: %v", err)
		}
		recSize := binary.LittleEndian.Uint32(sizeBuf[:])
		if recSize < 17 {
			log.Fatalf("rec_size %d too small", recSize)
		}
		buf := make([]byte, recSize)
		n, err = io.ReadFull(f, buf)
		if err != nil {
			if *flagAllowTruncatedTail && err == io.ErrUnexpectedEOF {
				emit(map[string]any{
					"_kind":        "truncated_tail",
					"offset":       offset,
					"phase":        "record_body",
					"record_size":  recSize,
					"bytes_read":   n,
					"bytes_needed": int(recSize) - n,
				}, *flagJSON)
				return
			}
			log.Fatalf("read rec: %v", err)
		}
		offset += int64(4 + recSize)
		rec := buf[0]
		seq := binary.LittleEndian.Uint64(buf[1:9])
		ts := int64(binary.LittleEndian.Uint64(buf[9:17]))
		body := buf[17:]
		out := map[string]any{
			"_kind": recName(rec),
			"seq":   seq,
			"ts_ns": ts,
		}
		switch rec {
		case recSessionOpen:
			out["session_id"] = binary.LittleEndian.Uint64(body[0:8])
			out["vm_index"] = binary.LittleEndian.Uint32(body[8:12])
			out["proxy_pid"] = binary.LittleEndian.Uint32(body[12:16])
			addrLen := binary.LittleEndian.Uint16(body[16:18])
			out["manager_addr"] = string(body[18 : 18+int(addrLen)])
		case recFrameH2E, recFrameE2H:
			out["body_size"] = binary.LittleEndian.Uint32(body[0:4])
			out["full_len"] = len(body)
		case recSessionClose:
			out["reason"] = closeName(body[0])
			msgLen := binary.LittleEndian.Uint16(body[1:3])
			if msgLen > 0 {
				out["error_msg"] = string(body[3 : 3+int(msgLen)])
			}
		case recDecodedSummary:
			out["dir"] = dirName(body[0])
			out["kind"] = kindName(body[1])
			jsonLen := binary.LittleEndian.Uint16(body[2:4])
			if jsonLen > 0 {
				var s any
				_ = json.Unmarshal(body[4:4+int(jsonLen)], &s)
				out["summary"] = s
			}
		case recTraceOverflow:
			out["dropped"] = binary.LittleEndian.Uint64(body[0:8])
		}
		emit(out, *flagJSON)
	}
}

func emit(v map[string]any, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
		return
	}
	fmt.Printf("%+v\n", v)
}

func nullTrim(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func recName(r uint8) string {
	switch r {
	case recSessionOpen:
		return "session_open"
	case recFrameH2E:
		return "frame_h2e"
	case recFrameE2H:
		return "frame_e2h"
	case recSessionClose:
		return "session_close"
	case recTraceOverflow:
		return "trace_overflow"
	case recDecodedSummary:
		return "decoded_summary"
	}
	return fmt.Sprintf("unknown(0x%02x)", r)
}

func dirName(d uint8) string {
	switch d {
	case 1:
		return "h2e"
	case 2:
		return "e2h"
	}
	return fmt.Sprintf("dir(0x%02x)", d)
}

func kindName(k uint8) string {
	switch k {
	case 0:
		return "none"
	case 1:
		return "exec_request"
	case 2:
		return "executing"
	case 3:
		return "exec_result"
	case 4:
		return "signal_update"
	case 5:
		return "corpus_triaged"
	case 6:
		return "state_request"
	case 7:
		return "state_result"
	case 0xFF:
		return "parse_error"
	}
	return fmt.Sprintf("kind(0x%02x)", k)
}

func closeName(r uint8) string {
	switch r {
	case 0:
		return "eof"
	case 1:
		return "error"
	case 2:
		return "killed"
	}
	return fmt.Sprintf("reason(0x%02x)", r)
}
