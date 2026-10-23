package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Trace file format. See docs/plans/production-exec-paired-oracle.md §5.

const (
	traceMagic     = "REFUZZTR"
	traceVersion   = uint32(1)
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

const (
	closeEOF    uint8 = 0
	closeError  uint8 = 1
	closeKilled uint8 = 2
)

type traceWriter struct {
	mu sync.Mutex
	f  *os.File
	bw *bufio.Writer
}

func openTraceWriter(path, gitRev string) (*traceWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	if err := writeHeader(bw, gitRev); err != nil {
		f.Close()
		return nil, err
	}
	return &traceWriter{f: f, bw: bw}, nil
}

func writeHeader(w io.Writer, gitRev string) error {
	var hdr [traceHeaderLen]byte
	copy(hdr[0:8], traceMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], traceVersion)
	binary.LittleEndian.PutUint64(hdr[12:20], uint64(time.Now().UnixNano()))
	gr := gitRev
	if len(gr) > 40 {
		gr = gr[:40]
	}
	copy(hdr[20:60], gr)
	_, err := w.Write(hdr[:])
	return err
}

// writeRecord writes one record: 4-byte LE size prefix, 1-byte type,
// 8-byte seq, 8-byte ts_ns, body. rec_size excludes the leading prefix.
func (tw *traceWriter) writeRecord(rec uint8, seq uint64, ts int64, body []byte) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	recSize := uint32(1 + 8 + 8 + len(body))
	var hdr [4 + 1 + 8 + 8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], recSize)
	hdr[4] = rec
	binary.LittleEndian.PutUint64(hdr[5:13], seq)
	binary.LittleEndian.PutUint64(hdr[13:21], uint64(ts))
	if _, err := tw.bw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := tw.bw.Write(body)
	return err
}

func (tw *traceWriter) WriteSessionOpen(sessionID uint64, vmIndex, pid uint32, mgrAddr string) error {
	body := make([]byte, 0, 8+4+4+2+len(mgrAddr))
	body = appendU64(body, sessionID)
	body = appendU32(body, vmIndex)
	body = appendU32(body, pid)
	body = appendStr16(body, mgrAddr)
	return tw.writeRecord(recSessionOpen, 0, time.Now().UnixNano(), body)
}

func (tw *traceWriter) WriteSessionClose(reason uint8, errMsg string) error {
	body := make([]byte, 0, 1+2+len(errMsg))
	body = append(body, reason)
	body = appendStr16(body, errMsg)
	return tw.writeRecord(recSessionClose, 0, time.Now().UnixNano(), body)
}

func (tw *traceWriter) WriteFrame(dir uint8, seq uint64, ts int64, prefix, body []byte) error {
	rec := recFrameH2E
	if dir == dirE2H {
		rec = recFrameE2H
	}
	full := make([]byte, 0, len(prefix)+len(body))
	full = append(full, prefix...)
	full = append(full, body...)
	return tw.writeRecord(rec, seq, ts, full)
}

func (tw *traceWriter) WriteDecodedSummary(dir uint8, seq uint64, ts int64, frameBody []byte) error {
	return tw.WriteDecodedSummaryWithExtras(dir, seq, ts, frameBody, nil)
}

// WriteDecodedSummaryWithExtras merges `extras` into the decoded summary JSON
// before writing. Used by COV-B.1 to attach `original_exec_flags` and
// `forced_collect_cover` to rewritten ExecRequest frames so the trace remains
// self-describing.
//
// `extras` keys overwrite the auto-generated summary keys on collision, which
// is the desired behavior: a downstream consumer can read "exec_flags" as
// what the executor saw and "original_exec_flags" as what syz-manager sent.
func (tw *traceWriter) WriteDecodedSummaryWithExtras(dir uint8, seq uint64, ts int64, frameBody []byte, extras map[string]any) error {
	kind, jsonBytes := decodeFrame(dir, frameBody)
	if len(extras) > 0 && len(jsonBytes) > 0 {
		var m map[string]any
		if err := json.Unmarshal(jsonBytes, &m); err == nil && m != nil {
			for k, v := range extras {
				m[k] = v
			}
			if merged, err := json.Marshal(m); err == nil {
				jsonBytes = merged
			}
		}
	}
	body := make([]byte, 0, 2+2+len(jsonBytes))
	body = append(body, dir, kind)
	body = appendBytes16(body, jsonBytes)
	return tw.writeRecord(recDecodedSummary, seq, ts, body)
}

func (tw *traceWriter) Flush() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	return tw.bw.Flush()
}

func (tw *traceWriter) Close() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if err := tw.bw.Flush(); err != nil {
		tw.f.Close()
		return err
	}
	return tw.f.Close()
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

func appendStr16(b []byte, s string) []byte {
	if len(s) > 65535 {
		s = s[:65535]
	}
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(s)))
	b = append(b, l[:]...)
	return append(b, s...)
}

func appendBytes16(b, x []byte) []byte {
	if len(x) > 65535 {
		x = x[:65535]
	}
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(x)))
	b = append(b, l[:]...)
	return append(b, x...)
}
