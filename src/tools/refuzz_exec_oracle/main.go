// refuzz_exec_oracle — V2 production-exec paired oracle PR4 (comparator).
//
// Reads exec_trace_*.bin (proxy output) and ref_result.bin (replayer output)
// for the same session, joins ExecRequest.id ↔ executor_id, and emits
// exec-oracle-report.json per docs/plans/production-exec-paired-oracle.md
// §7.2 v1 schema.
//
// v1 compares (per plan §3 / §7): errno / call_flags / call_count /
// hang classification. Coverage record-but-don't-gate (§7.3) — emits
// counters as 0 placeholders; per-request jaccard deferred to a follow-up
// PR. Skip/hole counts are surfaced loudly (plan §13 ship criterion).
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/prog"
	// Register linux/amd64 syscall metadata so prog.GetTarget + DeserializeExec
	// work. Required for §13.5 COV-B.4: per-call syscall name resolution.
	_ "github.com/google/syzkaller/sys"
)

// ============================================================
// Trace file constants (mirror tools/syz_flatrpc_proxy/trace.go).
// ============================================================

const (
	traceMagic       = "REFUZZTR"
	traceHeaderLen   = 64
	refResultMagic   = "REFUZRR"
	refResultHdrLen  = 64
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
	recReplaySessionOpen  uint8 = 0x20
	recReplayOutcome      uint8 = 0x21
	recReplaySkip         uint8 = 0x22

	// Replay skip reason bytes — must match
	// tools/refuzz_exec_replayer/ref_result_writer.hpp kSkip* constants.
	skipReasonUnsupportedExecOpts uint8 = 1
	skipReasonParseError          uint8 = 2
	skipReasonMissingProcId       uint8 = 3
	recReplaySessionClose uint8 = 0x23
)

const (
	kindNone          uint8 = 0
	kindExecRequest   uint8 = 1
	kindExecuting     uint8 = 2
	kindExecResult    uint8 = 3
)

const (
	outcomeNormal   uint8 = 0
	outcomeAbnormal uint8 = 1
	outcomeMissing  uint8 = 2
)

// reFuzz worker output head layout — must match
// executor/channel/worker/include/worker/backend/syz_exec_runner.hpp
// `struct SyzExecResult { int64 ret; int32 err; uint32 flags; uint32 cover_off; uint32 cover_count }`
const syzExecResultSize = 24

// Mirror core/include/refuzz/core/channel_contract.hpp:390 AbnormalKind enum.
// Index = uint8 wire value. Used for §13.3 abnormal_kind_buckets.
var abnormalKindNames = []string{
	"kTimeout",        // 0
	"kExecError",      // 1
	"kWorkerCrashed",  // 2
	"kWorkerSignaled", // 3
	"kCancelled",      // 4
	"kChildAborted",   // 5
}

// ============================================================
// Per-session data joined for comparison.
// ============================================================

type syzCall struct {
	Flags     uint8 `json:"flags"`     // CallFlag bits, see flatrpc.fbs:212
	Error     int32 `json:"error"`     // errno
	SignalLen int   `json:"signal_len"`
	CoverLen  int   `json:"cover_len"`
	CompsLen  int   `json:"comps_len"`

	// Per-call coverage PCs, populated from frame_e2h ExecResult.Info.Calls[i].Cover.
	// Only present when ExecFlagCollectCover was set on the originating ExecRequest.
	// Excluded from JSON (could be MB-scale) — used only for kcov_jaccard at compare time.
	Cover []uint64 `json:"-"`

	// Per-call syscall name resolved from frame_h2e ExecRequest.Data via
	// prog.DeserializeExec. Populated only when the wire bytes parse and
	// the call index exists; otherwise stays empty string. Drives §13.5
	// COV-B.4 coverage_divergence sample evidence + future A5 per-syscall
	// errno bucketing.
	SyscallName string `json:"syscall_name,omitempty"`
}

type syzRequest struct {
	ID          int64     `json:"id"`
	ExecFlags   uint64    `json:"exec_flags"`
	EnvFlags    uint64    `json:"env_flags"`
	Hanged      bool      `json:"hanged"`
	Error       string    `json:"error"`
	Calls       []syzCall `json:"calls"`
	HasResult   bool      `json:"has_result"`
	HasRequest  bool      `json:"has_request"`

	// §13.6 T1 diagnostic: per-record timestamps + the proc slot syzkaller
	// actually scheduled this request on. Captured from trace records so
	// downstream tooling can correlate "EBUSY divergence" with per-proc
	// cleanup gap timing (was previous mount on same proc still tearing
	// down when this one ran?). ProcID stays -1 if no Executing record was
	// surfaced (e.g. trace truncated before executor reported start).
	ProcID         int32  `json:"proc_id,omitempty"`
	H2ETsNs        uint64 `json:"h2e_ts_ns,omitempty"`
	ExecutingTsNs  uint64 `json:"executing_ts_ns,omitempty"`
	ExecResultTsNs uint64 `json:"exec_result_ts_ns,omitempty"`
}

type refCall struct {
	Ret         int64  `json:"ret"`
	Err         int32  `json:"err"`
	Flags       uint32 `json:"flags"`
	CoverOffset uint32 `json:"cover_offset"`
	CoverCount  uint32 `json:"cover_count"`
}

type refOutcome struct {
	ExecutorID   uint64    `json:"executor_id"`
	ReqID        int64     `json:"req_id"`
	Kind         uint8     `json:"kind"` // 0=normal, 1=abnormal, 2=missing
	AbnormalKind uint8     `json:"abnormal_kind"`
	SubmitNs     uint64    `json:"submit_ns"`
	CompleteNs   uint64    `json:"complete_ns"`
	RawOutputLen int       `json:"raw_output_len"`
	Calls        []refCall `json:"calls"`
	DecodeErr    string    `json:"decode_err,omitempty"`

	// Raw worker output bytes; decoded with the syz-side n_calls at compare time
	// (see decodeRefOutput). Excluded from JSON — typical size is a few KB and
	// would dominate the report file.
	RawOutput []byte `json:"-"`
}

type refSkip struct {
	ReqID     int64  `json:"req_id"`
	Reason    uint8  `json:"reason"`
	EnvFlags  uint64 `json:"env_flags"`
	ExecFlags uint64 `json:"exec_flags"`
}

type session struct {
	SyzSessionID uint64
	TracePath    string
	CreatedNs    uint64
	SyzRequests  map[int64]*syzRequest
	RefOutcomes  map[int64]*refOutcome
	RefSkips     map[int64]*refSkip
	// True once the session_close record was reached (for sanity reporting).
	SyzClosed bool
	RefClosed bool
}

func newSession(sessionID uint64, tracePath string, createdNs uint64) *session {
	return &session{
		SyzSessionID: sessionID,
		TracePath:    tracePath,
		CreatedNs:    createdNs,
		SyzRequests:  map[int64]*syzRequest{},
		RefOutcomes:  map[int64]*refOutcome{},
		RefSkips:     map[int64]*refSkip{},
	}
}

func (s *session) getOrAddReq(id int64) *syzRequest {
	r, ok := s.SyzRequests[id]
	if !ok {
		// ProcID -1 = sentinel "no Executing record seen yet"; distinguish
		// from legitimate proc 0 in the diagnostic CSV.
		r = &syzRequest{ID: id, ProcID: -1}
		s.SyzRequests[id] = r
	}
	return r
}

// ============================================================
// Trace file reader.
// ============================================================

type traceFileSummary struct {
	Path      string
	CreatedNs uint64
	GitRev    string
}

func collectTraceFiles(dir string) ([]traceFileSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read trace dir: %w", err)
	}
	var out []traceFileSummary
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < len("exec_trace_") || name[:len("exec_trace_")] != "exec_trace_" {
			continue
		}
		if filepath.Ext(name) != ".bin" {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			log.Printf("skip %s: open: %v", name, err)
			continue
		}
		var hdr [traceHeaderLen]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			f.Close()
			log.Printf("skip %s: header read: %v", name, err)
			continue
		}
		f.Close()
		if string(hdr[0:8]) != traceMagic {
			log.Printf("skip %s: bad magic", name)
			continue
		}
		s := traceFileSummary{
			Path:      path,
			CreatedNs: binary.LittleEndian.Uint64(hdr[12:20]),
			GitRev:    nullTrim(hdr[20:60]),
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedNs < out[j].CreatedNs })
	return out, nil
}

// readTraceFile populates s.SyzRequests from one trace file. The session_id
// in the file's session_open record is also written back into s if it
// differs from a placeholder.
func readTraceFile(path string, s *session) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(traceHeaderLen, io.SeekStart); err != nil {
		return err
	}
	for {
		var sizeBuf [4]byte
		_, err := io.ReadFull(f, sizeBuf[:])
		if err == io.EOF {
			return nil
		}
		if err == io.ErrUnexpectedEOF {
			log.Printf("trace %s: truncated_tail (expected on shutdown)", filepath.Base(path))
			return nil
		}
		if err != nil {
			return fmt.Errorf("rec size: %w", err)
		}
		recSize := binary.LittleEndian.Uint32(sizeBuf[:])
		if recSize < 17 {
			return fmt.Errorf("rec_size %d too small", recSize)
		}
		buf := make([]byte, recSize)
		if _, err := io.ReadFull(f, buf); err != nil {
			if err == io.ErrUnexpectedEOF {
				log.Printf("trace %s: truncated_tail mid-record", filepath.Base(path))
				return nil
			}
			return fmt.Errorf("rec body: %w", err)
		}
		rec := buf[0]
		// Record header layout (mirror trace_writer):
		//   buf[0]    : rec type
		//   buf[1:9]  : monotonic seq
		//   buf[9:17] : ts_ns (wall-clock when proxy saw the frame)
		// The ts is the closest signal we have to "when syzkaller dispatched /
		// completed this request"; T1 mount-mismatch diagnostic correlates it
		// with reFuzz worker submit/complete timestamps.
		recTsNs := binary.LittleEndian.Uint64(buf[9:17])
		body := buf[17:]
		switch rec {
		case recSessionOpen:
			if len(body) < 8 {
				continue
			}
			s.SyzSessionID = binary.LittleEndian.Uint64(body[0:8])
		case recFrameH2E:
			// COV-B.4: extract per-call syscall names from ExecRequest.Data
			// via prog.DeserializeExec. Same body layout as frame_e2h:
			// [u32 size_prefix | flatbuffer payload].
			if len(body) < 4 {
				continue
			}
			payloadSize := binary.LittleEndian.Uint32(body[0:4])
			if int(payloadSize)+4 > len(body) {
				continue
			}
			mergeSyscallNamesFromFrame(body[4:4+int(payloadSize)], s)
		case recFrameE2H:
			// body = [u32 size_prefix | flatbuffer payload]. The decoded summary
			// already gave us flags/error/signal_len/cover_len. We re-Parse here
			// only to lift per-call Cover []uint64 onto the request — the raw
			// PCs are needed for §7.3 kcov_jaccard but never stored in the
			// summary (would bloat the trace).
			if len(body) < 4 {
				continue
			}
			payloadSize := binary.LittleEndian.Uint32(body[0:4])
			if int(payloadSize)+4 > len(body) {
				continue
			}
			payload := body[4 : 4+int(payloadSize)]
			mergeSyzCoverFromFrame(payload, s)
		case recDecodedSummary:
			if len(body) < 4 {
				continue
			}
			// dir(1) kind(1) json_len(2) json...
			kind := body[1]
			jsonLen := binary.LittleEndian.Uint16(body[2:4])
			if int(jsonLen)+4 > len(body) {
				continue
			}
			jsonBody := body[4 : 4+int(jsonLen)]
			switch kind {
			case kindExecRequest:
				var sum struct {
					ID         int64  `json:"id"`
					ExecFlags  uint64 `json:"exec_flags"`
					EnvFlags   uint64 `json:"env_flags"`
				}
				if json.Unmarshal(jsonBody, &sum) != nil {
					continue
				}
				r := s.getOrAddReq(sum.ID)
				r.ExecFlags = sum.ExecFlags
				r.EnvFlags = sum.EnvFlags
				r.HasRequest = true
				if r.H2ETsNs == 0 {
					r.H2ETsNs = recTsNs
				}
			case kindExecuting:
				// §13.6 T1: capture proc_id + Executing ts for mount-mismatch
				// diagnostic. proc_id is the syzkaller slot the executor put
				// this request on — the same value reFuzz uses as
				// target_worker_id when replaying.
				var sum struct {
					ID     int64 `json:"id"`
					ProcID int32 `json:"proc_id"`
				}
				if json.Unmarshal(jsonBody, &sum) != nil {
					continue
				}
				r := s.getOrAddReq(sum.ID)
				r.ProcID = sum.ProcID
				if r.ExecutingTsNs == 0 {
					r.ExecutingTsNs = recTsNs
				}
			case kindExecResult:
				var sum struct {
					ID     int64  `json:"id"`
					Hanged bool   `json:"hanged"`
					Error  string `json:"error"`
					Calls  []struct {
						Flags     uint64 `json:"flags"`
						Error     int32  `json:"error"`
						SignalLen int    `json:"signal_len"`
						CoverLen  int    `json:"cover_len"`
						CompsLen  int    `json:"comps_len"`
					} `json:"calls"`
				}
				if json.Unmarshal(jsonBody, &sum) != nil {
					continue
				}
				r := s.getOrAddReq(sum.ID)
				r.Hanged = sum.Hanged
				r.Error = sum.Error
				r.HasResult = true
				if r.ExecResultTsNs == 0 {
					r.ExecResultTsNs = recTsNs
				}
				// Preserve any per-call fields already lifted onto r.Calls by
				// earlier passes (mergeSyscallNamesFromFrame on frame_h2e,
				// mergeSyzCoverFromFrame on frame_e2h). The proxy writes raw
				// frame records BEFORE their matching decoded_summary, so the
				// frame-side passes run first; without this preservation,
				// rebuilding r.Calls from scratch here would wipe Cover and
				// SyscallName, silently breaking kcov_jaccard + COV-B.4
				// divergence attribution.
				prev := r.Calls
				r.Calls = make([]syzCall, len(sum.Calls))
				for i, c := range sum.Calls {
					r.Calls[i] = syzCall{
						Flags:     uint8(c.Flags & 0xFF),
						Error:     c.Error,
						SignalLen: c.SignalLen,
						CoverLen:  c.CoverLen,
						CompsLen:  c.CompsLen,
					}
					if i < len(prev) {
						r.Calls[i].Cover = prev[i].Cover
						r.Calls[i].SyscallName = prev[i].SyscallName
					}
				}
			}
		case recSessionClose:
			s.SyzClosed = true
		}
	}
}

// progTarget caches the linux/amd64 prog.Target used for §13.5 COV-B.4
// per-call syscall name resolution. nil until first successful lookup; nil
// after a lookup failure means resolution is permanently skipped for this
// run (syscall names degrade to empty strings, not a hard error — the
// oracle's primary metrics don't depend on them).
var progTarget *prog.Target

func ensureProgTarget() *prog.Target {
	if progTarget != nil {
		return progTarget
	}
	t, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		log.Printf("syscall-name resolution disabled: prog.GetTarget linux/amd64: %v", err)
		return nil
	}
	progTarget = t
	return progTarget
}

// mergeSyscallNamesFromFrame parses one frame_h2e payload. If it is an
// ExecRequest, deserializes ExecRequest.Data via prog.DeserializeExec and
// writes the resolved syscall names back onto the matching syzRequest.Calls.
// Deserialize failures are soft (names stay empty) — wire-equivalence
// gate doesn't depend on syscall names, only the §13.5 divergence dump does.
func mergeSyscallNamesFromFrame(payload []byte, s *session) {
	defer func() { _ = recover() }()
	t := ensureProgTarget()
	if t == nil {
		return
	}
	msg, err := flatrpc.Parse[*flatrpc.HostMessageRaw](payload)
	if err != nil || msg == nil || msg.Msg == nil {
		return
	}
	req, ok := msg.Msg.Value.(*flatrpc.ExecRequest)
	if !ok || len(req.Data) == 0 {
		return
	}
	ep, err := t.DeserializeExec(req.Data, nil)
	if err != nil {
		return
	}
	r := s.getOrAddReq(req.Id)
	if len(r.Calls) < len(ep.Calls) {
		grow := make([]syzCall, len(ep.Calls))
		copy(grow, r.Calls)
		r.Calls = grow
	}
	for i, c := range ep.Calls {
		if c.Meta != nil {
			r.Calls[i].SyscallName = c.Meta.Name
		}
	}
}

// mergeSyzCoverFromFrame parses one frame_e2h flatbuffer payload. If it is an
// ExecResult, the per-call Cover []uint64 vectors are merged onto the matching
// syzRequest. Other ExecutorMessage variants (executing / state_result) carry
// no per-call cover and are ignored. Parse failures are swallowed silently —
// the decoded summary path already populated flags/error/cover_len, and a frame
// we cannot Parse here would have been kindParseError there too.
func mergeSyzCoverFromFrame(payload []byte, s *session) {
	defer func() {
		// flatrpc.Parse panics on truncated input on some old traces. Soft-fail.
		_ = recover()
	}()
	msg, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](payload)
	if err != nil || msg == nil || msg.Msg == nil {
		return
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res.Info == nil {
		return
	}
	r := s.getOrAddReq(res.Id)
	// recDecodedSummary may run before this case in the same record stream, so
	// r.Calls might already be sized. If not, size it lazily from frame data.
	if len(r.Calls) < len(res.Info.Calls) {
		grow := make([]syzCall, len(res.Info.Calls))
		copy(grow, r.Calls)
		r.Calls = grow
	}
	for i, c := range res.Info.Calls {
		if len(c.Cover) == 0 {
			continue
		}
		// Defensive copy: Parse hands us a slice over the trace buffer that
		// gets reused on the next record.
		cov := make([]uint64, len(c.Cover))
		copy(cov, c.Cover)
		r.Calls[i].Cover = cov
	}
}

// ============================================================
// ref_result.bin reader.
// ============================================================

// readRefResult walks ref_result.bin once and dispatches records into
// sessions keyed by trace_session_id (replay_session_open's first field).
func readRefResult(path string, sessions map[uint64]*session) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var hdr [refResultHdrLen]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("ref hdr: %w", err)
	}
	if string(hdr[0:len(refResultMagic)]) != refResultMagic {
		return fmt.Errorf("bad ref_result magic")
	}
	var current *session
	for {
		var sizeBuf [4]byte
		_, err := io.ReadFull(f, sizeBuf[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ref rec size: %w", err)
		}
		recSize := binary.LittleEndian.Uint32(sizeBuf[:])
		if recSize < 17 {
			return fmt.Errorf("ref rec_size %d too small", recSize)
		}
		buf := make([]byte, recSize)
		if _, err := io.ReadFull(f, buf); err != nil {
			return fmt.Errorf("ref rec body: %w", err)
		}
		rec := buf[0]
		body := buf[17:]
		switch rec {
		case recReplaySessionOpen:
			// body: u64 trace_session_id, u32 vm_index, u64 file_created_ns, u16 path_len, path
			if len(body) < 8 {
				continue
			}
			sid := binary.LittleEndian.Uint64(body[0:8])
			current = sessions[sid]
			if current == nil {
				// Replayer wrote a session_id that has no matching trace. Allocate
				// a synthetic session so we still surface its outcomes in the report.
				current = newSession(sid, "<ref-only>", 0)
				sessions[sid] = current
			}
		case recReplayOutcome:
			if current == nil {
				continue
			}
			if len(body) < 8+8+1+1+8+8+4 {
				continue
			}
			executorID := binary.LittleEndian.Uint64(body[0:8])
			reqID := int64(binary.LittleEndian.Uint64(body[8:16]))
			kind := body[16]
			abnormal := body[17]
			submitNs := binary.LittleEndian.Uint64(body[18:26])
			completeNs := binary.LittleEndian.Uint64(body[26:34])
			outLen := binary.LittleEndian.Uint32(body[34:38])
			outStart := 38
			outEnd := outStart + int(outLen)
			if outEnd > len(body) {
				continue
			}
			out := body[outStart:outEnd]
			oc := &refOutcome{
				ExecutorID:   executorID,
				ReqID:        reqID,
				Kind:         kind,
				AbnormalKind: abnormal,
				SubmitNs:     submitNs,
				CompleteNs:   completeNs,
				RawOutputLen: int(outLen),
			}
			// Preserve raw output bytes; precise SyzExecResult[n_calls] +
			// coverage_tail decode happens at compare time when the syz-side
			// n_calls is known (see decodeRefOutput).
			if kind == outcomeNormal && outLen > 0 {
				oc.RawOutput = make([]byte, outLen)
				copy(oc.RawOutput, out)
			}
			current.RefOutcomes[reqID] = oc
		case recReplaySkip:
			if current == nil {
				continue
			}
			if len(body) < 8+1+8+8 {
				continue
			}
			reqID := int64(binary.LittleEndian.Uint64(body[0:8]))
			reason := body[8]
			envFlags := binary.LittleEndian.Uint64(body[9:17])
			execFlags := binary.LittleEndian.Uint64(body[17:25])
			current.RefSkips[reqID] = &refSkip{
				ReqID:     reqID,
				Reason:    reason,
				EnvFlags:  envFlags,
				ExecFlags: execFlags,
			}
		case recReplaySessionClose:
			if current != nil {
				current.RefClosed = true
			}
			current = nil
		}
	}
}

// decodeRefOutput decodes the leading `nCalls` SyzExecResult heads followed
// by the coverage_tail uint64 array, mirroring the worker output layout
// documented in executor/channel/worker/include/worker/backend/
// syz_exec_runner.hpp:50:
//
//	output = [SyzExecResult × n] [uint64 × total_cov] [...其它 packets...]
//
// cover_offset on each head is an *index* into coverage_tail (not a byte
// offset). cover_count is the number of uint64 entries for that call.
//
// Returns ok=false (with calls=nil, tail=nil) when:
//   - raw is shorter than nCalls*24 bytes (truncated worker output —
//     call_count_mismatch upstream)
//   - any (cover_offset + cover_count) is out of bounds for what remains
//     after the head block
//
// The tail can be longer than the largest (cover_offset+cover_count) when
// the worker appended other packets after coverage — we only read up to
// the maximum end index needed by the heads.
func decodeRefOutput(raw []byte, nCalls int) (calls []refCall, tail []uint64, ok bool) {
	headBytes := nCalls * syzExecResultSize
	if len(raw) < headBytes {
		return nil, nil, false
	}
	calls = make([]refCall, nCalls)
	var maxEnd uint64
	for i := 0; i < nCalls; i++ {
		base := i * syzExecResultSize
		calls[i] = refCall{
			Ret:         int64(binary.LittleEndian.Uint64(raw[base : base+8])),
			Err:         int32(binary.LittleEndian.Uint32(raw[base+8 : base+12])),
			Flags:       binary.LittleEndian.Uint32(raw[base+12 : base+16]),
			CoverOffset: binary.LittleEndian.Uint32(raw[base+16 : base+20]),
			CoverCount:  binary.LittleEndian.Uint32(raw[base+20 : base+24]),
		}
		end := uint64(calls[i].CoverOffset) + uint64(calls[i].CoverCount)
		if end > maxEnd {
			maxEnd = end
		}
	}
	tailBytes := raw[headBytes:]
	if maxEnd*8 > uint64(len(tailBytes)) {
		// cover_offset/cover_count point past end of buffer — corrupted output
		// or an unexpected layout. Refuse to extract any cover, but keep calls
		// (so the wire-equivalence pass still gets flag/errno).
		return calls, nil, false
	}
	tail = make([]uint64, maxEnd)
	for i := uint64(0); i < maxEnd; i++ {
		tail[i] = binary.LittleEndian.Uint64(tailBytes[i*8 : i*8+8])
	}
	return calls, tail, true
}

// refCoverSlice returns the cover PCs for one call by indexing into the
// coverage_tail. Returns nil on out-of-bounds, which decodeRefOutput already
// rejects — defensive duplicate so callers can short-circuit safely.
func refCoverSlice(tail []uint64, offset, count uint32) []uint64 {
	end := uint64(offset) + uint64(count)
	if end > uint64(len(tail)) {
		return nil
	}
	return tail[offset : offset+count]
}

// quantile returns the p-th percentile (0 ≤ p ≤ 100) of an already-sorted
// (ascending) sample slice. Uses the simple "nearest-rank" definition: pick
// the index ⌈p/100·n⌉ - 1, clamped to [0, n-1]. Adequate for sample sizes
// in the thousands; we don't need linear interpolation here.
func quantile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	idx := int((p / 100.0) * float64(n))
	if idx >= n {
		idx = n - 1
	}
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// buildJaccardDistribution computes the §13.5 distribution stats from the
// raw per-call samples. Mean/sample_count match the existing scalar fields
// (kcov_jaccard_sum / count) — repeated here so a single struct describes
// the whole coverage signal for downstream scrapers.
//
// `kcovBufferOverflow` is the count of low-band samples that were caused
// by the worker side's kcov ring filling up (raw refCov >= kcovBufferCap).
// It is subtracted from low_band_count to produce actionable_low_band_count
// — the §13.1 coverage gate input. See plan §13.5 finding #3.
//
// §13.6 E: also subtract `processColdFault` (samples classified as
// measurement artifact by classifyProcessColdFault — child first-fault
// cold path that no worker-side prefault can eliminate without shifting
// the divergence elsewhere; see b15b PC-dump attribution + b15c/c3/c4
// negative results).
func buildJaccardDistribution(samples []float64, bothEmpty, kcovBufferOverflow,
	processColdFault int) jaccardDistribution {
	d := jaccardDistribution{
		SampleCount:                   len(samples),
		BothEmptyCount:                bothEmpty,
		KCovBufferOverflowCount:       kcovBufferOverflow,
		CoverageProcessColdFaultCount: processColdFault,
	}
	if len(samples) == 0 {
		return d
	}
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)
	d.Min = sorted[0]
	d.P25 = quantile(sorted, 25)
	d.P50 = quantile(sorted, 50)
	d.P95 = quantile(sorted, 95)
	d.P99 = quantile(sorted, 99)
	var sum float64
	for _, v := range sorted {
		sum += v
		if v < 0.5 {
			d.LowBandCount++
		}
		if v >= 0.9 {
			d.HighBandCount++
		}
	}
	d.Mean = sum / float64(len(sorted))
	// Clamp: both excluded buckets are counted at low-band emission time, so
	// each must be ≤ LowBandCount individually. Defensive caps in case a
	// future caller passes a stale value.
	if d.KCovBufferOverflowCount > d.LowBandCount {
		d.KCovBufferOverflowCount = d.LowBandCount
	}
	if d.CoverageProcessColdFaultCount > d.LowBandCount {
		d.CoverageProcessColdFaultCount = d.LowBandCount
	}
	// Combined exclusion cap: overflow + cold-fault can't together exceed
	// low_band (would imply double-counting at the call site, prevented by
	// the classifier's mutual-exclusion guarantee but worth a safety clamp).
	combined := d.KCovBufferOverflowCount + d.CoverageProcessColdFaultCount
	if combined > d.LowBandCount {
		// Trim cold-fault preferentially; overflow is the older, stricter
		// signal and the b15b attribution data covered it first.
		d.CoverageProcessColdFaultCount = d.LowBandCount - d.KCovBufferOverflowCount
		if d.CoverageProcessColdFaultCount < 0 {
			d.CoverageProcessColdFaultCount = 0
		}
		combined = d.KCovBufferOverflowCount + d.CoverageProcessColdFaultCount
	}
	d.ActionableLowBandCount = d.LowBandCount - combined
	return d
}

// accumKCovJaccard folds one (syz, ref) per-call cover pair into the report.
// Both-empty pairs are bucketed into KCovJaccardBothEmptyCount and NOT into
// Sum/Count: the (∅,∅)→1.0 identity is mathematically clean but counts as
// "neither side observed anything", which is the opposite of equivalence
// evidence. Folding it would inflate jaccard_mean by free 1.0 contributions
// in proportion to the dead-call rate. See plan §7.3 / §13.4.1.
// kcovDivergenceThreshold is the §13.5 COV-B.4 cut-off: per-call jaccards
// strictly below this are dumped as `coverage_divergence` samples with the
// resolved syscall name attached. Set conservatively at 0.5 — a call where
// barely half the PCs overlap is almost certainly a real kernel-path
// divergence, not measurement noise.
const kcovDivergenceThreshold = 0.5

// kcovBufferCap mirrors the Linux kcov `COVER_SIZE` default (kernel/kcov.c).
// When raw len(refCov) hits this number, the per-task kcov ring buffer
// filled up and the kernel silently drops subsequent PCs. The B1 #3
// root-cause analysis (2026-05-19, see plan §13.5) showed that 55/72
// low-band samples in the COV-B.6 dataset were ring-buffer-capped: the
// reFuzz worker's per-call kcov window admits pre-syscall mm / page-fault
// / maple-tree activity that consumes the ring before the actual syscall
// body's fs-driver PCs can be recorded. These samples are worker-side
// measurement artifacts, not reFuzz fuzz-signal defects, and are tracked
// separately as KCovBufferOverflowCount.
const kcovBufferCap = (1 << 19) - 1

// kcovActionableLowBandMaxRatio is the §13.1 coverage gate ceiling for
// `actionable_low_band_count / sample_count`. 1% accommodates the residual
// (non-overflow) low-band tail observed in COV-B.6 (17/2126 = 0.8%) which
// is dominated by sub-cap window-width artifacts (e.g. mount-image at
// 100K–240K raw len, syz_clone3 capturing child task PCs reFuzz sees but
// syz does not). When the worker kcov_sink window is narrowed (B1 worker
// epic), this ratio is expected to drop toward 0 and the threshold can be
// tightened.
const kcovActionableLowBandMaxRatio = 0.01

// kcovP95Min is the §13.1 coverage gate p95 floor. 0.8 = 95 % of per-call
// jaccards must clear 0.8. Prevents "90 % healthy + 10 % wandered off"
// being averaged into a deceptively clean mean.
const kcovP95Min = 0.8

// jaccardOutcome classifies a per-call (syz cover, ref cover) comparison.
// Only kJaccardCompared participates in the Jaccard sum / low_band / p25
// distribution. The other three are bookkeeping buckets so the report shows
// the population breakdown without contaminating equivalence statistics.
type jaccardOutcome int

const (
	// Both sides executed the call AND at least one side observed PCs —
	// jaccard is meaningful equivalence evidence.
	kJaccardCompared jaccardOutcome = iota
	// Neither side has any cover for this call (existing both-empty bucket).
	// Either both calls didn't execute, or both executed but produced no
	// PCs. The (∅,∅)→1.0 identity isn't equivalence evidence so it sits
	// out of the Jaccard sum.
	kJaccardBothEmpty
	// §13.6 T1.D (b15b follow-up): syz side's CallFlag.Executed is not set
	// (the call was filled with empty_call placeholder or was a Blocked
	// timeout) AND ref has at least one PC. Including this in Jaccard would
	// be comparing "no syscall ran" vs "one ran" → forced 0.0 — pollutes
	// the distribution as a low-band sample. Bucket separately so the
	// coverage gate's denominator only reflects calls both sides actually
	// executed.
	kJaccardSyzUnavail
	// Symmetric: ref side didn't execute (e.g. threaded Blocked) while syz
	// has cover. Surfaces ref-side wire/dispatch holes that the call-flag
	// gate (PR3 step 5) also catches; tracked here for transparency.
	kJaccardRefUnavail
)

// accumKCovJaccard folds one per-call (syz, ref) cover pair into the report.
// `syzExecuted` / `refExecuted` reflect CallFlag.Executed on each side —
// see jaccardOutcome doc for why the two unavail buckets are separated from
// the Jaccard sum. Returns the computed jaccard (only meaningful when the
// outcome is kJaccardCompared) and the outcome enum for the caller's sample
// emission logic.
func accumKCovJaccard(rep *report,
	syzCov []uint64, syzExecuted bool,
	refCov []uint64, refExecuted bool,
) (jaccard float64, outcome jaccardOutcome) {
	// "Unavailable" only when the other side actually has cover to compare
	// against. If both are empty, the existing both-empty bucket still
	// applies — no need to further subdivide.
	if !syzExecuted && len(refCov) > 0 {
		rep.CoverageSyzUnavailCount++
		return 0, kJaccardSyzUnavail
	}
	if !refExecuted && len(syzCov) > 0 {
		rep.CoverageRefUnavailCount++
		return 0, kJaccardRefUnavail
	}
	if len(syzCov) == 0 && len(refCov) == 0 {
		rep.KCovJaccardBothEmptyCount++
		return 0, kJaccardBothEmpty
	}
	j := jaccardU64(syzCov, refCov)
	rep.KCovJaccardSum += j
	rep.KCovJaccardCount++
	rep.KCovJaccardSamples = append(rep.KCovJaccardSamples, j)
	return j, kJaccardCompared
}

// jaccardU64 returns |A ∩ B| / |A ∪ B| over two uint64 sets (PCs).
// Convention: jaccard of two empty sets is 1.0 (vacuously identical).
// Callers in the compare path should NOT use this directly when both sides
// may be empty — go through accumKCovJaccard which separates that case.
func jaccardU64(a, b []uint64) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	sa := make(map[uint64]struct{}, len(a))
	for _, v := range a {
		sa[v] = struct{}{}
	}
	sb := make(map[uint64]struct{}, len(b))
	for _, v := range b {
		sb[v] = struct{}{}
	}
	intersect := 0
	for v := range sa {
		if _, ok := sb[v]; ok {
			intersect++
		}
	}
	union := len(sa) + len(sb) - intersect
	if union == 0 {
		return 1.0
	}
	return float64(intersect) / float64(union)
}

// ============================================================
// §13.6 E: coverage measurement-artifact bucket.
//
// b15b PC-dump attribution showed 42/43 actionable_low_band samples were
// dominated by one symbol family (do_user_addr_fault / wp_page_copy /
// filemap_map_pages / xas_* / folio_* / rcu_*) across 6 unrelated
// syz_open_dev$* variants with near-identical per-PC counts → child
// first-fault cold path, not syscall semantics. b15c (worker-side prefault)
// proved the divergence cannot be removed at source without shifting it
// into a different cluster.
//
// This bucket isolates that artifact from `actionable_low_band` WITHOUT
// loosening the gate threshold. Conservative classification:
//
//   1. call_idx == 0 only (first-fault pattern is per-program-child, only
//      hits call#0 because subsequent calls reuse the now-warmed pages).
//   2. max(syz_cov, ref_cov) / min(syz_cov, ref_cov) >= 3 — one side ran
//      far more PCs than the other, consistent with fault overhead
//      flooding ring on cold side.
//   3. of the larger side's unique PCs, > 50 % map to a hand-curated
//      VM/page-fault/page-cache/COW symbol family.
//   4. vmlinux must be loaded via -vmlinux PATH; absent → no bucketing,
//      no guessing from syscall names.
//
// The bucket exists so an operator can see exactly how much "measurement
// artifact" the gate is excluding. The conservative rules + symbol-table
// requirement mean a false positive would need the syscall to truly run
// 3× as many PCs on one side AND have most of the unique side land in
// the fault family — both real divergences (e.g. a worker syscall that
// genuinely takes a different code path) won't satisfy the second condition
// because their unique PCs are in the syscall's own subsystem code.
// ============================================================

// kernelSymbol is one entry parsed out of `nm -n vmlinux`. Sorted by Addr
// at load time; per-PC lookup is binary search for the largest Addr <= pc.
type kernelSymbol struct {
	Addr uint64
	Name string
}

// kernelSymbolTable lazily parses vmlinux symbols once and answers PC →
// family queries. Falls back to no-op (zero table) when no -vmlinux was set.
type kernelSymbolTable struct {
	syms   []kernelSymbol
	loaded bool
}

// processColdFaultFamily lists symbol-name prefixes whose presence in a
// per-call unique-PC set indicates first-fault / page-cache / COW noise
// rather than a real syscall divergence. Compiled from b15b PC-dump
// attribution: every entry was observed as a ref-only PC family on the
// 42 cold-path low-band samples across 6 different syz_open_dev$* variants
// with near-identical counts (not syscall-specific).
//
// Match is by prefix to absorb compiler-generated suffixes (.constprop,
// .isra, .part) and the rcu/folio inline expansion variants. Keep this list
// CONSERVATIVE — adding too-generic prefixes (e.g. "rcu_") would risk
// burying genuine syscall coverage that legitimately walks RCU paths.
var processColdFaultFamily = []string{
	// user-mode page fault entry + bottom half
	"do_user_addr_fault",
	"access_error",
	"handle_mm_fault",
	"__handle_mm_fault",
	"do_fault",
	"do_read_fault",
	"do_anonymous_page",
	"__do_fault",
	"finish_fault",
	// COW / wp
	"do_wp_page",
	"wp_page_copy",
	"wp_can_reuse_anon_folio",
	// filemap / page cache read-fault
	"filemap_map_pages",
	"filemap_map_folio_range",
	"next_uptodate_folio",
	// xarray (page cache index walk)
	"xas_find",
	"xas_next_entry",
	"xas_next_marked",
	"xas_reload",
	"xa_entry",
	// folio state / refcount used by fault paths
	"folio_flags",
	"const_folio_flags",
	"folio_wait_bit_common",
	"__folio_start_writeback",
	"__refcount_add_not_zero_limited_acquire",
	// VMA lookup
	"vma_start_read",
	"lock_vma_under_rcu",
	// PTE map (page table walk during fault)
	"pte_offset_map",
	"pte_offset_map_lock",
	// maple tree (VMA index)
	"mtree_range_walk",
	// RCU bookkeeping seen at fault entry
	"rcu_read_lock",
	"rcu_read_unlock",
	"rcu_lock_release",
	// static branch overhead
	"arch_static_branch",
}

// LoadFromVmlinux runs `nm -n vmlinux` once and parses its output. Lines look
// like "ffffffff81000000 T _stext"; we keep only T / t / W / w (text) syms.
// Other types (data, bss, debug) aren't reachable as KCOV PCs.
func (kt *kernelSymbolTable) LoadFromVmlinux(path string) error {
	cmd := exec.Command("nm", "-n", path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)  // some symbol names long
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 19 {  // 16 hex + space + 1 type + space + name
			continue
		}
		// type char is at column 17 (zero-based)
		ty := line[17]
		if ty != 'T' && ty != 't' && ty != 'W' && ty != 'w' {
			continue
		}
		addr, parseErr := strconv.ParseUint(line[:16], 16, 64)
		if parseErr != nil {
			continue
		}
		name := line[19:]
		kt.syms = append(kt.syms, kernelSymbol{Addr: addr, Name: name})
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// `nm -n` outputs sorted by address already, but sanity-sort.
	sort.Slice(kt.syms, func(i, j int) bool { return kt.syms[i].Addr < kt.syms[j].Addr })
	kt.loaded = len(kt.syms) > 0
	return nil
}

// Lookup returns the symbol name covering pc, or "" if no enclosing symbol
// is in the table. Binary search for the largest Addr <= pc.
func (kt *kernelSymbolTable) Lookup(pc uint64) string {
	if !kt.loaded {
		return ""
	}
	// sort.Search returns first index where syms[i].Addr > pc.
	i := sort.Search(len(kt.syms), func(i int) bool { return kt.syms[i].Addr > pc })
	if i == 0 {
		return ""
	}
	return kt.syms[i-1].Name
}

// matchesProcessColdFault returns true when the symbol name starts with one
// of the curated cold-fault family prefixes. Stripping compiler-generated
// suffixes is implicit (HasPrefix).
func matchesProcessColdFault(symName string) bool {
	if symName == "" {
		return false
	}
	for _, p := range processColdFaultFamily {
		if hasFamilyPrefix(symName, p) {
			return true
		}
	}
	return false
}

// hasFamilyPrefix returns true when name starts with prefix AND the rest is
// either empty, a '.' (compiler suffix), '_' / digit (same-word boundary).
// Prevents partial-name match (e.g. "do_mmap" prefix shouldn't fire on
// "do_mmap2" — actually do_mmap2 IS a relative we want — fine. But matters for
// avoiding "lock_is_held" matching "lock_is_help"-类 false positive).
func hasFamilyPrefix(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := name[len(prefix):]
	return rest == "" || rest[0] == '.' || rest[0] == '_' ||
		(rest[0] >= '0' && rest[0] <= '9')
}


// classifyProcessColdFault returns true when (syz, ref) PC sets for one call
// fit the b15b "child first-fault cold" pattern: the larger side has ≥ 3×
// the cov entry count of the smaller side, and ≥ 50 % of the larger side's
// unique PCs fall in the curated cold-fault symbol family.
//
// callIdx must be 0 (first call only — pattern is per-program-child).
// kt must be loaded; if not, returns false (no bucketing without symbols).
func classifyProcessColdFault(kt *kernelSymbolTable, callIdx int,
	syzCov, refCov []uint64) bool {
	if kt == nil || !kt.loaded || callIdx != 0 {
		return false
	}
	const minRatio = 3
	const minFamilyShare = 0.5
	var bigger, smaller []uint64
	if len(syzCov) > len(refCov) {
		bigger, smaller = syzCov, refCov
	} else {
		bigger, smaller = refCov, syzCov
	}
	if len(smaller) == 0 {
		// 0 vs N: one-side-unavailable handles the "Executed=0" subcase already;
		// surviving 0-vs-N here would mean Executed but no PCs — unusual.
		// Don't bucket: it's a real degenerate signal, not measurement noise.
		return false
	}
	if len(bigger) < minRatio*len(smaller) {
		return false
	}
	// Build smaller as a set for O(1) lookup.
	smallSet := make(map[uint64]struct{}, len(smaller))
	for _, pc := range smaller {
		smallSet[pc] = struct{}{}
	}
	var unique uint64Set
	unique.Init(len(bigger))
	for _, pc := range bigger {
		if _, ok := smallSet[pc]; ok {
			continue
		}
		unique.Add(pc)
	}
	uniqueList := unique.List()
	if len(uniqueList) == 0 {
		return false
	}
	hits := 0
	for _, pc := range uniqueList {
		if matchesProcessColdFault(kt.Lookup(pc)) {
			hits++
		}
	}
	share := float64(hits) / float64(len(uniqueList))
	return share >= minFamilyShare
}

// uint64Set is a small dedup container backing classifyProcessColdFault. Goes
// here rather than in a util file because nothing else in the oracle needs
// it; classifier scope keeps the helper local to its use.
type uint64Set struct {
	m map[uint64]struct{}
}

func (s *uint64Set) Init(hint int) { s.m = make(map[uint64]struct{}, hint) }
func (s *uint64Set) Add(v uint64)  { s.m[v] = struct{}{} }
func (s *uint64Set) List() []uint64 {
	out := make([]uint64, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}

// ============================================================
// Comparator + report builder.
// ============================================================

type sampleEntry struct {
	SessionID uint64 `json:"session_id"`
	ReqID     int64  `json:"req_id"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail,omitempty"`
}

// Plan §13.1 three-tier ship gate. Each tier proves a different layer of
// "production-path parity" — wire (input parsing), result (userspace return),
// coverage (kernel-path execution). Overall ship requires all three.
type wireGate struct {
	ReplayHolesClean bool `json:"replay_holes_clean"` // request_skipped_replay_holes == 0
	CallCountMatches bool `json:"call_count_matches"` // call_count_mismatch == 0
	CallFlagMatches  bool `json:"call_flag_matches"`  // call_flag_mismatch == 0
	Passed           bool `json:"passed"`
}

type resultGate struct {
	ErrnoMatches bool `json:"errno_matches"` // errno_mismatch == 0 (or below threshold)
	Passed       bool `json:"passed"`
}

// jaccardDistribution surfaces the per-call Jaccard distribution shape so
// coverage gate thresholds (plan §13.1, calibrated by COV-B in §13.5) can be
// set against quantiles rather than the mean alone. A single mean collapses
// "90% near 1.0 + 10% near 0" with "100% near 0.9" — these have very
// different ship implications.
//
// `sample_count` is the BothEmpty-excluded denominator (matches
// kcov_jaccard_count). `low_band_count` (j < 0.5) is the path-divergence
// red-zone counter; `high_band_count` (j >= 0.9) is the headroom signal.
type jaccardDistribution struct {
	SampleCount     int     `json:"sample_count"`
	BothEmptyCount  int     `json:"both_empty_count"`
	Mean            float64 `json:"mean"`
	Min             float64 `json:"min"`
	P25             float64 `json:"p25"`
	P50             float64 `json:"p50"`
	P95             float64 `json:"p95"`
	P99             float64 `json:"p99"`
	LowBandCount    int     `json:"low_band_count"`
	HighBandCount   int     `json:"high_band_count"`

	// §13.5 P2 (post-B1 #3 root-cause): split low_band by whether the worker
	// side hit the kcov ring buffer cap. raw refCov >= kcovBufferCap means
	// the per-task ring filled up before the syscall body finished — the
	// resulting low jaccard reflects worker-side window-width measurement
	// artifact (root-caused 2026-05-19), not a reFuzz fuzz-signal defect.
	// `actionable_low_band_count = low_band_count - kcov_buffer_overflow_count`
	// is what the coverage gate actually checks. When the worker kcov_sink
	// window is narrowed, kcov_buffer_overflow_count should fall to 0 and
	// the two will converge.
	KCovBufferOverflowCount int `json:"kcov_buffer_overflow_count"`

	// §13.6 E: per-call low-band samples classified as measurement artifact
	// by classifyProcessColdFault — child first-fault cold path that can't
	// be removed at source (b15b PC-dump attribution + b15c/c3/c4 negative
	// results). Excluded from ActionableLowBandCount but NOT from
	// LowBandCount or distribution stats so an operator can always see the
	// raw count. Mirrors KCovBufferOverflowCount in spirit.
	CoverageProcessColdFaultCount int `json:"coverage_process_cold_fault_count"`

	// actionable_low_band = low_band - kcov_buffer_overflow - process_cold_fault.
	// What the §13.1 coverage gate checks. When the worker / cold-fault
	// situation is fully accounted for, this converges with LowBandCount.
	ActionableLowBandCount int `json:"actionable_low_band_count"`
}

// Plan §7.3 + §13.4: coverage gate is the kernel-path equivalence dimension.
// Status state machine:
//   - "insufficient_data"  no jaccard samples (current state pre-COV-A)
//   - "pending_thresholds" samples present but coverage gate thresholds not
//                          calibrated yet — always Passed=false per §13.1
//   - "pass"               thresholds met
//   - "fail"               thresholds set and not met
type coverageGate struct {
	Status                string              `json:"status"`
	CoverageAvailableRate float64             `json:"coverage_available_rate"`
	JaccardMean           float64             `json:"jaccard_mean"`
	JaccardSampleCount    int                 `json:"jaccard_sample_count"`
	JaccardDistribution   jaccardDistribution `json:"jaccard_distribution"`
	Passed                bool                `json:"passed"`
}

type shipGate struct {
	Wire     wireGate     `json:"wire"`
	Result   resultGate   `json:"result"`
	Coverage coverageGate `json:"coverage"`
	Overall  bool         `json:"overall"`
}

type report struct {
	SchemaVersion          int          `json:"schema_version"`
	SessionCount           int          `json:"session_count"`
	RequestTotal           int          `json:"request_total"`
	RequestCompared        int          `json:"request_compared"`
	RequestSkipUnsupported int          `json:"request_skipped_unsupported"`
	// §13.6 PR3 step 3: requests the replayer dropped because the trace
	// never surfaced an Executing.proc_id for them, so strict slot-affinity
	// dispatch couldn't pick a worker. Counted separately so an operator can
	// distinguish "trace shape doesn't carry slot info" from genuine
	// CollectComps-style protocol gaps.
	RequestSkipMissingProcId int        `json:"request_skipped_missing_proc_id"`
	RequestSkipReplayHoles int          `json:"request_skipped_replay_holes"`
	Matched                int          `json:"matched"`
	ErrnoMismatch          int          `json:"errno_mismatch"`
	CallFlagMismatch       int          `json:"call_flag_mismatch"`
	CallCountMismatch      int          `json:"call_count_mismatch"`
	SyzHanged              int          `json:"syz_hanged"`
	RefHanged              int          `json:"ref_hanged"`
	RefOnlyFail            int          `json:"ref_only_fail"`
	SyzOnlyFail            int          `json:"syz_only_fail"`
	VMResetCount           int          `json:"vm_reset_count"`

	// §13.6 (schema v6): per-call skip buckets. A "skip" is a call where
	// `CallFlag.Executed` is not set on one or both sides. Comparing such a
	// call's errno/flags against the other side yields a false-positive
	// mismatch — see kCallFlagExecuted doc for the upstream/reFuzz origin
	// states. compareCalls excludes skipped calls from errno/flag tally
	// and counts them here instead.
	SyzCallSkipped  int `json:"syz_call_skipped"`  // syz didn't execute, ref did
	RefCallSkipped  int `json:"ref_call_skipped"`  // ref didn't execute, syz did
	BothCallSkipped int `json:"both_call_skipped"` // neither side executed

	// §13.1 ship-gate inputs (raw rates) + §13.3 observability.
	RawComparedRate     float64        `json:"raw_compared_rate"`
	ComparableRate      float64        `json:"comparable_rate"`
	AbnormalKindBuckets map[string]int `json:"abnormal_kind_buckets"`

	// §13.1 machine-readable ship-gate verdict.
	ShipGatePassed shipGate `json:"ship_gate_passed"`

	// §7.3 / §13.1 coverage tier data.
	// BothNormalCount is the proper denominator for coverage_available_rate:
	// it's the count of compared requests where neither side abnormaled, i.e.
	// the population where per-call cover compare was even possible. Without
	// this number, comparing SyzCoverUnavailable to request_compared mixes in
	// ref_only_fail / syz_only_fail / both_fail and produces a misleading rate.
	BothNormalCount     int     `json:"both_normal_count"`
	SyzCoverUnavailable int     `json:"syz_cover_unavailable_count"`
	KCovJaccardSum      float64 `json:"kcov_jaccard_sum"`
	KCovJaccardCount    int     `json:"kcov_jaccard_count"`
	// Per-call samples where BOTH syz.Cover and ref cover slice were empty —
	// recorded separately, NOT folded into KCovJaccardSum/Count. The (empty,
	// empty) → 1.0 identity is mathematically clean but is NOT evidence of
	// kernel-path equivalence (it's "neither side observed anything"), so
	// counting it would inflate jaccard_mean. Surfacing the count lets
	// downstream judge how much of the sample base was vacuous.
	KCovJaccardBothEmptyCount int     `json:"kcov_jaccard_both_empty_count"`
	// §13.6 T1.D (schema v7): per-call samples where the syz/ref side did
	// NOT set CallFlag.Executed but the other side had real cover. These
	// are excluded from KCovJaccardSum/Count because "no syscall ran vs one
	// ran" forces a 0.0 jaccard and pollutes the distribution as a fake
	// low-band sample. Surfaced as separate counters so operators can see
	// how much of the per-call population is structurally not comparable
	// before trusting the gate.
	CoverageSyzUnavailCount   int     `json:"coverage_syz_unavailable_count"`
	CoverageRefUnavailCount   int     `json:"coverage_ref_unavailable_count"`
	// §13.6 E (schema v8): per-call low-band samples classified as
	// "process cold-fault measurement artifact" by the conservative rules
	// in classifyProcessColdFault (call#0, ≥3× cov skew, ≥50 % of larger
	// side's unique PCs in the curated VM/page-fault/page-cache family,
	// and vmlinux symbol table available). NOT included in the
	// actionable_low_band gate denominator. 0 when no -vmlinux was passed.
	CoverageProcessColdFaultCount int `json:"coverage_process_cold_fault_count"`
	// Flag: true when -vmlinux was loaded successfully. Lets dashboards
	// distinguish "0 cold-fault classifications because no symbols" from
	// "0 because trace had no cold-fault pattern".
	CoverageSymbolTableLoaded bool   `json:"coverage_symbol_table_loaded"`
	KCovNote                  string  `json:"kcov_note,omitempty"`

	// §13.5 P2: per-call samples where the worker side's raw kcov ring
	// buffer hit the kernel `COVER_SIZE` cap (kcovBufferCap). Tracked at
	// report level here so the coverage gate can subtract it from
	// low_band_count to form actionable_low_band_count. See plan §13.5
	// finding #3 for the root cause.
	KCovBufferOverflowCount int `json:"kcov_buffer_overflow_count"`

	// Per-call jaccard sample list — feeds jaccardDistribution. Excluded
	// from JSON (would be N × float64 = up to 50 KB for thousand-class
	// samples; the distribution percentiles already summarize it).
	KCovJaccardSamples []float64 `json:"-"`

	Samples []sampleEntry `json:"samples"`
}

const (
	// flatrpc.fbs:158 ExecFlag bit positions.
	execFlagCollectSignal = 1 << 0
	execFlagCollectCover  = 1 << 1
	execFlagDedupCover    = 1 << 2
	execFlagCollectComps  = 1 << 3
	execFlagThreaded      = 1 << 4

	// flatrpc.fbs CallFlag bit_flags: bit 0 Executed, bit 1 Finished,
	// bit 2 Blocked, bit 3 FaultInjected, bit 4 CoverageOverflow.
	//
	// callFlagSemanticMask covers the four execution-state bits. We
	// deliberately EXCLUDE bit 4 (CoverageOverflow) from wire-equivalence
	// comparison — it's a kcov-buffer-fill observability artifact set by
	// the kernel only when the per-call PC buffer fills up. Whether it
	// fires depends on per-side kcov buffer sizing (host-side config), not
	// on whether the syscall walked the same kernel path. Folding it in
	// would let a benign buffer-size delta fail the wire gate (observed
	// 2026-05-19: req 667 call#0 syz=19 ref=3 — single CoverageOverflow
	// flip out of ~3.4k compared calls).
	callFlagSemanticMask uint8 = 0x0F

	// Individual CallFlag bits used by the "did this call actually run?"
	// predicate. Mirrors `Executed` in flatrpc.fbs CallFlag bit_flags. Both
	// sides set this bit only after Dispatch returns from a real syscall
	// (reFuzz: kernel_wire_driver.cpp serial line 927 / threaded line 1285;
	// upstream: executor.cc's per-call CallInfoRaw build). When the bit is
	// NOT set, the call is one of:
	//   * upstream syz `empty_call(NONE=0, errno=998)` placeholder filled by
	//     finish_output for nCalls slots that never completed
	//     (executor.cc:1542 — finish_output empty_call init).
	//   * reFuzz pre-zero / mid-loop bail: SyzExecResult slots are memset
	//     to zero before the dispatch loop; bail before reaching call_index
	//     leaves flags=0 err=0 (kernel_wire_driver.cpp:706 / :1147).
	//   * reFuzz threaded path `Blocked` (timeout / all-threads-busy):
	//     flags=Blocked(=4), Executed bit absent (kernel_wire_driver.cpp:
	//     1264 + 1279).
	// All three "not executed" states must be excluded from errno comparison
	// because comparing a skipped placeholder against a real syscall outcome
	// generates false-positive errno_mismatch. See §13.6.
	kCallFlagExecuted uint8 = 0x01
)

// dumpPCSet writes a sorted-unique uint64 PC set to path as one
// "0x%016x\n" line per PC. Used by §13.5 B1 #3 root-cause diagnosis: caller
// dumps syz-side + ref-side PCs for every low-band call so addr2line can
// bucket them by kernel symbol.
func dumpPCSet(path string, pcs []uint64) error {
	uniq := make(map[uint64]struct{}, len(pcs))
	for _, v := range pcs {
		uniq[v] = struct{}{}
	}
	sorted := make([]uint64, 0, len(uniq))
	for v := range uniq {
		sorted = append(sorted, v)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := make([]byte, 0, len(sorted)*19)
	for _, v := range sorted {
		bw = append(bw, []byte(fmt.Sprintf("0x%016x\n", v))...)
	}
	_, err = f.Write(bw)
	return err
}

// dumpPCRaw writes the PC slice **in original write order** (kcov ring
// fill sequence — area_[1..count]), one "0x%016x\n" per line, no dedupe,
// no sort. Used by §13.5 B1 #3 mechanism A-vs-B discriminator: the head
// of the file is the earliest written PCs, the tail is the latest before
// the ring filled. addr2line on head/mid/tail slices distinguishes
// "btrfs never made it into the ring" (A) from "btrfs got written then
// truncated/flushed" (B).
func dumpPCRaw(path string, pcs []uint64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := make([]byte, 0, len(pcs)*19)
	for _, v := range pcs {
		bw = append(bw, []byte(fmt.Sprintf("0x%016x\n", v))...)
	}
	_, err = f.Write(bw)
	return err
}

func compareSessions(sessions []*session, maxSamples int, pcDumpDir, pcDumpRawDir string, forceDumpReqs map[uint64]bool, kt *kernelSymbolTable, perCall *perCallEmitter) *report {
	symbolTableLoaded := kt != nil && kt.loaded
	rep := &report{
		SchemaVersion:       8,
		Samples:             []sampleEntry{},
		AbnormalKindBuckets: map[string]int{},
		CoverageSymbolTableLoaded: symbolTableLoaded,
		KCovNote: "per-call Jaccard over kcov PCs (compared+normal requests, " +
			"syz ExecFlagCollectCover set). Calls with BOTH sides empty are " +
			"counted in kcov_jaccard_both_empty_count and EXCLUDED from " +
			"kcov_jaccard_sum/count — the (empty,empty)→1.0 identity is " +
			"not equivalence evidence. jaccard_mean = sum/count is computed " +
			"only over calls where at least one side observed PCs.",
	}
	// Initialize all known buckets so JSON keys are stable for downstream
	// scrapers even when a bucket has zero observations.
	for _, name := range abnormalKindNames {
		rep.AbnormalKindBuckets[name] = 0
	}
	rep.SessionCount = len(sessions)
	rep.VMResetCount = len(sessions) // each session = 1 fresh VM/worker cycle

	addSample := func(s sampleEntry) {
		if len(rep.Samples) < maxSamples {
			rep.Samples = append(rep.Samples, s)
		}
	}

	for _, sess := range sessions {
		// Collect every (request_id) seen in syz OR ref so cross-only
		// outcomes still get accounted for.
		seenReqs := map[int64]struct{}{}
		for id := range sess.SyzRequests {
			seenReqs[id] = struct{}{}
		}
		for id := range sess.RefOutcomes {
			seenReqs[id] = struct{}{}
		}
		for id := range sess.RefSkips {
			seenReqs[id] = struct{}{}
		}

		for reqID := range seenReqs {
			rep.RequestTotal++

			syz, hasSyz := sess.SyzRequests[reqID]
			if !hasSyz || (!syz.HasRequest && !syz.HasResult) {
				syz = nil
				hasSyz = false
			}
			skip, hasSkip := sess.RefSkips[reqID]
			outcome, hasOutcome := sess.RefOutcomes[reqID]

			// 1. Replay skip (CollectComps / Threaded / missing proc_id) —
			// count it, don't compare. Different reasons go into different
			// buckets so operators can see "trace lacks proc_id" (a slot-
			// affinity gap surfaced by PR3 step 3) separately from
			// CollectComps-style protocol gaps.
			if hasSkip {
				switch skip.Reason {
				case skipReasonMissingProcId:
					rep.RequestSkipMissingProcId++
				default:
					rep.RequestSkipUnsupported++
				}
				_ = skip
				continue
			}
			// 2. No ref outcome at all (in trace but never reached replayer) — hole.
			if !hasOutcome {
				rep.RequestSkipReplayHoles++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "replay_hole",
					Detail:    "trace has ExecRequest, ref_result missing outcome",
				})
				continue
			}
			// 3. Ref outcome=missing (replayer accepted but worker never replied).
			if outcome.Kind == outcomeMissing {
				rep.RequestSkipReplayHoles++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "replay_outcome_missing",
				})
				continue
			}
			// 4. From here both sides should have data. Compute hang side-channel first.
			if hasSyz && syz.Hanged {
				rep.SyzHanged++
			}
			if outcome.Kind == outcomeAbnormal {
				if outcome.AbnormalKind == 0 /*kTimeout*/ {
					rep.RefHanged++
				}
				name := "unknown"
				if int(outcome.AbnormalKind) < len(abnormalKindNames) {
					name = abnormalKindNames[outcome.AbnormalKind]
				}
				rep.AbnormalKindBuckets[name]++
			}

			syzFail := !hasSyz || syz.Hanged || syz.Error != "" || !syz.HasResult
			refFail := outcome.Kind == outcomeAbnormal

			if refFail && !syzFail {
				rep.RefOnlyFail++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "ref_only_fail",
					Detail:    fmt.Sprintf("ref abnormal_kind=%d", outcome.AbnormalKind),
				})
				rep.RequestCompared++
				continue
			}
			if syzFail && !refFail {
				rep.SyzOnlyFail++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "syz_only_fail",
					Detail:    fmt.Sprintf("syz hanged=%v err=%q", syz != nil && syz.Hanged, errStr(syz)),
				})
				rep.RequestCompared++
				continue
			}
			if syzFail && refFail {
				rep.RequestCompared++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "both_fail",
				})
				continue
			}

			// 5. Both sides normal → precise decode + per-call compare.
			rep.RequestCompared++
			rep.BothNormalCount++
			if (syz.ExecFlags & execFlagCollectCover) == 0 {
				rep.SyzCoverUnavailable++
			}
			nCalls := len(syz.Calls)
			refCalls, refTail, decodeOK := decodeRefOutput(outcome.RawOutput, nCalls)
			outcome.Calls = refCalls // surface for callsBrief / sample formatting
			if !decodeOK && refCalls == nil {
				// raw output too short to even hold nCalls heads — count it as
				// a call_count mismatch (ref produced fewer calls than syz).
				rep.CallCountMismatch++
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "mismatch_call_count",
					Detail: fmt.Sprintf("ref raw output %d B < %d (nCalls=%d * %d)",
						len(outcome.RawOutput), nCalls*syzExecResultSize,
						nCalls, syzExecResultSize),
				})
				continue
			}
			match, reason, skipStats := compareCalls(syz, outcome)
			rep.SyzCallSkipped += skipStats.SyzSkipped
			rep.RefCallSkipped += skipStats.RefSkipped
			rep.BothCallSkipped += skipStats.BothSkipped
			if !match {
				switch reason {
				case "errno":
					rep.ErrnoMismatch++
				case "flags":
					rep.CallFlagMismatch++
				}
				addSample(sampleEntry{
					SessionID: sess.SyzSessionID,
					ReqID:     reqID,
					Reason:    "mismatch_" + reason,
					Detail:    callsBrief(syz, outcome),
				})
			} else {
				rep.Matched++
				// §13.6: when at least one call on this request was skipped
				// (either side missing Executed bit), the request still got
				// "matched" because every comparable call agreed — but the
				// skip is worth surfacing so an operator can see how much of
				// the request was actually comparable. Emit one sample per
				// such request, capped by maxSamples like other reasons.
				if skipStats.SyzSkipped+skipStats.RefSkipped+skipStats.BothSkipped > 0 {
					addSample(sampleEntry{
						SessionID: sess.SyzSessionID,
						ReqID:     reqID,
						Reason:    "matched_with_skips",
						Detail: fmt.Sprintf("syz_skip=%d ref_skip=%d both_skip=%d %s",
							skipStats.SyzSkipped,
							skipStats.RefSkipped,
							skipStats.BothSkipped,
							callsBrief(syz, outcome)),
					})
				}
			}

			// §7.3 kcov_jaccard: real per-call Jaccard when both sides have
			// cover. Recorded but not gated. refTail may be nil if cover_offset
			// math went out of bounds — then we skip jaccard for this request
			// but the wire-equivalence pass above still ran. Both-empty
			// handling lives in accumKCovJaccard.
			//
			// §13.5 COV-B.4 divergence sample emission: any per-call jaccard
			// below kcovDivergenceThreshold (0.5) gets a sample entry with
			// the resolved syscall name attached. These are the per-pseudo
			// "syz deep / ref shallow" evidence dumps that drive B1/B2 worker
			// repair priorities.
			if refTail != nil && (syz.ExecFlags&execFlagCollectCover) != 0 {
				forced := reqID >= 0 && forceDumpReqs[uint64(reqID)]
				for i := 0; i < nCalls; i++ {
					refCov := refCoverSlice(refTail, refCalls[i].CoverOffset, refCalls[i].CoverCount)
					// §13.6 T1.D: pass per-side Executed bits so accumKCovJaccard
					// can route one-side-skipped + other-side-with-cover into the
					// unavail bucket instead of letting the forced 0.0 jaccard
					// register as a low-band sample.
					syzExecuted := syz.Calls[i].Flags&kCallFlagExecuted != 0
					refExecuted := uint8(refCalls[i].Flags&0xFF)&kCallFlagExecuted != 0
					j, outcome := accumKCovJaccard(rep,
						syz.Calls[i].Cover, syzExecuted,
						refCov, refExecuted)
					refOverflow := len(refCov) >= kcovBufferCap
					emitPerCallRecord(perCall, sess.SyzSessionID, reqID, i,
						&syz.Calls[i], &refCalls[i], refCov,
						syzExecuted, refExecuted,
						true, j, refOverflow)
					isLowBand := outcome == kJaccardCompared && j < kcovDivergenceThreshold
					// §13.6 E: classify a low-band sample as process-cold-fault
					// measurement artifact if the conservative rules in
					// classifyProcessColdFault are met. Symbol-table-required,
					// call#0-only, ≥3× cov skew, ≥50 % unique-PCs in fault
					// family. NULL classifier → no bucketing.
					isColdFault := isLowBand &&
						classifyProcessColdFault(kt, i, syz.Calls[i].Cover, refCov)
					if isLowBand {
						// §13.5 P2: classify divergence by whether the worker
						// side hit the kernel kcov ring buffer cap. raw refCov
						// >= kcovBufferCap is treated as a worker measurement
						// artifact and bucketed separately so the coverage
						// gate doesn't fail on B1 #3 known root cause.
						if len(refCov) >= kcovBufferCap {
							rep.KCovBufferOverflowCount++
						} else if isColdFault {
							// Buckets are mutually exclusive: overflow takes
							// priority because the kcov ring filling up is a
							// hard worker-side capacity issue that would mask
							// any classifier output anyway. A non-overflow
							// low-band sample is the only candidate for the
							// cold-fault bucket.
							rep.CoverageProcessColdFaultCount++
						}
						addSample(sampleEntry{
							SessionID: sess.SyzSessionID,
							ReqID:     reqID,
							Reason:    "coverage_divergence",
							Detail: fmt.Sprintf(
								"call=%d syscall=%s jaccard=%.4f syz_cov=%d ref_cov=%d",
								i,
								syscallNameOrPlaceholder(syz.Calls[i].SyscallName),
								j,
								len(syz.Calls[i].Cover),
								len(refCov)),
						})
					}
					// §13.5 B1 #3 PC dump: write sorted-unique syz / ref PCs.
					// Fires when the call is low-band OR the req is in the
					// force-dump set (the latter for after-fix verification of
					// formerly low-band samples that should now be high-band).
					if isLowBand || forced {
						if pcDumpDir != "" {
							syzPath := filepath.Join(pcDumpDir,
								fmt.Sprintf("req%d_call%d_syz.txt", reqID, i))
							refPath := filepath.Join(pcDumpDir,
								fmt.Sprintf("req%d_call%d_ref.txt", reqID, i))
							if err := dumpPCSet(syzPath, syz.Calls[i].Cover); err != nil {
								log.Printf("pc-dump syz req=%d call=%d: %v", reqID, i, err)
							}
							if err := dumpPCSet(refPath, refCov); err != nil {
								log.Printf("pc-dump ref req=%d call=%d: %v", reqID, i, err)
							}
						}
						// §13.5 B1 #3 mechanism A vs B discriminator: raw
						// write-order PC dump. ref file head = earliest written
						// PCs in the kcov ring; tail = latest before cap. syz
						// side dumped too for symmetry — though syz cov never
						// hits cap so write order is less interesting there.
						if pcDumpRawDir != "" {
							syzPath := filepath.Join(pcDumpRawDir,
								fmt.Sprintf("req%d_call%d_syz_raw.txt", reqID, i))
							refPath := filepath.Join(pcDumpRawDir,
								fmt.Sprintf("req%d_call%d_ref_raw.txt", reqID, i))
							if err := dumpPCRaw(syzPath, syz.Calls[i].Cover); err != nil {
								log.Printf("pc-dump-raw syz req=%d call=%d: %v", reqID, i, err)
							}
							if err := dumpPCRaw(refPath, refCov); err != nil {
								log.Printf("pc-dump-raw ref req=%d call=%d: %v", reqID, i, err)
							}
						}
					}
				}
			} else if perCall != nil {
				// No-cover branch: still emit per-call jsonl so the downstream
				// per-pseudo aggregate sees every (request, call). Jaccard / PC
				// fields are dropped via cover_available=false. Without this
				// branch we'd silently lose errno-only evidence rows when the
				// request lacked CollectCover.
				for i := 0; i < nCalls; i++ {
					syzExecuted := syz.Calls[i].Flags&kCallFlagExecuted != 0
					refExecuted := uint8(refCalls[i].Flags&0xFF)&kCallFlagExecuted != 0
					emitPerCallRecord(perCall, sess.SyzSessionID, reqID, i,
						&syz.Calls[i], &refCalls[i], nil,
						syzExecuted, refExecuted,
						false, 0, false)
				}
			}
		}
	}

	// §13.3 rates (observability) — emit even when denominators are 0 so the
	// JSON shape stays stable.
	if rep.RequestTotal > 0 {
		rep.RawComparedRate = float64(rep.RequestCompared) / float64(rep.RequestTotal)
	}
	comparableDenom := rep.RequestTotal - rep.RequestSkipUnsupported -
		rep.RequestSkipMissingProcId
	if comparableDenom > 0 {
		rep.ComparableRate = float64(rep.RequestCompared) / float64(comparableDenom)
	}

	// §13.1 three-tier ship gate → machine-readable verdict.
	// All three tiers require at least one compared request, otherwise the
	// "zero mismatch" / "zero unavailable" surface area is vacuous.
	requireData := rep.RequestCompared > 0

	// Tier 1: wire gate.
	rep.ShipGatePassed.Wire.ReplayHolesClean = rep.RequestSkipReplayHoles == 0
	rep.ShipGatePassed.Wire.CallCountMatches = rep.CallCountMismatch == 0
	rep.ShipGatePassed.Wire.CallFlagMatches = rep.CallFlagMismatch == 0
	rep.ShipGatePassed.Wire.Passed = requireData &&
		rep.ShipGatePassed.Wire.ReplayHolesClean &&
		rep.ShipGatePassed.Wire.CallCountMatches &&
		rep.ShipGatePassed.Wire.CallFlagMatches

	// Tier 2: result gate. Default threshold == 0; per plan §13.1 the "low and
	// explainable" path is operator-driven (downstream attribution), not auto.
	rep.ShipGatePassed.Result.ErrnoMatches = rep.ErrnoMismatch == 0
	rep.ShipGatePassed.Result.Passed = requireData && rep.ShipGatePassed.Result.ErrnoMatches

	// Tier 3: coverage gate. coverage_available_rate is over both-normal
	// compared requests (the only ones that touch SyzCoverUnavailable).
	rep.ShipGatePassed.Coverage.JaccardSampleCount = rep.KCovJaccardCount
	if rep.KCovJaccardCount > 0 {
		rep.ShipGatePassed.Coverage.JaccardMean = rep.KCovJaccardSum / float64(rep.KCovJaccardCount)
	}
	rep.ShipGatePassed.Coverage.JaccardDistribution = buildJaccardDistribution(
		rep.KCovJaccardSamples, rep.KCovJaccardBothEmptyCount,
		rep.KCovBufferOverflowCount,
		rep.CoverageProcessColdFaultCount)
	if rep.BothNormalCount > 0 {
		avail := rep.BothNormalCount - rep.SyzCoverUnavailable
		if avail < 0 {
			avail = 0
		}
		rep.ShipGatePassed.Coverage.CoverageAvailableRate =
			float64(avail) / float64(rep.BothNormalCount)
	}
	// §13.1 / §13.5 P2 coverage gate (post-B1 #3 root-cause calibration):
	//   - p95 >= kcovP95Min (0.8) — 95 % of per-call jaccards must clear 0.8
	//   - actionable_low_band_count / sample_count < kcovActionableLowBandMaxRatio
	//     (1 %). actionable = low_band - kcov_buffer_overflow, so worker-side
	//     kcov ring overflow false-positives don't fail the gate.
	switch {
	case rep.KCovJaccardCount == 0:
		rep.ShipGatePassed.Coverage.Status = "insufficient_data"
		rep.ShipGatePassed.Coverage.Passed = false
	default:
		d := rep.ShipGatePassed.Coverage.JaccardDistribution
		p95OK := d.P95 >= kcovP95Min
		actionableRatio := 0.0
		if d.SampleCount > 0 {
			actionableRatio = float64(d.ActionableLowBandCount) / float64(d.SampleCount)
		}
		actionableOK := actionableRatio < kcovActionableLowBandMaxRatio
		if p95OK && actionableOK {
			rep.ShipGatePassed.Coverage.Status = "pass"
			rep.ShipGatePassed.Coverage.Passed = true
		} else {
			rep.ShipGatePassed.Coverage.Status = "fail"
			rep.ShipGatePassed.Coverage.Passed = false
		}
	}

	rep.ShipGatePassed.Overall = rep.ShipGatePassed.Wire.Passed &&
		rep.ShipGatePassed.Result.Passed &&
		rep.ShipGatePassed.Coverage.Passed

	return rep
}

// callCmpStats counts per-call skip cases observed in one request. See
// kCallFlagExecuted comment for the rationale.
type callCmpStats struct {
	SyzSkipped  int // syz didn't execute, ref did
	RefSkipped  int // ref didn't execute, syz did
	BothSkipped int // neither side executed
}

func compareCalls(syz *syzRequest, ref *refOutcome) (matched bool, reason string, stats callCmpStats) {
	// Precondition: len(syz.Calls) == len(ref.Calls). Upstream call-count
	// shortfall is detected by decodeRefOutput and short-circuits before this
	// runs, so we only need to walk errno → flags here.
	//
	// §13.6 Executed-bit predicate: only compare errno/flags for calls
	// where BOTH sides have CallFlag.Executed set. Otherwise one side never
	// reached the syscall (upstream empty_call placeholder / reFuzz
	// pre-zero / Blocked-without-Executed), so the slot's err/flags are
	// not real outcomes and comparing them generates false positives.
	for i := range syz.Calls {
		syzExec := syz.Calls[i].Flags&kCallFlagExecuted != 0
		refExec := uint8(ref.Calls[i].Flags&0xFF)&kCallFlagExecuted != 0
		switch {
		case !syzExec && !refExec:
			stats.BothSkipped++
			continue
		case !syzExec:
			stats.SyzSkipped++
			continue
		case !refExec:
			stats.RefSkipped++
			continue
		}
		if syz.Calls[i].Error != ref.Calls[i].Err {
			return false, "errno", stats
		}
	}
	for i := range syz.Calls {
		syzExec := syz.Calls[i].Flags&kCallFlagExecuted != 0
		refExec := uint8(ref.Calls[i].Flags&0xFF)&kCallFlagExecuted != 0
		if !(syzExec && refExec) {
			// already counted in the errno loop above
			continue
		}
		// Reduce ref Flags to lower 8 bits to match syz CallFlag width,
		// then mask off CoverageOverflow (bit 4) per the semantic-bits
		// rationale on callFlagSemanticMask.
		syzFlags := syz.Calls[i].Flags & callFlagSemanticMask
		refFlags := uint8(ref.Calls[i].Flags&0xFF) & callFlagSemanticMask
		if syzFlags != refFlags {
			return false, "flags", stats
		}
	}
	return true, "", stats
}

func errStr(s *syzRequest) string {
	if s == nil {
		return "<no syz request>"
	}
	return s.Error
}

// §13.6 T1 mount-mismatch diagnostic emitter. Walks every session's compared
// requests; for each request whose first call is syz_mount_image$* AND syz
// errno differs from ref errno on call 0, write a CSV row that joins:
//   * syz-side request timing (H2E / Executing / ExecResult ts) + proc_id
//   * ref-side dispatch timing (submit / complete ns)
//   * fs type (from the $-suffix of the resolved syscall name)
//   * how many syz_mount_image calls are in the program (single → reuse
//     pressure comes from a prior request on the same proc; multiple →
//     in-program reuse pressure)
//   * previous syz_mount_image* request on the same proc (req_id, fs,
//     errno, ExecResult ts) and the cleanup gap to current Executing
//
// The CSV is NOT folded into the JSON report — it's a separate side-channel
// for offline analysis. Failure to write is logged but doesn't fail the run.
func writeMountMismatchDiag(path string, sessions []*session) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	header := []string{
		"session_id", "req_id", "proc_id", "fs", "syz_errno", "ref_errno",
		"syz_flags", "ref_flags",
		"h2e_ts_ns", "executing_ts_ns", "exec_result_ts_ns",
		"ref_submit_ns", "ref_complete_ns",
		"mounts_in_program",
		"prev_mount_req_id", "prev_mount_fs", "prev_mount_syz_errno",
		"prev_mount_exec_result_ts_ns", "syz_cleanup_gap_ns",
		// ref-side prev complete + complete-to-complete spacing. We don't
		// record the worker's process-start ts, only submit (queue time)
		// and complete (worker child done). Since the replayer submits the
		// whole queue in a burst, submit_ns clusters at session start and
		// can predate the previous request's complete_ns — using submit
		// for the gap measurement is misleading. Use the complete→complete
		// spacing instead: it's a strict upper bound on the reFuzz worker's
		// wall-clock gap between processing two requests on the same
		// proc_slot_id (= worker_id). If ref_complete_to_complete_ns is
		// already in the same order of magnitude as syz_cleanup_gap_ns
		// (or smaller), the lifecycle/timing hypothesis stays — both sides
		// give the kernel similar cleanup time and the EBUSY divergence is
		// purely about cleanup ORDER inside the worker process.
		"prev_ref_complete_ns", "ref_complete_to_complete_ns",
	}
	if _, err := fmt.Fprintln(w, strings.Join(header, ",")); err != nil {
		return err
	}

	for _, sess := range sessions {
		// Build per-proc history of (Executing ts asc) syz_mount_image requests.
		// Used to find "previous mount-image request on the same proc".
		type procEntry struct {
			req           *syzRequest
			fs            string
			call0SyzErrno int32
		}
		perProc := map[int32][]procEntry{}
		var allReqs []*syzRequest
		for _, r := range sess.SyzRequests {
			allReqs = append(allReqs, r)
		}
		sort.Slice(allReqs, func(i, j int) bool {
			return allReqs[i].ExecutingTsNs < allReqs[j].ExecutingTsNs
		})
		for _, r := range allReqs {
			if r.ProcID < 0 || len(r.Calls) == 0 {
				continue
			}
			name := r.Calls[0].SyscallName
			if !strings.HasPrefix(name, "syz_mount_image$") {
				continue
			}
			perProc[r.ProcID] = append(perProc[r.ProcID], procEntry{
				req:           r,
				fs:            strings.TrimPrefix(name, "syz_mount_image$"),
				call0SyzErrno: r.Calls[0].Error,
			})
		}

		// For each compared request whose first call is syz_mount_image* with
		// syz != ref errno, emit a row.
		for _, r := range allReqs {
			if !r.HasRequest || !r.HasResult || len(r.Calls) == 0 {
				continue
			}
			name := r.Calls[0].SyscallName
			if !strings.HasPrefix(name, "syz_mount_image$") {
				continue
			}
			outcome, ok := sess.RefOutcomes[r.ID]
			if !ok || outcome.Kind != outcomeNormal || len(outcome.Calls) == 0 {
				continue
			}
			syzErr := r.Calls[0].Error
			refErr := outcome.Calls[0].Err
			if syzErr == refErr {
				continue
			}
			fs := strings.TrimPrefix(name, "syz_mount_image$")
			mountsInProgram := 0
			for _, c := range r.Calls {
				if strings.HasPrefix(c.SyscallName, "syz_mount_image$") {
					mountsInProgram++
				}
			}
			// Walk this proc's history; find the last mount-image with
			// ExecResult ts strictly earlier than current Executing ts.
			var prev *procEntry
			if r.ProcID >= 0 {
				hist := perProc[r.ProcID]
				for i := range hist {
					if hist[i].req.ID == r.ID {
						break
					}
					if hist[i].req.ExecResultTsNs > 0 &&
						(r.ExecutingTsNs == 0 || hist[i].req.ExecResultTsNs < r.ExecutingTsNs) {
						p := hist[i]
						prev = &p
					}
				}
			}
			prevReqID := int64(-1)
			prevFs := ""
			prevSyzErr := int32(0)
			prevExecResultTs := uint64(0)
			cleanupGap := int64(-1)
			prevRefCompleteNs := uint64(0)
			refCompleteSpacing := int64(-1)
			if prev != nil {
				prevReqID = prev.req.ID
				prevFs = prev.fs
				prevSyzErr = prev.call0SyzErrno
				prevExecResultTs = prev.req.ExecResultTsNs
				if r.ExecutingTsNs > 0 && prevExecResultTs > 0 &&
					r.ExecutingTsNs >= prevExecResultTs {
					cleanupGap = int64(r.ExecutingTsNs - prevExecResultTs)
				}
				if prevOutcome, ok := sess.RefOutcomes[prev.req.ID]; ok &&
					prevOutcome.Kind == outcomeNormal {
					prevRefCompleteNs = prevOutcome.CompleteNs
					if outcome.CompleteNs > 0 && prevRefCompleteNs > 0 &&
						outcome.CompleteNs >= prevRefCompleteNs {
						refCompleteSpacing = int64(outcome.CompleteNs - prevRefCompleteNs)
					}
				}
			}
			row := []string{
				fmt.Sprint(sess.SyzSessionID),
				fmt.Sprint(r.ID),
				fmt.Sprint(r.ProcID),
				fs,
				fmt.Sprint(syzErr),
				fmt.Sprint(refErr),
				fmt.Sprint(r.Calls[0].Flags),
				fmt.Sprint(outcome.Calls[0].Flags & 0xFF),
				fmt.Sprint(r.H2ETsNs),
				fmt.Sprint(r.ExecutingTsNs),
				fmt.Sprint(r.ExecResultTsNs),
				fmt.Sprint(outcome.SubmitNs),
				fmt.Sprint(outcome.CompleteNs),
				fmt.Sprint(mountsInProgram),
				fmt.Sprint(prevReqID),
				prevFs,
				fmt.Sprint(prevSyzErr),
				fmt.Sprint(prevExecResultTs),
				fmt.Sprint(cleanupGap),
				fmt.Sprint(prevRefCompleteNs),
				fmt.Sprint(refCompleteSpacing),
			}
			if _, err := fmt.Fprintln(w, strings.Join(row, ",")); err != nil {
				return err
			}
		}
	}
	return nil
}

// syscallNameOrPlaceholder returns the resolved syscall name, or a
// "(unknown)" sentinel when the trace wasn't deserializable. Used by §13.5
// COV-B.4 sample entries — empty strings here would silently hide attribution
// gaps in the divergence dump.
func syscallNameOrPlaceholder(name string) string {
	if name == "" {
		return "(unknown)"
	}
	return name
}

func callsBrief(syz *syzRequest, ref *refOutcome) string {
	n := len(syz.Calls)
	if m := len(ref.Calls); m > n {
		n = m
	}
	if n > 4 {
		n = 4
	}
	var b []byte
	for i := 0; i < n; i++ {
		var s, r, name string
		if i < len(syz.Calls) {
			s = fmt.Sprintf("syz(f=%d e=%d)", syz.Calls[i].Flags, syz.Calls[i].Error)
			name = syz.Calls[i].SyscallName
		} else {
			s = "syz(-)"
		}
		if i < len(ref.Calls) {
			r = fmt.Sprintf("ref(f=%d e=%d)", ref.Calls[i].Flags&0xFF, ref.Calls[i].Err)
		} else {
			r = "ref(-)"
		}
		if i > 0 {
			b = append(b, ',', ' ')
		}
		// COV-B.4 / A5: include the syscall name so flag/errno mismatch
		// samples are self-attributing without a separate trace lookup.
		b = append(b, fmt.Sprintf("#%d[%s] %s %s",
			i, syscallNameOrPlaceholder(name), s, r)...)
	}
	return string(b)
}

func nullTrim(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ============================================================
// per-call JSONL emitter — feeds scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py,
// the post-layer3 replacement for the retired per-pseudo allowlist pipeline.
// Schema is a strict superset of the old layer3 per-call jsonl so the
// renamed aggregator can keep its parse_pcs_hex / err_mismatch logic.
// ============================================================

type perCallRecord struct {
	SessionID uint64 `json:"session_id"`
	ReqID     int64  `json:"req_id"`
	CallIdx   int    `json:"call_idx"`
	Syscall   string `json:"syscall"`

	SyzErr int32 `json:"syz_err"`
	RefErr int32 `json:"ref_err"`

	SyzFlags    uint8 `json:"syz_flags"`
	RefFlags    uint8 `json:"ref_flags"`
	SyzExecuted bool  `json:"syz_executed"`
	RefExecuted bool  `json:"ref_executed"`

	// raw_err_mismatch ignores Executed bits — direct numeric compare.
	// real_err_mismatch requires both Executed (matches compareCalls semantics).
	// actionable_err_mismatch additionally filters out the syz_mount_image$*
	// {0, EBUSY=16} structural-tension family identified in plan §13.5.
	RawErrMismatch        bool `json:"raw_err_mismatch"`
	RealErrMismatch       bool `json:"real_err_mismatch"`
	ActionableErrMismatch bool `json:"actionable_err_mismatch"`

	// PC sets encoded as continuous 16-hex-char-per-uint64 strings (sorted
	// + deduped) — matches the layer3 schema parse_pcs_hex consumes.
	SyzPcsHex string `json:"syz_pcs_hex"`
	RefPcsHex string `json:"ref_pcs_hex"`

	// {syz,ref}_pc_count is the RAW kcov ring write count INCLUDING duplicates
	// (kernel writes the same PC each time it's traced — tight loops inflate
	// this). The syz side is pre-deduped by syzkaller's executor so it equals
	// its unique count; the ref side is not, so ref_pc_count >> unique_ref
	// for deep syscalls (mount-image, kvm_setup, usb_connect — saw 95× on
	// msdos). For cross-program ratio / allowlist decisions use the unique_*
	// fields below — they share the same set semantics as jaccard.
	SyzPcCount int `json:"syz_pc_count"`
	RefPcCount int `json:"ref_pc_count"`

	// Deduped PC set cardinality. Same semantics as the jaccard numerator /
	// denominator built from the syz_pcs_hex / ref_pcs_hex sets above (those
	// strings are already sorted + uniq). Always emitted when CoverAvailable.
	UniqueSyzPcCount int `json:"unique_syz_pc_count"`
	UniqueRefPcCount int `json:"unique_ref_pc_count"`

	// CoverAvailable=false means the request lacked CollectCover or ref had
	// no cover tail — Jaccard / PC fields are then meaningless and Jaccard
	// is omitted. KcovBufferOverflow flags refCov hitting kcovBufferCap
	// (raw worker measurement artifact, see plan §13.5 finding #3).
	CoverAvailable     bool     `json:"cover_available"`
	Jaccard            *float64 `json:"jaccard,omitempty"`
	KcovBufferOverflow bool     `json:"kcov_buffer_overflow"`
}

type perCallEmitter struct {
	f   *os.File
	w   *bufio.Writer
	enc *json.Encoder
	cnt int
}

func newPerCallEmitter(path string) (*perCallEmitter, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	// JSONL: one record per line, no indent.
	return &perCallEmitter{f: f, w: w, enc: enc}, nil
}

func (e *perCallEmitter) emit(rec *perCallRecord) {
	if e == nil {
		return
	}
	if err := e.enc.Encode(rec); err != nil {
		log.Printf("per-call-jsonl emit (req=%d call=%d): %v", rec.ReqID, rec.CallIdx, err)
		return
	}
	e.cnt++
}

func (e *perCallEmitter) close() error {
	if e == nil {
		return nil
	}
	if err := e.w.Flush(); err != nil {
		return err
	}
	return e.f.Close()
}

// encodePCsHex serializes a PC slice as continuous 16-hex-char/uint64 string
// (sorted + deduped). Matches the layer3 schema so the renamed aggregator's
// parse_pcs_hex consumer reads it unchanged. Empty input → empty string.
// Also returns the unique PC count so callers can fill unique_*_pc_count
// without re-deduping.
func encodePCsHex(pcs []uint64) (string, int) {
	if len(pcs) == 0 {
		return "", 0
	}
	set := make(map[uint64]struct{}, len(pcs))
	for _, p := range pcs {
		set[p] = struct{}{}
	}
	uniq := make([]uint64, 0, len(set))
	for p := range set {
		uniq = append(uniq, p)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i] < uniq[j] })
	var sb strings.Builder
	sb.Grow(len(uniq) * 16)
	for _, p := range uniq {
		fmt.Fprintf(&sb, "%016x", p)
	}
	return sb.String(), len(uniq)
}

// mountErrnoTolerant: structural-tension hand-wave for the syz_mount_image$*
// family — both sides reporting {0, EBUSY} is treated as inter-program state
// residue, not a worker semantic gap. See plan §13.5.
func mountErrnoTolerant(syscall string, syzErr, refErr int32) bool {
	if !strings.HasPrefix(syscall, "syz_mount_image$") {
		return false
	}
	tolerantErrno := func(e int32) bool { return e == 0 || e == 16 /*EBUSY*/ }
	return tolerantErrno(syzErr) && tolerantErrno(refErr)
}

// ioUringCompleteErrnoLeak: syz_io_uring_complete is a pure C helper
// (executor/common_linux.h:1896 `return (...) ? cqe.res : (long)-1;`) that
// NEVER sets errno. On the no-fd path it returns -1 and leaves errno at
// whatever stale thread-local value a prior call left — so a syz-vs-ref errno
// mismatch on that path (e.g. syz=EFAULT, ref=0) is a thread-local residue
// artifact, not a real result divergence (both sides returned -1). Gate on the
// observable ref return (-1) so a real success path (valid fd, ret>=0) is never
// masked. See docs/plans/kcov-structural-noise/03_findings.md F9.
func ioUringCompleteErrnoLeak(syscall string, refRet int64) bool {
	return syscall == "syz_io_uring_complete" && refRet == -1
}

// emitPerCallRecord builds one JSONL row from per-call state. coverAvailable
// gates the PC / Jaccard fields; jaccardVal is read only when coverAvailable.
func emitPerCallRecord(
	em *perCallEmitter,
	sessionID uint64, reqID int64, callIdx int,
	syz *syzCall, ref *refCall, refCov []uint64,
	syzExecuted, refExecuted bool,
	coverAvailable bool, jaccardVal float64, kcovOverflow bool,
) {
	if em == nil {
		return
	}
	rawErrMis := syz.Error != ref.Err
	realErrMis := rawErrMis && syzExecuted && refExecuted
	actionable := realErrMis &&
		!mountErrnoTolerant(syz.SyscallName, syz.Error, ref.Err) &&
		!ioUringCompleteErrnoLeak(syz.SyscallName, ref.Ret)

	rec := perCallRecord{
		SessionID:             sessionID,
		ReqID:                 reqID,
		CallIdx:               callIdx,
		Syscall:               syz.SyscallName,
		SyzErr:                syz.Error,
		RefErr:                ref.Err,
		SyzFlags:              syz.Flags,
		RefFlags:              uint8(ref.Flags & 0xFF),
		SyzExecuted:           syzExecuted,
		RefExecuted:           refExecuted,
		RawErrMismatch:        rawErrMis,
		RealErrMismatch:       realErrMis,
		ActionableErrMismatch: actionable,
		CoverAvailable:        coverAvailable,
		KcovBufferOverflow:    kcovOverflow,
	}
	if coverAvailable {
		rec.SyzPcsHex, rec.UniqueSyzPcCount = encodePCsHex(syz.Cover)
		rec.RefPcsHex, rec.UniqueRefPcCount = encodePCsHex(refCov)
		rec.SyzPcCount = len(syz.Cover)
		rec.RefPcCount = len(refCov)
		j := jaccardVal
		rec.Jaccard = &j
	}
	em.emit(&rec)
}

// ============================================================
// main.
// ============================================================

func main() {
	flagTraceDir := flag.String("trace-dir", "", "directory containing exec_trace_*.bin (required)")
	flagRefResult := flag.String("ref-result", "", "path to ref_result.bin (required)")
	flagOutput := flag.String("output", "", "output report JSON path (required)")
	flagMaxSamples := flag.Int("max-samples", 30, "max sample mismatch entries in report")
	flagPCDumpDir := flag.String("pc-dump-dir", "",
		"if set, write sorted-unique syz / ref PC files (one per low-band "+
			"call, j<0.5) under this dir for §13.5 B1 #3 addr2line bucketing")
	flagPCDumpRawDir := flag.String("pc-dump-raw-dir", "",
		"if set, write raw write-order PC files (no dedupe / no sort) for "+
			"low-band calls under this dir; head=earliest kcov ring write, "+
			"tail=latest before cap. §13.5 B1 #3 mechanism A vs B discriminator")
	flagPCDumpForceReqs := flag.String("pc-dump-force-reqs", "",
		"comma-separated list of req IDs whose PCs are dumped regardless of "+
			"jaccard (alongside -pc-dump-dir / -pc-dump-raw-dir). Useful for "+
			"diagnostic comparisons of formerly low-band samples that the worker "+
			"fix may have moved above the threshold")
	flagMountMismatchDiag := flag.String("mount-mismatch-diag", "",
		"if set, write a CSV at PATH with one row per syz_mount_image* "+
			"errno_mismatch — columns: req_id, proc_id, fs, syz_errno, "+
			"ref_errno, h2e_ts_ns, executing_ts_ns, exec_result_ts_ns, "+
			"ref_submit_ns, ref_complete_ns, mounts_in_program, "+
			"prev_mount_req_id, prev_mount_fs, prev_mount_syz_errno, "+
			"prev_mount_exec_result_ts_ns, cleanup_gap_ns. T1 step-6 "+
			"investigation hook for the per-proc timing-vs-lifecycle root "+
			"cause question.")
	flagPerCallJSONL := flag.String("per-call-jsonl", "",
		"if set, write one JSON object per (request, call) into PATH (JSONL). "+
			"Drives the post-layer3 allowlist aggregation pipeline "+
			"(scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py). Schema is a strict "+
			"superset of the retired layer3 per-call jsonl (syscall / "+
			"syz_pcs_hex / ref_pcs_hex / raw_err_mismatch / real_err_mismatch) "+
			"plus session_id / req_id / call_idx / actionable_err_mismatch / "+
			"kcov_buffer_overflow / jaccard / cover_available")
	flagVmlinux := flag.String("vmlinux", "",
		"path to vmlinux for kernel symbol resolution. When set, the §13.6 "+
			"E measurement-artifact classifier (classifyProcessColdFault) "+
			"runs on every low-band sample: call#0 + ≥3× cov skew + ≥50 % "+
			"of larger side's unique PCs in the VM/page-fault/page-cache "+
			"family → bucket into coverage_process_cold_fault_count and "+
			"exclude from actionable_low_band. Absent → no classification "+
			"happens, low-band counted as-is (gate behavior unchanged from "+
			"pre-E).")
	flag.Parse()

	if *flagTraceDir == "" || *flagRefResult == "" || *flagOutput == "" {
		fmt.Fprintf(os.Stderr,
			"usage: %s -trace-dir <dir> -ref-result <ref_result.bin> -output <report.json> [-max-samples N] [-pc-dump-dir DIR] [-pc-dump-raw-dir DIR]\n",
			os.Args[0])
		os.Exit(2)
	}
	if *flagPCDumpDir != "" {
		if err := os.MkdirAll(*flagPCDumpDir, 0o755); err != nil {
			log.Fatalf("mkdir pc-dump-dir %s: %v", *flagPCDumpDir, err)
		}
	}
	if *flagPCDumpRawDir != "" {
		if err := os.MkdirAll(*flagPCDumpRawDir, 0o755); err != nil {
			log.Fatalf("mkdir pc-dump-raw-dir %s: %v", *flagPCDumpRawDir, err)
		}
	}
	forceDumpReqs := map[uint64]bool{}
	if *flagPCDumpForceReqs != "" {
		for _, tok := range strings.Split(*flagPCDumpForceReqs, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			v, err := strconv.ParseUint(tok, 10, 64)
			if err != nil {
				log.Fatalf("pc-dump-force-reqs: invalid token %q: %v", tok, err)
			}
			forceDumpReqs[v] = true
		}
	}

	// Step 1: enumerate trace files sorted by header.created_unix_ns.
	traceFiles, err := collectTraceFiles(*flagTraceDir)
	if err != nil {
		log.Fatalf("trace dir: %v", err)
	}
	if len(traceFiles) == 0 {
		log.Fatalf("no exec_trace_*.bin in %s", *flagTraceDir)
	}

	// Step 2: parse each trace file → session keyed by SyzSessionID.
	sessions := map[uint64]*session{}
	for _, tf := range traceFiles {
		sess := newSession(0, tf.Path, tf.CreatedNs)
		if err := readTraceFile(tf.Path, sess); err != nil {
			log.Printf("trace %s: %v (continuing)", filepath.Base(tf.Path), err)
			continue
		}
		if sess.SyzSessionID == 0 {
			log.Printf("trace %s: no session_open record; skipping", filepath.Base(tf.Path))
			continue
		}
		if existing, ok := sessions[sess.SyzSessionID]; ok {
			// Same session_id appearing twice would be weird (proxy uses unix_ns
			// + pid). Surface and skip the second.
			log.Printf("trace %s: duplicate session_id=%d (first=%s); skipping",
				filepath.Base(tf.Path), sess.SyzSessionID,
				filepath.Base(existing.TracePath))
			continue
		}
		sessions[sess.SyzSessionID] = sess
	}
	if len(sessions) == 0 {
		log.Fatalf("no usable sessions found in trace files")
	}

	// Step 3: walk ref_result.bin and dispatch into sessions.
	if err := readRefResult(*flagRefResult, sessions); err != nil {
		log.Fatalf("ref_result: %v", err)
	}

	// Step 4: stable order for report.
	ordered := make([]*session, 0, len(sessions))
	for _, s := range sessions {
		ordered = append(ordered, s)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].CreatedNs < ordered[j].CreatedNs })

	// §13.6 E: load vmlinux symbols once for measurement-artifact
	// classification. Without -vmlinux the classifier is a no-op (returns
	// false for everything); gate behavior matches pre-E.
	var kernelSyms *kernelSymbolTable
	if *flagVmlinux != "" {
		kernelSyms = &kernelSymbolTable{}
		if err := kernelSyms.LoadFromVmlinux(*flagVmlinux); err != nil {
			log.Printf("vmlinux load failed (%v); cold-fault classifier disabled", err)
			kernelSyms = nil
		} else {
			log.Printf("vmlinux loaded: %d kernel text symbols", len(kernelSyms.syms))
		}
	}

	// Step 5: comparator.
	perCall, err := newPerCallEmitter(*flagPerCallJSONL)
	if err != nil {
		log.Fatalf("per-call-jsonl: %v", err)
	}
	defer func() {
		if perCall != nil {
			if cerr := perCall.close(); cerr != nil {
				log.Printf("per-call-jsonl close: %v", cerr)
			}
			log.Printf("per-call-jsonl: wrote %d records to %s", perCall.cnt, *flagPerCallJSONL)
		}
	}()
	rep := compareSessions(ordered, *flagMaxSamples, *flagPCDumpDir, *flagPCDumpRawDir, forceDumpReqs, kernelSyms, perCall)

	// Step 5b (T1 diagnostic, no behavior change): emit mount-mismatch CSV
	// when -mount-mismatch-diag is set. Compare-time rep has already
	// classified samples; the diag walks the full sessions to get every
	// mount-image errno-divergent request with proc + timing context.
	if *flagMountMismatchDiag != "" {
		if err := writeMountMismatchDiag(*flagMountMismatchDiag, ordered); err != nil {
			log.Printf("mount-mismatch-diag: %v", err)
		}
	}

	// Step 6: emit report.
	out, err := os.Create(*flagOutput)
	if err != nil {
		log.Fatalf("open output: %v", err)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		out.Close()
		log.Fatalf("encode report: %v", err)
	}
	out.Close()

	fmt.Fprintf(os.Stderr,
		"refuzz_exec_oracle: sessions=%d total=%d compared=%d matched=%d "+
			"errno_mis=%d flag_mis=%d count_mis=%d syz_hang=%d ref_hang=%d "+
			"ref_only_fail=%d syz_only_fail=%d skip_unsupported=%d skip_missing_proc_id=%d "+
			"replay_holes=%d cold_fault=%d symtab=%v "+
			"raw_rate=%.3f comparable_rate=%.3f cov_avail_rate=%.3f jaccard=%d/%d both_empty=%d "+
			"gates=[wire:%v result:%v cov:%s(%v) overall:%v] report=%s\n",
		rep.SessionCount, rep.RequestTotal, rep.RequestCompared, rep.Matched,
		rep.ErrnoMismatch, rep.CallFlagMismatch, rep.CallCountMismatch,
		rep.SyzHanged, rep.RefHanged, rep.RefOnlyFail, rep.SyzOnlyFail,
		rep.RequestSkipUnsupported, rep.RequestSkipMissingProcId,
		rep.RequestSkipReplayHoles,
		rep.CoverageProcessColdFaultCount, rep.CoverageSymbolTableLoaded,
		rep.RawComparedRate, rep.ComparableRate,
		rep.ShipGatePassed.Coverage.CoverageAvailableRate,
		rep.KCovJaccardCount,
		// jaccard denominator = both-normal compared where syz had CollectCover.
		rep.BothNormalCount-rep.SyzCoverUnavailable,
		rep.KCovJaccardBothEmptyCount,
		rep.ShipGatePassed.Wire.Passed,
		rep.ShipGatePassed.Result.Passed,
		rep.ShipGatePassed.Coverage.Status,
		rep.ShipGatePassed.Coverage.Passed,
		rep.ShipGatePassed.Overall,
		*flagOutput)
}
