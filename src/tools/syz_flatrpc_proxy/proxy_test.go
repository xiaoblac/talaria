package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// TestProxyRoundTrip wires a fake syz-manager and a fake syz-executor runner
// across the proxy without any VM / real executor. It validates:
//   - byte-equal forwarding of one HostMessage(ExecRequest) and one
//     ExecutorMessage(ExecResult) across the proxy
//   - trace contains valid header, session_open, frame_h2e, frame_e2h,
//     decoded_summary {ExecRequest, ExecResult}, and session_close records
//
// This is the PR1 acceptance smoke: no VM, no real syz-executor, no
// real syz-manager.
func TestProxyRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	tracePath := filepath.Join(tmpDir, "trace.bin")

	// Fake syz-manager (upstream end of the proxy).
	mgrLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("manager listen: %v", err)
	}
	defer mgrLn.Close()

	mgrDone := make(chan error, 1)
	go func() {
		conn, err := mgrLn.Accept()
		if err != nil {
			mgrDone <- err
			return
		}
		defer conn.Close()
		c := flatrpc.NewConn(conn)
		req, err := flatrpc.Recv[*flatrpc.HostMessageRaw](c)
		if err != nil {
			mgrDone <- err
			return
		}
		execReq, ok := req.Msg.Value.(*flatrpc.ExecRequest)
		if !ok {
			mgrDone <- errors.New("manager: expected ExecRequest")
			return
		}
		reply := &flatrpc.ExecutorMessage{
			Msg: &flatrpc.ExecutorMessages{
				Type: flatrpc.ExecutorMessagesRawExecResult,
				Value: &flatrpc.ExecResult{
					Id:   execReq.Id,
					Proc: 0,
					Info: &flatrpc.ProgInfo{
						Freshness: 0,
						Calls: []*flatrpc.CallInfo{
							{
								Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished,
								Error: 0,
							},
						},
					},
				},
			},
		}
		if err := flatrpc.Send(c, reply); err != nil {
			mgrDone <- err
			return
		}
		// Hold the connection open until the runner side disconnects so the
		// proxy's mgr→runner reader doesn't see EOF too early.
		var one [1]byte
		_, _ = conn.Read(one[:])
		mgrDone <- nil
	}()

	// Proxy listener — caller-owned so we can read the bound address
	// before any client dials in. Run() handles Close().
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- RunWithListener(ctx, proxyLn, Config{
			Dial:                mgrLn.Addr().String(),
			Trace:               tracePath,
			SessionID:           7,
			VMIndex:             3,
			GitRev:              "deadbeefcafebabe00112233445566778899aabb",
			WriteDecodedSummary: true,
		})
	}()

	// Fake runner.
	runnerConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("runner dial: %v", err)
	}
	rc := flatrpc.NewConn(runnerConn)
	send := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:   42,
				Type: flatrpc.RequestTypeProgram,
				Data: []byte("dummy-syz-wire-bytes"),
				ExecOpts: &flatrpc.ExecOpts{
					EnvFlags:  flatrpc.ExecEnvSandboxNone,
					ExecFlags: flatrpc.ExecFlagCollectSignal,
				},
				AllSignal: []int32{},
			},
		},
	}
	if err := flatrpc.Send(rc, send); err != nil {
		t.Fatalf("runner send: %v", err)
	}
	reply, err := flatrpc.Recv[*flatrpc.ExecutorMessageRaw](rc)
	if err != nil {
		t.Fatalf("runner recv: %v", err)
	}
	res, ok := reply.Msg.Value.(*flatrpc.ExecResult)
	if !ok {
		t.Fatalf("runner got non-ExecResult: %T", reply.Msg.Value)
	}
	if res.Id != 42 {
		t.Fatalf("got id=%d want 42", res.Id)
	}
	if len(res.Info.Calls) != 1 {
		t.Fatalf("got %d calls want 1", len(res.Info.Calls))
	}

	// Tear down: close runner side first, manager goroutine then sees EOF.
	runnerConn.Close()

	select {
	case err := <-mgrDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("manager: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("manager goroutine did not return")
	}
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Errorf("proxy: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("proxy did not return")
	}

	// Walk the trace and verify expected records exist.
	data, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}
	if len(data) < traceHeaderLen {
		t.Fatalf("trace too short: %d bytes", len(data))
	}
	if string(data[0:8]) != traceMagic {
		t.Fatalf("bad magic: %q", data[0:8])
	}
	if v := binary.LittleEndian.Uint32(data[8:12]); v != traceVersion {
		t.Fatalf("bad version: %d", v)
	}

	off := traceHeaderLen
	var sawOpen, sawClose, sawH2E, sawE2H bool
	summariesByKind := map[uint8]int{}
	for off < len(data) {
		if off+4 > len(data) {
			t.Fatalf("truncated record header at off=%d", off)
		}
		recSize := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		if int(recSize) < 17 || off+int(recSize) > len(data) {
			t.Fatalf("bogus rec_size=%d at off=%d (file=%d)", recSize, off-4, len(data))
		}
		rec := data[off]
		off++
		off += 16 // seq + ts
		bodyLen := int(recSize) - 17
		body := data[off : off+bodyLen]
		off += bodyLen
		switch rec {
		case recSessionOpen:
			sawOpen = true
			if got := binary.LittleEndian.Uint64(body[0:8]); got != 7 {
				t.Errorf("session_id=%d want 7", got)
			}
		case recFrameH2E:
			sawH2E = true
			sz := binary.LittleEndian.Uint32(body[0:4])
			if int(sz)+4 != len(body) {
				t.Errorf("h2e inner size %d vs body %d", sz, len(body))
			}
		case recFrameE2H:
			sawE2H = true
		case recSessionClose:
			sawClose = true
		case recDecodedSummary:
			kind := body[1]
			jsonLen := binary.LittleEndian.Uint16(body[2:4])
			if int(jsonLen)+4 != len(body) {
				t.Errorf("summary json_len %d vs body %d", jsonLen, len(body))
			}
			var v any
			if jsonLen > 0 {
				if err := json.Unmarshal(body[4:4+int(jsonLen)], &v); err != nil {
					t.Errorf("summary kind=%d json: %v", kind, err)
				}
			}
			summariesByKind[kind]++
		}
	}
	if !sawOpen || !sawClose || !sawH2E || !sawE2H {
		t.Errorf("missing records: open=%v close=%v h2e=%v e2h=%v",
			sawOpen, sawClose, sawH2E, sawE2H)
	}
	if summariesByKind[kindExecRequest] == 0 {
		t.Errorf("no decoded_summary kind=ExecRequest")
	}
	if summariesByKind[kindExecResult] == 0 {
		t.Errorf("no decoded_summary kind=ExecResult")
	}
}
