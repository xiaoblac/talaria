package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

type Config struct {
	Dial                string
	Trace               string
	SessionID           uint64
	VMIndex             uint32
	GitRev              string
	WriteDecodedSummary bool

	// COV-B.1: wire-level rewrite that ORs ExecFlagCollectCover into every
	// HostMessage→ExecRequest before forwarding. Breaks byte-equal capture
	// for ExecRequest frames; trace records both original_exec_flags and
	// forwarded exec_flags for audit. Other frame kinds unaffected.
	ForceCollectCover bool
}

// Frame size cap mirrors pkg/flatrpc/conn.go maxMessageSize. Anything larger
// is either an upstream schema change or a corrupted stream — fail hard.
const maxMessageSize = 64 << 20

const (
	dirH2E uint8 = 1 // host (syz-manager) → executor (runner)
	dirE2H uint8 = 2 // executor (runner) → host (syz-manager)
)

// RunWithListener runs the proxy on a caller-provided listener. main() uses
// this after net.Listen; tests use this to discover the bound address before
// the runner dials in.
func RunWithListener(ctx context.Context, ln net.Listener, cfg Config) error {
	tw, err := openTraceWriter(cfg.Trace, cfg.GitRev)
	if err != nil {
		return fmt.Errorf("open trace: %w", err)
	}
	defer tw.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	runnerConn, err := ln.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("accept: %w", err)
	}
	defer runnerConn.Close()

	mgrConn, err := net.Dial("tcp", cfg.Dial)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.Dial, err)
	}
	defer mgrConn.Close()

	if err := tw.WriteSessionOpen(cfg.SessionID, cfg.VMIndex,
		uint32(os.Getpid()), cfg.Dial); err != nil {
		return fmt.Errorf("session_open: %w", err)
	}

	var seq atomic.Uint64
	errc := make(chan error, 2)
	// Force-collect-cover rewrite only applies host→executor (ExecRequest is
	// host-emitted); executor→host frames are never mutated.
	go func() {
		errc <- forwardFrames(ctx, mgrConn, runnerConn, dirH2E,
			tw, &seq, cfg.WriteDecodedSummary, cfg.ForceCollectCover)
	}()
	go func() {
		errc <- forwardFrames(ctx, runnerConn, mgrConn, dirE2H,
			tw, &seq, cfg.WriteDecodedSummary, false)
	}()

	// First side to return tears down both — there's no half-open flatrpc
	// session worth keeping; both peers expect symmetric duplex.
	firstErr := <-errc
	runnerConn.Close()
	mgrConn.Close()
	<-errc

	reason := closeEOF
	msg := ""
	switch {
	case ctx.Err() != nil:
		reason = closeKilled
	case firstErr != nil && !errors.Is(firstErr, io.EOF) && !errors.Is(firstErr, net.ErrClosed):
		reason = closeError
		msg = firstErr.Error()
	}
	if err := tw.WriteSessionClose(reason, msg); err != nil {
		return fmt.Errorf("session_close: %w", err)
	}
	return tw.Flush()
}

// forwardFrames reads size-prefixed flatbuffer frames from src, writes them
// to dst (byte-equal unless forceCollectCover requested a HostMessage rewrite),
// and records each (raw frame + optional decoded summary) to the trace.
// Forwarding is the hot path; trace writes piggyback after the dst write so a
// slow disk doesn't stall the wire.
//
// forceCollectCover=true triggers COV-B.1 wire-level mutation on this side
// (only set for dirH2E by RunWithListener). Mutated ExecRequests have
// ExecFlagCollectCover OR-ed into exec_opts.exec_flags and are re-serialized;
// the trace records the FORWARDED bytes and tags the decoded_summary with
// `original_exec_flags` for audit. Non-ExecRequest frames pass through.
func forwardFrames(ctx context.Context, src io.Reader, dst io.Writer,
	dir uint8, tw *traceWriter, seq *atomic.Uint64, withSummary bool,
	forceCollectCover bool) error {
	var prefix [4]byte
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := io.ReadFull(src, prefix[:]); err != nil {
			return err
		}
		size := binary.LittleEndian.Uint32(prefix[:])
		if size > maxMessageSize {
			return fmt.Errorf("frame size %d exceeds %d", size, maxMessageSize)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(src, body); err != nil {
			return fmt.Errorf("read body size=%d: %w", size, err)
		}

		// COV-B.1: optional ExecRequest mutation. mutated=true means we
		// rewrote the body; forwardBody / forwardPrefix point at the new
		// bytes. Failure modes (parse error, no ExecOpts, etc.) fall through
		// to the byte-equal forward path silently — capture must not break
		// on schema drift, just degrade to non-force.
		forwardPrefix := prefix[:]
		forwardBody := body
		mutated := false
		var origExecFlags uint64
		var extras map[string]any
		if forceCollectCover && dir == dirH2E {
			newBody, prevFlags, isReq, didMutate, _ := mutateForceCollectCover(body)
			if didMutate {
				forwardBody = newBody
				var newPrefix [4]byte
				binary.LittleEndian.PutUint32(newPrefix[:], uint32(len(newBody)))
				forwardPrefix = newPrefix[:]
				mutated = true
				origExecFlags = prevFlags
				extras = map[string]any{
					"original_exec_flags": origExecFlags,
					"forced_collect_cover": true,
				}
			} else if isReq {
				// ExecRequest that already had CollectCover (or no ExecOpts).
				// Tag the trace so downstream can tell "force-mode was on
				// but this one didn't need rewrite" apart from "force-mode
				// off."
				extras = map[string]any{
					"original_exec_flags": prevFlags,
					"forced_collect_cover": false,
				}
			}
		}

		if _, err := dst.Write(forwardPrefix); err != nil {
			return fmt.Errorf("forward prefix: %w", err)
		}
		if _, err := dst.Write(forwardBody); err != nil {
			return fmt.Errorf("forward body: %w", err)
		}
		s := seq.Add(1) - 1
		ts := time.Now().UnixNano()
		if err := tw.WriteFrame(dir, s, ts, forwardPrefix, forwardBody); err != nil {
			return fmt.Errorf("trace frame: %w", err)
		}
		if withSummary {
			if mutated || extras != nil {
				if err := tw.WriteDecodedSummaryWithExtras(dir, s, ts, forwardBody, extras); err != nil {
					return fmt.Errorf("trace summary: %w", err)
				}
			} else {
				if err := tw.WriteDecodedSummary(dir, s, ts, forwardBody); err != nil {
					return fmt.Errorf("trace summary: %w", err)
				}
			}
		}
	}
}
