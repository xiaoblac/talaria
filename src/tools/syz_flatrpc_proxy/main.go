// syz_flatrpc_proxy — V2 production-exec paired oracle PR1.
// Frame-aware transparent TCP proxy between syz-manager (host) and
// syz-executor runner (VM). Forwards bytes byte-equal and writes a
// side trace consumable by refuzz_exec_replayer / refuzz_exec_oracle.
//
// See docs/plans/production-exec-paired-oracle.md (§4, §5).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		listen    = flag.String("listen", "127.0.0.1:0", "TCP address to accept the VM-side syz-executor runner")
		dial      = flag.String("dial", "", "TCP address of the real syz-manager rpcserver (required)")
		trace     = flag.String("trace", "", "trace file output path (required)")
		sessionID = flag.Uint64("session-id", 0, "session id recorded in trace session_open")
		vmIndex   = flag.Uint("vm-index", 0, "vm index recorded in trace session_open")
		gitRev    = flag.String("syzkaller-git-rev", "", "syzkaller git revision (trace header; truncated/padded to 40 chars)")
		summary   = flag.Bool("decoded-summary", true, "emit per-frame decoded summary records (type 0x10)")
	)
	flag.Parse()
	if *dial == "" || *trace == "" {
		log.Fatalf("syz_flatrpc_proxy: -dial and -trace are required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("syz_flatrpc_proxy: listen %s: %v", *listen, err)
	}
	fmt.Fprintf(os.Stderr, "syz_flatrpc_proxy: listen=%s forward=%s trace=%s\n",
		ln.Addr(), *dial, *trace)

	// COV-B.1: opt-in CollectCover forcing. Env knob (not CLI) so capture
	// orchestrators (scripts/pc_compare/exec_oracle_smoke.sh) can flip it without
	// re-plumbing flags through the VM-side wrapper. Any non-empty value
	// other than "0" / "false" / "off" enables.
	forceCover := false
	switch v := os.Getenv("REFUZZ_FORCE_COLLECT_COVER"); v {
	case "", "0", "false", "off", "no":
		forceCover = false
	default:
		_ = v
		forceCover = true
		fmt.Fprintf(os.Stderr, "syz_flatrpc_proxy: REFUZZ_FORCE_COLLECT_COVER=on — wire-level rewrite enabled (COV-B)\n")
	}

	cfg := Config{
		Dial:                *dial,
		Trace:               *trace,
		SessionID:           *sessionID,
		VMIndex:             uint32(*vmIndex),
		GitRev:              *gitRev,
		WriteDecodedSummary: *summary,
		ForceCollectCover:   forceCover,
	}
	if err := RunWithListener(ctx, ln, cfg); err != nil {
		log.Fatalf("syz_flatrpc_proxy: %v", err)
	}
}
