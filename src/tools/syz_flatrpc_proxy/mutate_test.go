package main

import (
	"encoding/binary"
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// packHostExecRequest builds a raw flatrpc HostMessage(ExecRequest) body
// (no size prefix) with the given exec_flags + env_flags, mirroring what
// syz-manager would put on the wire. Used by the mutator round-trip tests.
func packHostExecRequest(execFlags flatrpc.ExecFlag, envFlags ...flatrpc.ExecEnv) []byte {
	env := flatrpc.ExecEnvSandboxNone
	for _, e := range envFlags {
		env |= e
	}
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:   1,
				Type: flatrpc.RequestTypeProgram,
				Data: []byte("dummy"),
				ExecOpts: &flatrpc.ExecOpts{
					EnvFlags:  env,
					ExecFlags: execFlags,
				},
				AllSignal: []int32{},
			},
		},
	}
	b := flatbuffers.NewBuilder(0)
	off := msg.Pack(b)
	b.FinishSizePrefixed(off)
	full := b.FinishedBytes()
	// Strip the 4-byte size prefix to match the body shape the proxy hands
	// to mutateForceCollectCover.
	return full[4:]
}

// Empty original ExecFlags + production-faithful EnvFlags (only SandboxNone)
// is the canonical fresh-exec wire shape. Real B.6 capture showed these
// need ALL THREE bits added: ExecFlags{Signal, Cover} AND EnvFlags{Signal}.
// Without env Signal, executor's session-level flag_coverage stays false
// and per-request CollectCover is suppressed wholesale.
func TestMutateForceCollectCover_AddsAllThreeBitsFromEmpty(t *testing.T) {
	body := packHostExecRequest(0) // default env = SandboxNone, no Signal
	newBody, orig, isReq, mutated, parseOK := mutateForceCollectCover(body)
	if !parseOK || !isReq || !mutated {
		t.Fatalf("expected parseOK/isReq/mutated all true, got %v/%v/%v", parseOK, isReq, mutated)
	}
	if orig != 0 {
		t.Errorf("orig exec_flags = %#x, want 0", orig)
	}
	msg, err := flatrpc.Parse[*flatrpc.HostMessageRaw](newBody)
	if err != nil || msg == nil {
		t.Fatalf("re-parse of mutated body failed: %v", err)
	}
	req := msg.Msg.Value.(*flatrpc.ExecRequest)
	wantExec := flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	if req.ExecOpts.ExecFlags != wantExec {
		t.Errorf("post-mutation exec_flags = %#x, want %#x = Signal|Cover",
			uint64(req.ExecOpts.ExecFlags), uint64(wantExec))
	}
	// EnvFlags must now also carry ExecEnvSignal (in addition to SandboxNone).
	if req.ExecOpts.EnvFlags&flatrpc.ExecEnvSignal == 0 {
		t.Errorf("post-mutation env_flags = %#x, missing ExecEnvSignal",
			uint64(req.ExecOpts.EnvFlags))
	}
	if req.ExecOpts.EnvFlags&flatrpc.ExecEnvSandboxNone == 0 {
		t.Errorf("post-mutation env_flags = %#x lost SandboxNone bit",
			uint64(req.ExecOpts.EnvFlags))
	}
	if req.Id != 1 || string(req.Data) != "dummy" {
		t.Errorf("payload not round-tripped: id=%d data=%q", req.Id, req.Data)
	}
}

// ExecFlags only — env still missing Signal. Should still mutate (env side).
func TestMutateForceCollectCover_EnvSignalAlsoFlippedWhenExecAlready(t *testing.T) {
	body := packHostExecRequest(flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover)
	newBody, _, _, mutated, _ := mutateForceCollectCover(body)
	if !mutated {
		t.Fatal("must mutate when EnvSignal is missing even if ExecFlags satisfy")
	}
	msg, _ := flatrpc.Parse[*flatrpc.HostMessageRaw](newBody)
	req := msg.Msg.Value.(*flatrpc.ExecRequest)
	if req.ExecOpts.EnvFlags&flatrpc.ExecEnvSignal == 0 {
		t.Errorf("env_flags should now carry ExecEnvSignal")
	}
}

// All three bits already on → no-op.
func TestMutateForceCollectCover_AllAlreadySet(t *testing.T) {
	body := packHostExecRequest(
		flatrpc.ExecFlagCollectSignal|flatrpc.ExecFlagCollectCover,
		flatrpc.ExecEnvSignal)
	newBody, _, isReq, mutated, parseOK := mutateForceCollectCover(body)
	if !parseOK || !isReq {
		t.Fatalf("expected parseOK + isReq")
	}
	if mutated {
		t.Errorf("should not mutate when all required bits already set")
	}
	if newBody != nil {
		t.Errorf("newBody must be nil when mutated=false")
	}
}

func TestMutateForceCollectCover_NonExecRequest(t *testing.T) {
	// SignalUpdate is also a HostMessage but not ExecRequest — mutator
	// should report parseOK=true, isReq=false, mutated=false.
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawSignalUpdate,
			Value: &flatrpc.SignalUpdate{},
		},
	}
	b := flatbuffers.NewBuilder(0)
	off := msg.Pack(b)
	b.FinishSizePrefixed(off)
	body := b.FinishedBytes()[4:]
	newBody, _, isReq, mutated, parseOK := mutateForceCollectCover(body)
	if !parseOK {
		t.Fatalf("SignalUpdate should parse cleanly")
	}
	if isReq || mutated || newBody != nil {
		t.Errorf("SignalUpdate must be left alone: isReq=%v mutated=%v newBody=%v",
			isReq, mutated, newBody != nil)
	}
}

func TestMutateForceCollectCover_GarbageBody(t *testing.T) {
	// Random bytes should be soft-rejected (parseOK=false), never panic.
	garbage := []byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1, 2, 3}
	_, _, _, mutated, parseOK := mutateForceCollectCover(garbage)
	if parseOK {
		t.Errorf("garbage should not parse OK")
	}
	if mutated {
		t.Errorf("garbage must never report mutated=true")
	}
}

// Round-trip new size prefix: the proxy writes a fresh size prefix matching
// len(new body); make sure that size really matches what Parse will accept
// (catches a regression where FinishedBytes is mistakenly used wholesale).
func TestMutateForceCollectCover_NewSizeRoundTrip(t *testing.T) {
	body := packHostExecRequest(flatrpc.ExecFlagCollectSignal)
	newBody, _, _, mutated, _ := mutateForceCollectCover(body)
	if !mutated {
		t.Fatal("setup expected mutation")
	}
	// Build a size-prefixed wire frame and parse it via flatrpc.Parse to
	// confirm it's a valid flatbuffer with the expected size prefix.
	wire := make([]byte, 4+len(newBody))
	binary.LittleEndian.PutUint32(wire[:4], uint32(len(newBody)))
	copy(wire[4:], newBody)
	if got := int(binary.LittleEndian.Uint32(wire[:4])); got != len(newBody) {
		t.Fatalf("size prefix sanity: %d != %d", got, len(newBody))
	}
	if _, err := flatrpc.Parse[*flatrpc.HostMessageRaw](newBody); err != nil {
		t.Fatalf("post-mutation body fails Parse: %v", err)
	}
}
