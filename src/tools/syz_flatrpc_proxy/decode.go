package main

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// Decoded summary kinds. Raw frame is preserved separately, so decode
// failure is a soft failure (kindParseError) — downstream tools can still
// re-parse the raw frame with a future schema.
const (
	kindNone          uint8 = 0
	kindExecRequest   uint8 = 1
	kindExecuting     uint8 = 2
	kindExecResult    uint8 = 3
	kindSignalUpdate  uint8 = 4
	kindCorpusTriaged uint8 = 5
	kindStateRequest  uint8 = 6
	kindStateResult   uint8 = 7
	kindParseError    uint8 = 0xFF
)

func decodeFrame(dir uint8, body []byte) (kind uint8, summary []byte) {
	defer func() {
		if r := recover(); r != nil {
			kind = kindParseError
			summary = nil
		}
	}()
	if dir == dirH2E {
		return decodeHostMessage(body)
	}
	return decodeExecutorMessage(body)
}

func decodeHostMessage(body []byte) (uint8, []byte) {
	msg, err := flatrpc.Parse[*flatrpc.HostMessageRaw](body)
	if err != nil || msg == nil || msg.Msg == nil {
		return kindParseError, nil
	}
	switch v := msg.Msg.Value.(type) {
	case *flatrpc.ExecRequest:
		return kindExecRequest, marshalJSON(execRequestSummary(v))
	case *flatrpc.SignalUpdate:
		return kindSignalUpdate, marshalJSON(map[string]any{
			"new_max_len": len(v.NewMax),
		})
	case *flatrpc.CorpusTriaged:
		return kindCorpusTriaged, []byte("{}")
	case *flatrpc.StateRequest:
		return kindStateRequest, []byte("{}")
	}
	return kindNone, nil
}

func decodeExecutorMessage(body []byte) (uint8, []byte) {
	msg, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](body)
	if err != nil || msg == nil || msg.Msg == nil {
		return kindParseError, nil
	}
	switch v := msg.Msg.Value.(type) {
	case *flatrpc.ExecResult:
		return kindExecResult, marshalJSON(execResultSummary(v))
	case *flatrpc.ExecutingMessage:
		return kindExecuting, marshalJSON(map[string]any{
			"id":            v.Id,
			"proc_id":       v.ProcId,
			"try":           v.Try,
			"wait_duration": v.WaitDuration,
		})
	case *flatrpc.StateResult:
		return kindStateResult, marshalJSON(map[string]any{
			"data_len": len(v.Data),
		})
	}
	return kindNone, nil
}

func execRequestSummary(r *flatrpc.ExecRequest) map[string]any {
	out := map[string]any{
		"id":             r.Id,
		"type":           uint64(r.Type),
		"data_len":       len(r.Data),
		"flags":          uint64(r.Flags),
		"avoid":          r.Avoid,
		"all_signal_len": len(r.AllSignal),
	}
	if r.ExecOpts != nil {
		out["env_flags"] = uint64(r.ExecOpts.EnvFlags)
		out["exec_flags"] = uint64(r.ExecOpts.ExecFlags)
		out["sandbox_arg"] = r.ExecOpts.SandboxArg
	}
	return out
}

func execResultSummary(r *flatrpc.ExecResult) map[string]any {
	out := map[string]any{
		"id":         r.Id,
		"proc":       r.Proc,
		"hanged":     r.Hanged,
		"error":      r.Error,
		"output_len": len(r.Output),
	}
	if r.Info != nil {
		out["freshness"] = r.Info.Freshness
		out["elapsed"] = r.Info.Elapsed
		calls := make([]map[string]any, 0, len(r.Info.Calls))
		for _, c := range r.Info.Calls {
			calls = append(calls, map[string]any{
				"flags":      uint64(c.Flags),
				"error":      c.Error,
				"signal_len": len(c.Signal),
				"cover_len":  len(c.Cover),
				"comps_len":  len(c.Comps),
			})
		}
		out["calls"] = calls
	}
	return out
}

func marshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
