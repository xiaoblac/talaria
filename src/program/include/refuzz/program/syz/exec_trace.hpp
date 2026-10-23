// Layer-3 trace-equivalence schema.
//
// Both the Go reference dumper (tools/syzgen exec-trace-dump) and the
// C++ wire-driven dumper (tools/refuzz_syz_v2_exec_trace) emit JSONL in
// this exact format. One program per line:
//
//   {"file":"<basename>",
//    "calls":[{"nr":<u64>, "args":[<arg-tag>, ...]}, ...]}
//
// Argument tags (mirror prog/encodingexec.go writeArg dispatch — what
// the wire actually emits per call arg):
//   {"k":"C","sz":N,"v":N,"f":N,"bo":N,"bl":N,"ps":N}
//       ConstArg, or ResultArg with nil Res (which the encoder lowers
//       to writeConstArg). val is post-pid-stride-add but pre-pid
//       (i.e. ProcType emits ValuesStart+Val with ps=ValuesPerProc).
//   {"k":"R","sz":N,"f":N,"d":N,"a":N,"def":N}
//       ResultArg with Res != nil. Wire emits (size, fmt, idx, op_div,
//       op_add, default). Idx is omitted from the trace because it is
//       sequence-assigned by SerializeForExec and any divergence would
//       already manifest as a §3.2 byte-equal failure.
//   {"k":"P","sz":4|8,"o":N}
//       PointerArg. o = physical_addr - data_offset, same on both sides.
//   {"k":"D","h":"<hex>","r":bool}
//       DataArg as a top-level call arg.
//   UnionArg is transparent — both sides recurse into Option, so the
//   trace emits the option's tag directly.
//
// The schema is intentionally minimal so that two independent
// information sources (Go IR walk vs C++ wire walk) produce
// byte-identical JSONL on a passing program. Acceptance for
// Layer-3 milestone I is 821/821 byte-equal on the L3 filtered corpus.

#pragma once

namespace refuzz::program::syz::exec_trace {

// Tag string constants — keep in sync between Go and C++ emitters.
inline constexpr const char* kTagConst   = "C";
inline constexpr const char* kTagResult  = "R";
inline constexpr const char* kTagPointer = "P";
inline constexpr const char* kTagData    = "D";

// Field key constants.
inline constexpr const char* kFieldFile      = "file";
inline constexpr const char* kFieldCalls     = "calls";
inline constexpr const char* kFieldNR        = "nr";
inline constexpr const char* kFieldArgs      = "args";
inline constexpr const char* kFieldKind      = "k";
inline constexpr const char* kFieldSize      = "sz";
inline constexpr const char* kFieldVal       = "v";
inline constexpr const char* kFieldFormat    = "f";
inline constexpr const char* kFieldBfOff     = "bo";
inline constexpr const char* kFieldBfLen     = "bl";
inline constexpr const char* kFieldPidStride = "ps";
inline constexpr const char* kFieldOpDiv     = "d";
inline constexpr const char* kFieldOpAdd     = "a";
inline constexpr const char* kFieldDefault   = "def";
inline constexpr const char* kFieldOffset    = "o";
inline constexpr const char* kFieldHex       = "h";
inline constexpr const char* kFieldReadable  = "r";

} // namespace refuzz::program::syz::exec_trace
