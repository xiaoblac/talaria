// Exec wire encoder — port of prog/encodingexec.go.
//
// Serializes a Prog into the syzkaller-executor wire format: a uint64
// stream encoded as Go-style zig-zag varints (binary.AppendVarint), with
// special instruction codes (Copyin/Copyout/SetProps/EOF), arg type
// codes (Const/Addr32/Addr64/Result/Data/Csum), and inline binary blobs
// for DataArg payloads.
//
// Output is byte-equal to syzkaller `prog.Prog.SerializeForExec` for any
// non-KFuzzTest program the C++ TextDecoder accepts. The reFuzz worker
// (§3.3) consumes this wire format directly, so structural equivalence
// with the upstream executor wire is what enables a worker swap without
// mutator/codec changes.
//
// Errors are returned via std::expected; the only failure modes mirror
// the upstream ones: oversized buffer (>4MiB) and excessive copyout
// records (>1000). KFuzzTest calls (`Attrs.kfuzztest`) currently report
// an error because the kfuzztest path needs a separate marshalling layer
// not yet ported.

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace refuzz::program::syz {

constexpr std::size_t kExecBufferSize  = 4 * 1024 * 1024;
constexpr std::size_t kExecMaxCommands = 1000;
constexpr uint64_t    kExecNoCopyout   = ~uint64_t{0};

struct ExecError {
    std::string message;
};

// Returns a wire-encoded byte buffer or an ExecError. Does not mutate
// the program (KFuzzTest support, when added, will require a const-cast
// or a mutable variant — not exposed yet).
std::expected<std::vector<uint8_t>, ExecError> serialize_for_exec(const Prog& prog);

} // namespace refuzz::program::syz
