// Copyright 2026 reFuzz project author -------youngkk.
//
// [machine-check C4.2] Probe-program builder. Constructs a minimal program of
// one DEFAULT-arg call per syscall — like syzkaller's bare `read()`: args
// defaulted to zero/nil, just enough to reach the syscall so the kernel returns
// ENOSYS-or-not — and encodes it to the exec-wire payload the worker runs. The
// trial-exec runner (next step) submits these through the channel and reads back
// the per-call errno (`SyzExecResult.err`); `errno == ENOSYS ⇒ unsupported`.
//
// A program batches up to kProbeMaxCalls independent calls (one errno per call,
// in submission order: prog.calls()[i] ↔ the i-th meta passed in). See
// docs/plans/machine-check.md.

#pragma once

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace refuzz::control::support::machine_check {

namespace syz = ::refuzz::program::syz;

// Calls per probe program = 1, mirroring syz's machine-check: its default
// ENOSYS trial runs `supportedSyscalls([oneName])` → one bare call per program
// (pkg/vminfo/syscalls.go), NOT a batch. ONE call per program is what makes the
// check DETERMINISTIC: a blocking syscall (pause/poll/…) occupies only its own
// program — it can't mask batch-mates by holding a worker thread until the
// end-drain, which is exactly what produced reFuzz's run-to-run variance when
// probes were batched 40-wide. A lone blocked call deterministically reaches the
// end-drain → ENOSYS sentinel → disabled, just as syz disables it (its 1-call
// program hangs → ENOSYS). The InMemoryTaskQueue is unbounded and the channel
// paces submission, so the resulting ~hundreds of 1-call programs stream fine.
inline constexpr std::size_t kProbeMaxCalls = 1;

// Build a probe program: one default-arg call per non-null meta, preserving
// order (prog.calls()[i] ↔ the i-th non-null meta). The caller keeps the list
// length <= kProbeMaxCalls (split larger sets across programs).
syz::Prog BuildProbeProgram(const syz::Target&                          target,
                            const std::vector<const syz::SyscallMeta*>& calls);

// Finalize (assign_sizes) + serialize a probe program to the channel payload.
// nullopt if encoding fails (the batch is then unprobable; the caller may fall
// back to probing its calls one at a time).
std::optional<std::vector<std::uint8_t>> EncodeProbeProgram(syz::Prog& prog);

} // namespace refuzz::control::support::machine_check
