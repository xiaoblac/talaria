// Copyright 2026 reFuzz project author -------youngkk.
//
// [machine-check C4.6] The machine-check phase driver — the host-side capstone
// that ties C4.1-C4.4 together over reFuzz's STANDARD data plane:
//
//   EnvFeatures (guest) ──EnvFeaturesToSupportEnv──> SupportEnv
//   whitelist ─ probe candidates ─> HostFuzzTask ─push─> InMemoryTaskQueue
//                                          │ Executor submits + forwards
//                                          ▼
//   TrialResults <─DecodeProbeCompletion─ ChannelEvent <─pop─ InMemoryEventQueue
//                                          │
//   resolve_enabled_calls(whitelist ∩ supported(env,trials) ∩ transitive)
//                                          ▼
//                          MachineCheckResult{enabled mask, disabled report}
//
// The caller runs this AFTER the Executor service is up (channels booted, worker
// threads forwarding completions) but BEFORE the fuzz loop drains the event
// queue, then applies `enabled.mask` to the engine (RebuildChoiceTable) and logs
// `disabled`. It NEVER touches IChannel directly — submission is the same
// task_queue → Executor → event_queue path the fuzz loop uses. See
// docs/plans/machine-check.md.

#pragma once

#include "refuzz/control/support/support_checker.hpp"  // SupportEnv, DisabledCall, resolve_enabled_calls
#include "refuzz/program/syz/target.hpp"               // Target, EnabledCalls, SyscallMeta
#include "refuzz/proto_wire/env_features.h"            // ::EnvFeatures
#include "refuzz/queue/event_queue.hpp"                // InMemoryEventQueue
#include "refuzz/queue/task_queue.hpp"                 // InMemoryTaskQueue

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::control::support::machine_check {

namespace syz = ::refuzz::program::syz;

// Translate the guest wire facts (EnvFeatures POD) into the semantic SupportEnv
// the resolver consumes. `sandbox_is_none` is a host-config fact (not probed),
// so it's supplied separately; probed is set true (we have real probe data).
::refuzz::control::support::SupportEnv EnvFeaturesToSupportEnv(
    const ::EnvFeatures& ef, bool sandbox_is_none);

// Inputs to the machine-check phase.
struct MachineCheckConfig {
    std::vector<std::string>               enable;   // operator whitelist globs
    std::vector<std::string>               disable;  // operator blacklist globs
    ::refuzz::control::support::SupportEnv  env;      // static + probed facts
    std::uint32_t             timeout_ms       = 1000;  // per probe program
    // Executor-id base for probe tasks (nonzero; tagged so it can't collide with
    // fuzz-task ids, which start low and monotonic).
    std::uint64_t             base_executor_id = 0x4d43000000000000ull;  // 'MC'
    // NOTE: no overall drain timeout — the machine-check MUST fully complete
    // (every probe batch resolved) before fuzzing; RunMachineCheck drains until
    // pending == 0, relying on the channel's per-task terminal-event guarantee.
};

// Result of the machine-check phase.
struct MachineCheckResult {
    syz::EnabledCalls                         enabled;   // final mask (ok/error)
    std::vector<syz::DisabledCall>            disabled;  // report (canonical record)
    std::size_t probe_calls       = 0;   // syscalls trial-probed
    std::size_t probe_programs    = 0;   // batched programs submitted
    std::size_t programs_returned = 0;   // completions decoded (excl. timeouts)
    // [diagnostic] of the probed calls: how many actually executed in the guest
    // (kCallFlagExecuted), and of those how many returned ENOSYS. A low
    // `probe_executed` ⇒ batched probe programs terminate early (calls past an
    // exiting/faulting call never run → treated as "unknown" ⇒ kept).
    std::size_t probe_executed = 0;
    std::size_t probe_enosys   = 0;
    // [diagnostic] probe tags that did NOT execute (kCallFlagExecuted unset) —
    // these resolve to "no evidence ⇒ kept", the root of both the count gap vs
    // syz and the run-to-run variance. Sorted; the orchestrator logs a sample.
    std::vector<std::string> probe_not_executed;
};

// Run the machine-check over the standard data plane (see file header). Builds
// probe programs for the candidate syscalls, pushes them onto `task_queue`,
// drains `event_queue` matching by executor_id, decodes per-call errno into
// TrialResults, then resolves the final enabled set. Pure orchestration: holds
// no IChannel, spawns no threads — it relies on the already-running Executor to
// move tasks and forward completions.
MachineCheckResult RunMachineCheck(
    const syz::Target&                   target,
    const MachineCheckConfig&            cfg,
    ::refuzz::queue::InMemoryTaskQueue&  task_queue,
    ::refuzz::queue::InMemoryEventQueue& event_queue);

} // namespace refuzz::control::support::machine_check
