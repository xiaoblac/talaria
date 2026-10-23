#pragma once

#include "refuzz/proto_domain/fault_event.hpp"
#include "refuzz/proto_domain/frozen_program_entry.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

// post-V1-retirement — artifact-first universal contract.
// Forward-decl to keep proto_domain header-only and free of refuzz_program
// link dependencies. Consumers that dereference the artifact must include
// "refuzz/program/artifact.hpp" themselves.
namespace refuzz::program { class ProgramArtifact; }

namespace refuzz::proto {

struct CombinedCrashEvent {
    uint64_t incident_id = 0;
    std::optional<FaultEvent> fault_event;
    std::optional<FrozenProgramEntry> crash_program;
    std::vector<FrozenProgramEntry> history;

    // [v2 PR-B console snapshot universal slot — 当前版本]
    // 跨 fault 与 abnormal 两条 path 的统一 console 文本载体:
    //   - fault path: BuildCombinedFromFault 把 FaultEvent.crash_console
    //     同时写到这里,保持兼容(现有 BuildContextOp 第一分支仍读 fault_event.crash_console)。
    //   - abnormal path: BuildCombinedFromAbnormal 把 AbnormalCompletion.console_snapshot
    //     写到这里(abnormal 不构造 fault_event,所以 fault_event.crash_console 不可用)。
    // BuildContextOp 第二分支(else if crash_program/completion)从这里灌 console_log,
    // 修复 abnormal 路径下 [console] block / serial_log_tail 全丢的问题。
    std::optional<std::string> console_snapshot;

    // post-V1-retirement artifact-first universal contract:
    //   The authoritative typed view of the program responsible for this
    //   incident. Populated by feedback/src/signal/fault_signal.cpp from
    //   the channel CompletionContext::artifact (Abnormal path). The Fault
    //   path is opaque to channeldispatcher's submit→completion pairing
    //   today, so it leaves this null and downstream repro_manager
    //   StageMinimize fails closed (`ctx.origin_artifact == nullptr`).
    //   Replaces the deleted "reverse-decode bytes → typed Prog" production
    //   path (D-1) — see docs/syzkaller-parity-review/post_v1_retirement_followups.md.
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> crash_origin_artifact;
};

} // namespace refuzz::proto
