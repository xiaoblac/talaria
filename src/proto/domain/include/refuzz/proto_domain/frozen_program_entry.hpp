#pragma once

#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace refuzz::program { class ProgramArtifact; }

namespace refuzz::proto {

struct FrozenExecutionSummary {
    uint32_t worker_id = 0;
    ResultCode result_code = ResultCode::kOk;
    InfraError infra_error = InfraError::kNone;
    uint64_t start_ts_us = 0;
    uint64_t finish_ts_us = 0;
    uint32_t crash_signal = 0;
    // [XiUOS leak 一等公民化 Phase 1] dedicated leak-magnitude carrier (net heap
    // bytes / resource residue not reclaimed by the program's own cleanup). This
    // is the proper home for the XiUOS leak delta — it used to be misplaced into
    // crash_signal, conflating a leak with a worker signal. crash_signal stays 0
    // for leaks. See docs/plans/xiuos-leak-componentization.md.
    uint32_t leak_bytes = 0;
    // [XiUOS leak 一等公民化 Phase 5] resource-residue carrier (waitq|victim<<8|delay<<16),
    // parallel to leak_bytes (heap delta). A kResourceLeak finding may carry both
    // (heap leak AND resource residue). 0 = none. See docs/plans/xiuos-leak-componentization.md.
    uint32_t resource_residue = 0;
    std::vector<uint8_t> output;
    std::vector<uint64_t> coverage_hashes;
};

struct FrozenProgramEntry {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    std::vector<uint8_t> program_payload;
    uint64_t submit_ts_us = 0;
    std::optional<FrozenExecutionSummary> completion;
    // [async-crash-reproduction Phase 1] typed view of this program, carried from
    // the channeldispatcher's (in-flight | recent) artifact map so a history /
    // bisect / concat extract can be minimized (StageMinimize needs the typed
    // ProgramArtifact, not just exec-wire bytes). Null when unavailable.
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
};

} // namespace refuzz::proto
