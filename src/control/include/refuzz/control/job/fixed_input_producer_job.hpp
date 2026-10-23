#pragma once
// [fixed request stream, Step 4] docs/plans/fixed-request-stream-performance-replay.md
//
// FixedInputProducerJob feeds a pre-validated request stream, strictly in
// sequence order, through the SAME producer contract ExploreJob uses
// (ctx.emit() -> JobScheduler request window -> InMemoryTaskQueue). It is not
// a new entry point into the pipeline; it is the fixed-workload replacement
// for ExploreJob's gen/mut supply, so everything downstream (dispatcher,
// Channel, worker, FuzzerLoop feedback) stays the native path.
//
// Unlike ExploreJob it does NOT self-respawn: it drains the stream exactly
// once, then calls on_fully_drained after every emitted request's completion
// has been observed (via emit's on_completed) -- the stream is meant to be
// the run's only task source (plan §6.2), not a recurring producer.

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/control/request_stream_reader.hpp"

#include <cstdint>
#include <functional>

namespace refuzz::control {

struct FixedInputProducerJobDeps {
    // Owned by the caller (Orchestrator) for the whole run; must outlive the job.
    const refuzz::request_stream::RequestStream* stream = nullptr;
    // reFuzz's own configured exec timeout -- the plan's record schema carries
    // no per-record timeout (see plan §4.2), so this stays reFuzz-native.
    std::uint32_t exec_timeout_ms = 0;
    // Invoked at most once, on the control thread, once every record has been
    // emitted AND every emitted request's completion has been observed.
    std::function<void()> on_fully_drained;
};

// Builds the producer job (returns JobFn for FuzzerLoop::SpawnFixedInputProducerJob).
job::JobFn MakeFixedInputProducerJob(FixedInputProducerJobDeps deps);

}  // namespace refuzz::control
