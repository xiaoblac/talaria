// Brick 4a — dedicated snapshot worker loop (syz snapshot.h execution model).
//
// Single process, no daemon/loop_child split, NO per-program fork: do all
// expensive setup ONCE (so the S0 snapshot captures a fully-warm worker), then
// spin-wait on the ivshmem TaskSlot (no sleep, so S0 is a clean poll point and
// loadvm resumes straight into the poll), run each program IN-PLACE via
// ChildExecuteTask (KCOV collected in-process), and write CompletionSlot. loadvm
// provides crash isolation + per-program state reset, so the continuous worker's
// per-program fork / SetupTest re-mount / workdir churn are all dropped.
//
// See docs/plans/snapshot-brick4a-worker.md.

#pragma once

#include "worker/adapter/worker_task_channel.hpp"
#include "worker/backend/exec_backend.hpp"
#include "worker/engine/execution_domain_registry.hpp"
#include "worker/engine/execution_engine.hpp"  // EngineConfig
#include "worker/observation/observation_bus.hpp"

namespace refuzz::worker {

// Runs the snapshot execution loop after RunWorkerProfile has registered the
// daemon. Does the one-time domain setup, publishes READY, then loops
// {spin-wait TaskSlot -> ChildExecuteTask in-place -> ReportDone} until
// g_running clears. Returns a process exit code.
int RunSnapshotEngine(IWorkerTaskChannel& task_channel,
                      IExecutionDomainRegistry& domain_registry,
                      IExecBackend& backend,
                      IObservationBus& bus,
                      const EngineConfig& cfg);

}  // namespace refuzz::worker
