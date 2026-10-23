// ExecutionEngine is a compatibility facade plus the per-program dispatch
// helper. DomainSupervisor owns the daemon lifecycle state machine.
//
// P1 重构:把 child 生命周期(fork/notify/wait/kill/respawn)+ child 内主循环
// 从本文件拆出到独立模块:
//   - worker/topology/reusable_child_topology.{hpp,cpp}
//       原 ForkChild/NotifyChild/WaitChild/KillChild/RespawnChild 整段搬过去
//   - worker/engine/loop_runtime.{hpp,cpp}
//       原 ChildMain 主体(fd ABI / sandbox / read-dispatch-write loop)搬过去
//   - worker/engine/program_runtime.{hpp,cpp}
//       原 crash handler globals + install_engine_child_crash_handlers +
//       "一条 prog 执行"(包装 ChildExecuteTask)搬过去
//
// 本文件现在只剩:
//   - ExecutionEngine ctor/Run facade
//   - ChildExecuteTask(被 ProgramRuntime 调用,declaration 仍在
//     execution_engine.hpp 因为 sink/coverage 集成跟 engine 语义紧耦合)
//
// [v1 / v1.5 / v2 历史实现 — ROLLBACK 参考:
//   - 旧版完整 child 生命周期 + ChildMain 见 git history(refs to commits
//     before 2026-05-12)
//   - 当前等价行为通过 ReusableChildTopology + LoopRuntime + ProgramRuntime
//     的组合实现,byte-equal 路径见各自 ROLLBACK 注释]

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/engine/execution_engine.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/sandbox/device_init/device_init.hpp"

#include <utility>

namespace refuzz::worker {

// ============================================================================
// ChildExecuteTask — 一条 task 的真实 dispatch(被 ProgramRuntime 调用)。
// 实现保留在本文件:它跟 ObservationBus / ExecBackend / KCOV sink 协调,跟
// engine 主循环属同一语义边界。ProgramRuntimeRunInline 把 input/output 解包后
// 调过来。
// ============================================================================

// [v2 ChildExecuteTask — 当前版本: 走 IObservationBus,KCOV / step event 各 sink
//  自决 Begin/End/PackFeedback,driver 不再感知 coverage]
int ChildExecuteTask(IExecBackend& backend,
                     IObservationBus& bus,
                     const uint8_t* input_buf,
                     uint32_t input_len,
                     uint8_t* output_buf,
                     uint32_t output_cap,
                     uint32_t* out_len,
                     ExecMode mode,
                     uint32_t worker_id,
                     uint64_t executor_id,
                     bool collect_comps,
                     ExecTaskFailure* out_failure)
{
    auto* perf_sample = ::refuzz::worker::perf::CurrentSample();
    auto set_failure = [out_failure](ExecTaskFailure f) {
        if (out_failure != nullptr) *out_failure = f;
    };
    set_failure(ExecTaskFailure::kNone);

    *out_len = 0;
    // host 送来的 wire 输入不合法 —— 配置/协议错,不是程序的问题。
    if (input_buf == nullptr || output_buf == nullptr || input_len < 4) {
        set_failure(ExecTaskFailure::kInvalidInput);
        return -1;
    }

    ObservationContext obs_ctx{};
    obs_ctx.worker_id = worker_id;
    obs_ctx.executor_id = executor_id;
    obs_ctx.exec_mode = mode;
    // [v2 Epic 5 PR-5-B] forward collect_comps to KcovSink via bus.
    obs_ctx.collect_comps = collect_comps;

    // ---- 任务开始：sink 决定是否 enable 自身 (KcovSink 在 serial 模式 Begin) ----
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kObservationStart);
        bus.Publish(ObservationEvent::kTaskStart, obs_ctx);
    }
    if (bus.RuntimeFailureState() != RuntimeFailure::kNone) {
        set_failure(ExecTaskFailure::kRuntimeFault);   // observation sink 起不来 — infra
        return -1;
    }

    // ---- dispatch to backend（纯执行，只写 raw results）----
    uint32_t raw_len = 0;
    int status = 0;
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kBackendExecute);
        status = backend.Execute(input_buf, input_len,
                                 output_buf, output_cap, &raw_len, mode);
    }

    if (mode.scratch_reset == ScratchResetMode::kForkClean) {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kProgramFdCleanup);
        ::refuzz::worker::sandbox::device_init::CloseProgramFds();
    }

    // ---- 任务结束：sink 自行收尾 (KcovSink End) ----
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kObservationEnd);
        bus.Publish(ObservationEvent::kSessionEnd, obs_ctx);
    }

    if (bus.RuntimeFailureState() != RuntimeFailure::kNone ||
        backend.RuntimeFailureState() != RuntimeFailure::kNone) {
        *out_len = 0;
        set_failure(ExecTaskFailure::kRuntimeFault);   // sink/backend 运行时故障 — infra
        return -1;
    }

    // ---- 统一序列化 artifacts 到 output_buf 尾部 ----
    uint32_t final_len = raw_len;
    const uint32_t before_pack = final_len;
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kFeedbackPack);
        bus.PackAllFeedback(output_buf, output_cap, &final_len);
    }
    if (final_len == before_pack && bus.SinkCount() > 0) {
        // 所有 sink 都没贡献 feedback (空程序 or NoSpace) — 不打 LOG,因为
        // 每个 sink 自决,且大部分情况下是 mode=threaded → KCOV 跳过的正常路径。
    }

    *out_len = final_len;
    if (perf_sample != nullptr) {
        perf_sample->backend_status = status;
        perf_sample->output_len = final_len;
    }
    // backend 自述执行失败(KernelWireDriver 的 dispatcher 缺失 / wire decode 失败 /
    // copyin-copyout 失败 / scratch mmap 失败 …)。这些都是 worker 侧问题,程序无罪 —
    // 归 infra。注意:被测程序**自己**的行为(exit_group / crash / 卡死)不走这里,它们
    // 由上层 ForkingProgramExecutor 的 waitpid 分流判定。
    if (status != 0) {
        set_failure(ExecTaskFailure::kRuntimeFault);
    }
    return status;
}

// ============================================================================
// ExecutionEngine 实现
// ============================================================================

ExecutionEngine::ExecutionEngine(
    IWorkerTaskChannel& task_channel,
    IExecutionDomainRegistry& domain_registry,
    DomainComponentBinding components,
    std::unique_ptr<topology::ProcessTopology> topology,
    EngineConfig config)
    : supervisor_(std::make_unique<DomainSupervisor>(
          task_channel, domain_registry, std::move(components),
          std::move(topology), std::move(config)))
{}

int ExecutionEngine::Run()
{
    return supervisor_->Run();
}

void ExecutionEngine::RequestStop()
{
    supervisor_->RequestStop();
}

bool ExecutionEngine::IsRunning() const
{
    return supervisor_->IsRunning();
}

} // namespace refuzz::worker
