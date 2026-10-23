// ExecutionEngine: DomainSupervisor compatibility facade plus the shared
// per-program backend/observation helper.
//
// [R2] 原 ICoverageCollector 单 sink 被 IObservationBus 替代。
//      KCOV / step event / 未来其它观测都挂在 bus 上,driver 不直接感知。

#pragma once

#include "worker/backend/exec_backend.hpp"
#include "worker/coverage/coverage_collector.hpp"  // [R2] 仍保留：KcovCollector 在 KcovSink 内部使用
#include "worker/engine/domain_supervisor.hpp"
#include "worker/exec_mode.hpp"
#include "worker/observation/observation_bus.hpp"  // [v2 R2]

#include <cstdint>
#include <memory>
#include <signal.h>
#include <string>
#include <sys/types.h>

namespace refuzz::worker {

// Compatibility facade over DomainSupervisor plus per-program execution helper.
class ExecutionEngine {
public:
    ExecutionEngine(IWorkerTaskChannel& task_channel,
                    IExecutionDomainRegistry& domain_registry,
                    DomainComponentBinding components,
                    std::unique_ptr<topology::ProcessTopology> topology,
                    EngineConfig config);

    // Thin facade over DomainSupervisor. The supervisor owns every daemon
    // lifecycle decision and returns only after shutdown or budget exhaustion.
    int Run();

    // 从外部请求停止（信号处理器调用）
    void RequestStop();
    bool IsRunning() const;

private:
    std::unique_ptr<DomainSupervisor> supervisor_;

    // Child IPC and lifecycle mechanics live behind ProcessTopology.
};

// ==================== child 进程内部函数（fork 后运行）====================
// 这些函数在 child 进程中执行，通过 fork 继承 parent 的指针

// child 进程主循环：等待 ReadyMsg → 执行 → 发送 DoneMsg
// step event ring 指针通过 IvshmemStepEventSink::Init() 在 child 内 SetStepEventWriter,
// engine/ChildMain 不再感知。
// sandbox_mode 在 bus.InitAll() 之后、while(true) 之前生效；
// ivshmem_bytes 用于组装 SandboxSizing 算 RLIMIT_AS。
//
// ChildExecuteTask 返回非 0 时的失败归属。返回值本身(-1 / backend status)只说
// "失败了",不说"谁的错" —— 而这两类的处理完全不同,不能塌成一个 exec_error:
//   kInvalidInput — 配置/协议错:host 送来的 wire 输入不合法、exec flags 不被支持。
//                   **程序无罪**,且是确定性的:同一请求重试必然同样失败。
//   kRuntimeFault — worker 侧运行时故障:observation sink(KCOV 等)或 backend 执行
//                   失败。**程序无罪**,属基础设施问题。
// 两者都归 COMP_STATUS_INFRA_FAULT,由 error_code 区分(ERR_INVALID_INPUT /
// ERR_EXECUTOR_ERROR)。
enum class ExecTaskFailure : uint8_t {
    kNone = 0,
    kInvalidInput,
    kRuntimeFault,
};

// [v2 Epic 5 PR-5-B] collect_comps trailing bool: read from
// task_flags_get_collect_comps(msg.flags) by ChildMain; threaded into
// ObservationContext so KcovSink can switch KCOV_TRACE_PC ↔ KCOV_TRACE_CMP.
//
// out_failure(可选):返回值非 0 时写入失败归属,供调用方选 result_kind / error_code。
// 传 nullptr 表示调用方不关心细分(snapshot 路径)。
int ChildExecuteTask(IExecBackend& backend,
                     IObservationBus& bus,
                     const uint8_t* input_buf,
                     uint32_t input_len,
                     uint8_t* output_buf,
                     uint32_t output_cap,
                     uint32_t* out_len,
                     ExecMode mode = {},
                     uint32_t worker_id = 0,
                     uint64_t executor_id = 0,
                     bool collect_comps = false,
                     ExecTaskFailure* out_failure = nullptr);

} // namespace refuzz::worker
