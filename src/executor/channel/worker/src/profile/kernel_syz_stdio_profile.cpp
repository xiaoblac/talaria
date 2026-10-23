// Copyright 2026 reFuzz project author -------youngkk.
//
// kernel-syz-stdio profile: reFuzz-owned stdio worker profile for Layer-3
// paired VM oracle runs.

#include "worker/profile/worker_profile.hpp"

#include "worker/adapter/stdio_adapter.hpp"
#include "worker/profile/kernel_syz_execution_domain.hpp"
#include "worker/topology/double_fork_topology.hpp"

namespace refuzz::worker {

WorkerProfile MakeKernelSyzStdioProfile(const KernelSyzStdioArgs& args)
{
    WorkerProfile p{};
    p.name = "kernel-syz-stdio";

    StdioWorkerAdapter::Config adapter_cfg;
    adapter_cfg.worker_id = args.worker_id;
    adapter_cfg.exec_timeout_ms = args.exec_timeout_ms;
    adapter_cfg.max_input_size = args.max_input_size;
    adapter_cfg.output_size = args.output_size;
    p.adapter = std::make_unique<StdioWorkerAdapter>(adapter_cfg);

    constexpr uint32_t kMaxThreadCount = 32;
    uint32_t thread_count = args.thread_count;
    if (thread_count < 1) thread_count = 1;
    if (thread_count > kMaxThreadCount) thread_count = kMaxThreadCount;

    p.sandbox_mode = args.sandbox_mode;
    p.exec_timeout_ms = args.exec_timeout_ms;
    // [D12 plan §3] daemon-side Collect watchdog,解耦自 exec_timeout_ms。
    p.daemon_watchdog_ms = args.daemon_watchdog_ms;
    p.domain_startup_timeout_ms = args.domain_startup_timeout_ms;
    p.recycle_after = args.recycle_after;
    p.worker_id = args.worker_id;
    p.poll_ms = 1;
    p.enable_step_events = false;
    p.executor_path = args.executor_path;
    p.recycle_gate_path = args.recycle_gate_path;
    auto& boot = p.loop_boot_config;
    boot.worker_id = args.worker_id;
    boot.sandbox_mode = static_cast<uint32_t>(args.sandbox_mode);
    boot.coverage_mode = static_cast<uint32_t>(args.coverage_mode);
    boot.thread_count = thread_count;
    boot.exec_timeout_ms = args.exec_timeout_ms;
    boot.per_call_timeout_ms = args.per_call_timeout_ms;
    boot.kcov_entries = args.kcov_entries;
    boot.kcov_collector_count = args.kcov_collector_count;
    boot.kcov_premap_count = args.kcov_premap_count;
    boot.worker_perf_sample_rate = args.worker_perf_sample_rate;
    boot.worker_perf_report_every = args.worker_perf_report_every;
    if (args.enable_worker_log) {
        boot.flags |= engine::kLoopBootEnableWorkerLog;
    }
    if (args.enable_worker_perf) {
        boot.flags |= engine::kLoopBootEnableWorkerPerf;
    }

    if (args.process_topology == topology::TopologyKind::kExecDoubleFork) {
        p.execution_components = ExecRebuiltExecutionComponents{};
        p.topology = std::make_unique<topology::ExecDoubleForkTopology>();
    } else {
        auto domain = BuildKernelSyzExecutionDomain(boot);
        if (!domain) {
            return p;
        }
        p.topology = topology::MakeTopology(
            args.process_topology, *domain.backend, *domain.bus);
        p.execution_components = std::move(domain);
    }

    return p;
}

} // namespace refuzz::worker
