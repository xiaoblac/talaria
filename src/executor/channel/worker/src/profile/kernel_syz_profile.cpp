// Copyright 2026 reFuzz project author -------youngkk.
//
// kernel-syz family factory + 通用 RunWorkerProfile。
// R5 引入。

#include "worker/profile/worker_profile.hpp"

#include "worker/adapter/ivshmem_adapter.hpp"
#include "worker/profile/kernel_syz_execution_domain.hpp"
#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/topology/double_fork_topology.hpp"

namespace refuzz::worker {

WorkerProfile MakeKernelSyzProfile(const KernelSyzArgs& args)
{
    WorkerProfile p{};
    p.name = "kernel-syz";

    // ---- Transport: ivshmem ----
    IvshmemWorkerAdapter::Config adapter_cfg;
    adapter_cfg.worker_id = args.worker_id;
    adapter_cfg.vm_id = args.vm_id;
    adapter_cfg.peer_id = args.peer_id;
    adapter_cfg.poll_ms = args.poll_ms;
    adapter_cfg.enable_step_events = args.enable_step_events;
    p.adapter = std::make_unique<IvshmemWorkerAdapter>(adapter_cfg);

    // ---- Driver: kernel-syz family — varint exec wire (§3.2) only ----

    // [v2 Epic 7 PR-4] thread_count 钳到 [1, 32]。32 来自 syzkaller 上游
    // kMaxThreads;KCOV collector slot 数由 KcovSink 按配置创建,可以小于
    // logical thread_count,调度层按 syzkaller 语义拒绝超过 coverage slot
    // 的执行需求。
    // == 1 时 driver Execute 走 serial fast path,与 Step 1~3 等价。
    constexpr uint32_t kMaxThreadCount = 32;
    uint32_t thread_count = args.thread_count;
    if (thread_count < 1) thread_count = 1;
    if (thread_count > kMaxThreadCount) thread_count = kMaxThreadCount;
    (void)args.driver_kind; // always kWire after V1 retirement

    // ---- Engine config 副本 ----
    p.sandbox_mode = args.sandbox_mode;
    p.exec_timeout_ms = args.exec_timeout_ms;
    // [D12 plan §3] daemon-side Collect watchdog,解耦自 exec_timeout_ms。
    p.daemon_watchdog_ms = args.daemon_watchdog_ms;
    p.domain_startup_timeout_ms = args.domain_startup_timeout_ms;
    p.recycle_after = args.recycle_after;
    p.worker_id = args.worker_id;
    p.poll_ms = args.poll_ms;
    p.enable_step_events = args.enable_step_events;
    if (args.worker_id == 0) {
        p.post_register_setup = []() {
            sandbox::device_init::SetupVmSysctls();
            sandbox::device_init::MountCgroupsHost();
            sandbox::device_init::SetupBinfmtMisc();
            // [fuse-abort 2026-08-08] 把 fusectl 挂进 daemon 根 mount
            // namespace，daemon 和所有 loop 才能看到全局 FUSE connections：
            // StopDomainHandle 的 timeout escalation 和 program_runtime 的
            // kill_and_wait 路径都要靠它 abort 卡死的 connection。sandbox
            // 每 program 自己的 SetupFusectl 变成 EBUSY no-op（同路径已挂），
            // 行为不变。
            sandbox::device_init::SetupFusectl();
        };
    }
    // [FUP-METRIC-VM 2026-05-10] CLI-supplied metric dump path (template).
    p.metric_dump_path = args.metric_dump_path;
    // [Brick 4a] snapshot worker mode (single-process in-place loop).
    p.snapshot = args.snapshot;
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
    if (args.enable_step_events) {
        boot.flags |= engine::kLoopBootEnableStepEvents;
    }
    if (args.enable_worker_log) {
        boot.flags |= engine::kLoopBootEnableWorkerLog;
    }
    if (args.enable_worker_perf) {
        boot.flags |= engine::kLoopBootEnableWorkerPerf;
    }

    const bool exec_owns_components =
        !args.snapshot &&
        args.process_topology == topology::TopologyKind::kExecDoubleFork;
    if (exec_owns_components) {
        p.execution_components = ExecRebuiltExecutionComponents{};
        p.topology = std::make_unique<topology::ExecDoubleForkTopology>();
    } else {
        auto local_boot = boot;
        local_boot.flags &= ~engine::kLoopBootEnableStepEvents;
        auto domain = BuildKernelSyzExecutionDomain(local_boot);
        if (!domain) {
            return p;
        }
        p.topology = topology::MakeTopology(
            args.process_topology, *domain.backend, *domain.bus);
        p.execution_components = std::move(domain);
    }

    return p;
}

// [FUP-METRIC-VM placeholder helper — REMOVED 2026-05-10
//  (FUP-PSEUDO-METRIC-TELEMETRY)]
// `ResolveMetricDumpPath` substituted "{worker_id}" in the dump-path
// template for the daemon-shutdown JSON dump. That dump path is now dead
// code (see RunWorkerProfile site for rationale); the helper went with it.

} // namespace refuzz::worker
