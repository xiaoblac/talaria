// Copyright 2026 reFuzz project author -------youngkk.
//
// WorkerProfile: family-specific 装配根 (composition root)。
//
// R5 引入：把 worker 启动时需要的所有可插拔组件 (adapter / driver / bus /
// sandbox) 打包成一个 struct,让 main() 退化为"按 --profile= 选 factory →
// 跑通用 RunProfile" 的两行调度。
//
// 当前注册的 profile：
//   - kernel-syz : ivshmem + KernelChildDriver(SyzExec+SyscallOrPseudo) + KcovSink+IvshmemStepEventSink
//
// 未来 profile (按 §3.x 路线):
//   - afl-cli       (3.1) : ivshmem + ForkServerDriver + AflBitmapSink + ExitOrAsanDetector
//   - middleware    (3.2) : ivshmem + DaemonClientDriver + LibfuzzerCovSink + RestartSupervisor
//   - protocol      (3.3) : ivshmem + PeerConnDriver  + grammar-aware mutator
//   - db-sqlite     (3.4) : ivshmem + InProcDriver + LibfuzzerCovSink + ResultDigestSink
//   - compiler      (3.5) : ivshmem + SubprocessDriver(exec compiler) + IceParser + CrossOptOracle
//   - browser       (3.6) : ivshmem + SubprocessDriver(d8/content_shell) + LibfuzzerCovSink + SandboxCrashToolkit
//   - pytorch       (3.7) : ivshmem + PythonSubprocessDriver + NumericDiffOracle
//
// 每个 profile 的 factory 都返回同一个 WorkerProfile 类型;新 family 着陆
// = 加一个 .cpp factory + 在 main 的 switch 里加一行,worker core 不动。

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/adapter/worker_adapter.hpp"
#include "worker/coverage/kcov_collector.hpp"
#include "worker/profile/execution_components.hpp"
#include "worker/sandbox.hpp"
#include "worker/topology/process_topology.hpp"  // [v3 P1] TopologyKind / ProcessTopology
#include "worker/engine/loop_worker_boot_config.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace refuzz::worker {

// 命令行解析后传给 factory 的纯数据视图,与 syz family 强相关。
// 其它 family 的 args 结构体定义在各自 factory 文件里。
struct KernelSyzArgs {
    // [Layer-2 §3.3] 选择 driver:
    //   kWire = syzkaller-equivalent exec wire (§3.2 byte-equal output via
    //           streaming KernelWireDriver). Only path after V1 retirement.
    enum class DriverKind : uint8_t {
        kWire = 0,
    };

    uint32_t worker_id = 0;
    uint32_t vm_id = 0;
    int peer_id = 1;
    int poll_ms = 1;
    uint32_t exec_timeout_ms = 5000;
    // 0 = derive 3 * exec_timeout_ms, matching syzkaller's runner watchdog.
    uint32_t daemon_watchdog_ms = 0;
    uint32_t domain_startup_timeout_ms =
        topology::kDefaultDomainStartupTimeoutMs;
    uint32_t recycle_after = 600;
    CoverageMode coverage_mode = CoverageMode::kKcov;
    SandboxMode sandbox_mode = SandboxMode::kNone;
    bool enable_step_events = false;
    bool enable_worker_log = false;
    bool enable_worker_perf = false;
    uint32_t worker_perf_sample_rate = 1;
    uint32_t worker_perf_report_every = 256;
    std::string executor_path;
    std::string recycle_gate_path = "/run/refuzz-domain-recycle.lock";
    DriverKind driver_kind = DriverKind::kWire;
    // [v2 Epic 7 PR-4] worker 内部 thread pool 大小。默认 1 → serial-only,
    // 行为与 Epic 7 PR-1~PR-3 完全等价(driver Execute 走 serial fast path,
    // pool 不 spawn,sink 池 size=1)。>1 时开启 threaded path:
    //   - sink 在 ctor 建 min(thread_count, 8) 个 KcovCollector;Init() 打开
    //     全部 fd/KCOV_INIT_TRACE,但只预 mmap 前 3 个 collector,跟齐
    //     syzkaller delayed-KCOV 的 collector/mmap 上限
    //   - driver 持 KernelThreadPool,IntraTaskMode::kThreaded task 走 worker
    //     thread 调度;pseudo / fail_nth 都在 worker thread 内执行
    //   - profile thread_count > 32 视为配置错误(KCOV fd 数过多 + 内存
    //     压力),driver ctor 钳到上限
    uint32_t thread_count = 1;
    // [FUP-METRIC-VM 2026-05-10] PR-METRIC dump trigger 在 QEMU mode 下 host env
    // 不传给 VM 内 worker,getenv("SYZ_PSEUDO_METRIC_DUMP") 永远 fire 不到。改用
    // CLI 透传:host config target.metric_dump_path → worker_start_cmd
    // --metric-dump-path PATH → 这里。Path 支持 {worker_id} 占位符让 n_workers>1
    // 时各 worker 写不同文件;空字符串 = 禁用 dump (与默认 false 等效)。fallback
    // 仍保留 getenv 让 host-side dev/unit-test 不破。
    std::string metric_dump_path;
    // [当前版本 P5] process topology 跟 stdio profile 同源,默认 kDoubleFork —
    // syzkaller exec mode 进程拓扑对齐(daemon → loop child=PID 1 → program
    // child)。recycle_after=600 由 ExecutionEngine 在 ReportDone 后的 idle
    // maintenance boundary 执行，不进入第 600 条任务的 RTT。需要长 child
    // 复用做 throughput baseline 测试时显式设 process_topology=kReusableChild。
    ::refuzz::worker::topology::TopologyKind process_topology =
        ::refuzz::worker::topology::TopologyKind::kExecDoubleFork;
    // KCOV_INIT_TRACE entry count per collector. Default keeps upstream
    // syzkaller parity (512 Ki entries = 4 MiB on 64-bit Linux); experiments
    // can lower it to quantify KCOV mmap contribution to fork/exit cost.
    uint32_t kcov_entries = static_cast<uint32_t>(kDefaultKcovEntries);
    // [当前版本 kcov-pool-config] 拆 thread_count vs KCOV mmap 预热规模:
    //   kcov_collector_count : threaded mode 下 KCOV fd / collector 数上限。
    //     默认 8 对齐 syzkaller kCoverOptimizedCount。允许小于
    //     thread_count;调度到没有 opened kcov fd 的 coverage-required thread
    //     会失败,不会静默无 coverage 执行。
    //   kcov_premap_count    : 上述 collector 池里 fork 模板前预 mmap 的数量
    //     (跟齐 kCoverOptimizedPreMmap=3)。其余 collector 在 worker thread
    //     首次 Begin() 时 lazy mmap,避免 N × 4 MiB 进 fork 模板。
    // 两值默认匹配 syzkaller upstream;ops 可在 config 里调低 thread_count/collector
    // 一起省内存,或调高 collector_count 覆盖 32-thread oracle。0 / 负值会在
    // KcovSink 内回退到默认。
    uint32_t kcov_collector_count = 8;
    uint32_t kcov_premap_count    = 3;
    // [当前版本 per-call-timeout-config] threaded path 下 worker thread 每条
    // syscall WaitCallDone 的超时(ms)。对齐 syzkaller upstream 实际 fuzz 路径:
    //   targets.go:857 Syscall = 50 * Millisecond (base)
    //   executor.cc:1158 timeout_ms = syscall_timeout_ms + attrs.timeout*slowdown
    //   QEMU slowdown_scale=10 → 实际 per-call ≈ 500ms (base × slowdown)
    // executor.cc:1647 的 5000ms 是 stdio fallback (manager 未下发 RPC 时),
    // 之前误用作 fuzz 路径默认 → 拖完整 program 的最坏成本被放大 100×。
    // 默认 500ms 跟齐 QEMU fuzz 主路径;native (slowdown=1) 可降到 50,KASAN/
    // KCSAN 等 slowdown 更高时可调高。serial path 不读此字段。
    uint32_t per_call_timeout_ms  = 500;
    // [Brick 4a] snapshot worker mode: single-process, no fork, spin-wait +
    // in-place execute (syz snapshot.h model). Set via --snapshot. When true,
    // RunWorkerProfile dispatches to RunSnapshotEngine instead of ExecutionEngine
    // (process_topology is ignored — the snapshot loop owns its own lifecycle).
    bool snapshot = false;
};

// Stdio-mode kernel syz profile args. This is a local-process worker profile
// for Layer-3 oracle use: stdin carries length-prefixed syz exec wire, stdout
// carries JSONL results.
struct KernelSyzStdioArgs {
    uint32_t worker_id = 0;
    uint32_t exec_timeout_ms = 5000;
    // 0 = derive 3 * exec_timeout_ms.
    uint32_t daemon_watchdog_ms = 0;
    uint32_t domain_startup_timeout_ms =
        topology::kDefaultDomainStartupTimeoutMs;
    // Layer-3 stdio oracle compares one syz exec-wire program at a time.
    // syz-executor stdio forks per program, so default reFuzz stdio to the
    // same externally visible process-state lifetime. Production ivshmem keeps
    // its amortized child reuse default in KernelSyzArgs.
    uint32_t recycle_after = 1;
    CoverageMode coverage_mode = CoverageMode::kKcov;
    SandboxMode sandbox_mode = SandboxMode::kNone;
    uint32_t thread_count = 1;
    uint32_t kcov_entries = static_cast<uint32_t>(kDefaultKcovEntries);
    // [当前版本 kcov-pool-config / per-call-timeout-config] 见 KernelSyzArgs
    // 同名字段。per_call_timeout_ms 默认 500 对齐 QEMU fuzz 路径 (50ms×10),
    // 不再是 stdio fallback 5000ms。
    uint32_t kcov_collector_count = 8;
    uint32_t kcov_premap_count    = 3;
    uint32_t per_call_timeout_ms  = 500;
    uint32_t max_input_size = 4u << 20;
    // Match upstream syzkaller stdio executor's anonymous output mapping:
    // `execute_stdio_main()` preallocates kMaxOutputCoverage = 6 MiB.
    // This now also comfortably covers reFuzz's syzkaller-aligned 4 MiB KCOV
    // collector plus SyzExecResult headers / tail metadata.
    uint32_t output_size = SYZKALLER_MAX_OUTPUT_COVERAGE;
    bool enable_worker_log = false;
    bool enable_worker_perf = false;
    uint32_t worker_perf_sample_rate = 1;
    uint32_t worker_perf_report_every = 256;
    std::string executor_path;
    std::string recycle_gate_path;
    // [v3 P4 DoubleFork plan] stdio profile 默认 kDoubleFork — 跟 syzkaller
    // exec mode 进程拓扑对齐(daemon → loop child=PID 1 → program child)。
    // ForkingProgramExecutor 每条 prog fork program child,sandbox 由 loop
    // child 一次性应用 program child 继承。
    // ivshmem 生产 profile 仍 kReusableChild + recycle_after=600 长复用(P5
    // 再切默认 kDoubleFork)。
    ::refuzz::worker::topology::TopologyKind process_topology =
        ::refuzz::worker::topology::TopologyKind::kExecDoubleFork;
};

// 装配根：拥有所有可插拔组件的 unique_ptr,加上 plain config。
struct WorkerProfile {
    std::string name;

    // ---- Pluggable components ----
    std::unique_ptr<IWorkerAdapter> adapter;   // transport owner + explicit facet accessors
    // Explicit ownership variant: legacy/snapshot profiles own daemon-side
    // components; exec profiles rebuild them from LoopWorkerBootConfig.
    WorkerExecutionComponents execution_components;
    // topology owns the execution-domain lifecycle and is always daemon-side.
    std::unique_ptr<::refuzz::worker::topology::ProcessTopology> topology;
    // Optional daemon-side VM setup. RunWorkerProfile invokes it exactly once
    // after Register() has published CLAIMED/heartbeat and before domain setup.
    std::function<void()> post_register_setup;

    // coverage-off Null Objects live inside the daemon-owned variant, keeping
    // the driver's borrowed provider/drain pointers valid for the whole run.
    // ---- Engine config (从 args 直接派生) ----
    SandboxMode sandbox_mode = SandboxMode::kNone;
    uint32_t exec_timeout_ms = 5000;
    // 0 = derive 3 * exec_timeout_ms.
    uint32_t daemon_watchdog_ms = 0;
    uint32_t domain_startup_timeout_ms =
        topology::kDefaultDomainStartupTimeoutMs;
    uint32_t recycle_after = 600;
    uint32_t worker_id = 0;
    int poll_ms = 1;

    // ---- 后期 sink 装配钩子 ----
    // 某些 sink (例如 IvshmemStepEventSink) 需要 adapter.Init() 之后才能取到
    // ring 指针。RunProfile 在 Init 后调用 late_sink_setup(*profile, args) 完成挂载。
    bool enable_step_events = false;
    // [FUP-METRIC-VM] dump path template (with optional {worker_id} placeholder).
    std::string metric_dump_path;
    // [Brick 4a] snapshot worker mode (single-process in-place loop). When true,
    // RunWorkerProfile runs RunSnapshotEngine instead of ExecutionEngine.
    bool snapshot = false;
    ::refuzz::worker::engine::LoopWorkerBootConfig loop_boot_config =
        ::refuzz::worker::engine::MakeLoopWorkerBootConfig();
    std::string executor_path;
    std::string recycle_gate_path;
};

// kernel-syz family 装配 factory。
//
// 注意：不调用 adapter.Init()——交给 RunProfile 统一处理,使 ROLLBACK
// 路径 (旧 main 直接构造) 能复用同一个流程。
WorkerProfile MakeKernelSyzProfile(const KernelSyzArgs& args);
WorkerProfile MakeKernelSyzStdioProfile(const KernelSyzStdioArgs& args);

// 通用 worker 启动入口：负责 sandbox 预检 / adapter.Init/Handshake/Register /
// 后期 sink 挂载 / engine 构造 / engine.Run / 清理。
//
// 返回 worker 退出码 (与 main 一致语义)。
int RunWorkerProfile(WorkerProfile& profile);

} // namespace refuzz::worker
