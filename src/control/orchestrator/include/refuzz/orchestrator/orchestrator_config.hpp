// Copyright 2026 reFuzz project author -------youngkk.

#pragma once

#include "channeldispatcher.hpp"
#include "refuzz/channel/factory/channel_assembler.hpp"       // ChannelConfig
#include "refuzz/channel/factory/channel_backend_profile.hpp" // IChannelBackendProfile
#include "refuzz/orchestrator/session_layout.hpp"
#include "refuzz/crash/repro/core/repro_config.hpp"
#include "refuzz/control/fuzzer_loop.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/policy/policy_engine.hpp"
#include "refuzz/telemetry/observation/terminal_dashboard.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::orchestrator {

enum class ExecutionMode : uint8_t {
    kKernelSyscall = 0,
    kUserspaceHarness,
    kBinaryDbi,
};

enum class CoverageMode : uint8_t {
    kNone = 0,
    kKcov,
};

enum class SanitizerMode : uint8_t {
    kNone = 0,
    kKasan,
    kKcsan,
    kUbsan,
};

// child (fuzz exec) 进程隔离模式。仅作用于 worker 侧 child，不影响 parent/
// watchdog——后者必须保持 root 以访问 /dev/uio* /dev/kcov。
//   kNone      : 不隔离（默认，兼容旧行为）
//   kSetuid    : drop 到 uid=65534 (nobody) + PR_SET_NO_NEW_PRIVS
//   kNamespace : Phase 2 预留（当前未实现，worker 会拒绝启动）
enum class SandboxMode : uint8_t {
    kNone = 0,
    kSetuid,
    kNamespace,
};

enum class RunLimitMode : uint8_t {
    kBoth = 0,
    kTaskCount,
    kRuntime,
};

// [fixed request stream] docs/plans/fixed-request-stream-performance-replay.md
// §6. Top-level run mode, orthogonal to TargetRuntimeConfig::execution_mode
// (which selects target ABI/surface -- kernel_syscall/userspace_harness/
// binary_dbi -- not workload source). Mirrors Syzkaller's own -mode concept
// (fuzzing/corpus-run/smoke-test/...) as a named, mutually-exclusive run type,
// rather than an orthogonal boolean toggle.
//   kFuzzing: normal continuous fuzzing (default) -- FuzzerLoop spawns its
//     usual ExploreJob, catch-all triage follows the active profile exactly
//     as it does today. Every existing config is unaffected.
//   kReplay: fixed request stream replay (plan §6) -- see ReplayConfig below.
//     The operator must size run_limit_mode/runtime/total_tasks generously
//     enough to cover the whole stream: the stream-drained stop condition and
//     the run_limit stop condition are independent, and whichever fires first
//     wins.
enum class RunMode : uint8_t {
    kFuzzing = 0,
    kReplay,
};

// Replay-mode-specific config; only meaningful when run_mode == kReplay.
struct ReplayConfig {
    std::string stream_path;

    // [fixed request stream] Hold-before-teardown, for out-of-band GUEST-side
    // probes (perf record) that must be stopped and fetched while the VM is
    // still alive.
    //
    // Why this is needed at all: a replay run ends by itself -- the stream
    // drains, on_fully_drained calls RequestStop(), the fuzzer thread exits,
    // and Stop() proceeds to registry.StopAll() which destroys the VM. That
    // whole tail is seconds long, while stopping perf and fetching its data
    // over ssh/scp measures in tens of seconds. An external driver polling for
    // "looks quiesced" can therefore never win the race; the only correct
    // synchronisation point is inside the process that owns the VM lifetime.
    // (The now-deleted refuzz-exec-replayer carried the same mechanism as
    // -hold-after-drain-s / -hold-release-file, for exactly this reason.)
    //
    // Contract-safe by construction: the hold sits AFTER the fuzzer thread has
    // joined, so every request has already completed and no measurement is in
    // flight. It cannot move an E1--E9 / A--D / R boundary (plan §2.2); it only
    // delays teardown.
    //
    // Empty drained_marker_path disables the hold entirely (no-op default).
    std::string drained_marker_path;   // touched once quiesced; VM still alive
    std::string release_path;          // polled; teardown resumes once present
    std::uint32_t hold_timeout_s = 900;  // backstop; 0 = wait forever
};

struct TargetRuntimeConfig {
    ExecutionMode execution_mode = ExecutionMode::kKernelSyscall;
    CoverageMode coverage_mode = CoverageMode::kKcov;
    SanitizerMode sanitizer_mode = SanitizerMode::kNone;
    SandboxMode sandbox_mode = SandboxMode::kNone;
    // [syscall-enable-whitelist] syzkaller-style syscall selection globs
    // (mirror of mgrconfig enable_syscalls / disable_syscalls). Empty
    // enable_syscalls = every call enabled; disable_syscalls then
    // subtracts. Patterns: exact name, base name (matches all `$variant`),
    // or a trailing-`*` prefix. Resolved against the target by
    // program::syz::compute_enabled_calls at engine build + corpus load.
    std::vector<std::string> enable_syscalls;
    std::vector<std::string> disable_syscalls;
    // [FUP-METRIC-VM 2026-05-10] PR-METRIC dump trigger 路径模板。
    // 非空时 config_parser 把 --metric-dump-path <path> 注入 worker_start_cmd,
    // worker 在 engine.Run 退出后用该路径调 metrics::DumpJsonToFile (替代
    // QEMU mode 下永远 fire 不到的 host env SYZ_PSEUDO_METRIC_DUMP)。
    // 路径支持 {worker_id} 占位符:n_workers>1 时操作员需用占位符避免 race
    // (例 "/root/refuzz_metrics_w{worker_id}.json")。
    // VM-side 写出位置由 operator 决定:典型用 qemu-virtfs 把 host
    // /tmp/refuzz_vm_share/ 9p mount 到 VM 内 /root/,这样 worker 写
    // /root/refuzz_metrics_w0.json 等价于 host /tmp/refuzz_vm_share/refuzz_metrics_w0.json。
    // 默认空字符串 = 禁用 dump (与历史行为一致)。
    std::string metric_dump_path;

    // [debug instrumentation] LoopRuntime 启动稳态 dump /proc/self/smaps +
    // fd 数,定位 fork_avg 成本。worker_start_cmd 注入 --debug-smaps。
    bool debug_smaps = false;
    // [debug instrumentation] ForkingProgramExecutor child 跳过 program 执行,
    // 只 fork → 写空 result → _exit,量纯 fork+exit floor。注入 --debug-empty-fork。
    bool debug_empty_fork = false;
    // [debug instrumentation] mount-image / loop-device timing trace.
    // worker_start_cmd 注入 --debug-mount-timing,worker 端把 env
    // REFUZZ_MOUNT_TIMING_DIAG=1 置上并开启 WorkerLog。仅用于 paired-oracle
    // timing divergence 诊断,默认 false。
    bool debug_mount_timing = false;
    // [debug instrumentation] kDoubleFork topology probe. worker_start_cmd
    // 注入 --debug-topology-probe,worker 端输出 loop/program child
    // pid namespace identity、cgroup pids 和 post-exit cleanup summary。
    bool debug_topology_probe = false;
    // b15 cold-VM warmup. Inject `--warmup-devices` on worker_start_cmd so
    // the worker pre-touches a hardcoded set of /dev/* paths at startup,
    // warming kernel VFS/dentry/page caches before the first replayed
    // syz_open_dev$* request. Mirrors the side effect of syz-manager's
    // pre-fuzz feature probing that the captured trace doesn't replay.
    // Purely an oracle/strict-equivalence knob — leave false in production.
    bool warmup_devices = false;

    // [v2 Epic 7 PR-4.5] worker 内 KCOV per-thread fd 池大小。
    //   == 1 (default) : worker 走 serial fast path,等价 Epic 7 PR-1~PR-3 (无
    //                    KernelThreadPool 构造,worker 端 mmap 仅 1 个 collector
    //                    = coverage.kcov.entries × 8B，默认 4 MiB);任何
    //                    task.flags 设了 INTRA_THREADED 都会
    //                    被 worker 拒成 exec_error (driver Execute 入口检查
    //                    thread_count > 1)。
    //   >  1           : worker 在 driver 端 lazy 构造 KernelThreadPool,
    //                    IntraTaskMode::kThreaded task 走 worker thread 调度。
    //                    KCOV collector 池按 syzkaller delayed-KCOV 模型
    //                    裁剪到最多 8 个,且只预 mmap 前 3 个,避免 32 ×
    //                    4 MiB mmap 进入 fork 模板。
    //   范围: [1, 32]。config_parser fail-closed 拒收范围外值。
    //   上限 32 跟齐 syzkaller upstream kMaxThreads;实际 KCOV fd/mmap 由
    //   worker 端 delayed-KCOV collector pool 再裁剪。
    //
    // 仅 thread_count > 1 时把 --thread-count N 注入 worker_start_cmd;
    // == 1 时保持历史 cmd 不变 (向后兼容,既有 sample config 不需要改)。
    //
    // 注意:thread_count > 1 仅是 worker 端 "infra ready"。要让 task 真的
    // 走 threaded branch 还得让 task.flags 带 TASK_FLAG_INTRA_THREADED——这
    // 由下面的 intra_task_mode 字段控制。
    uint32_t thread_count = 1;

    // [当前版本 kcov-pool-config] worker 内 KCOV collector 池大小 + 预 mmap 数。
    //   kcov_collector_count : threaded mode 下 collector 上限,默认 8 = syzkaller
    //                          upstream executor.cc kCoverOptimizedCount。可小于
    //                          thread_count;worker 调度层会拒绝需要 coverage
    //                          但没有 opened kcov fd 的线程,对齐 syzkaller。
    //   kcov_premap_count    : 上述池里 fork 模板前预 mmap 的数量,默认 3 =
    //                          kCoverOptimizedPreMmap;其余 collector 首次 Begin
    //                          时 lazy mmap。
    // 仅 thread_count > 1 时这两个值有意义;config_parser 在 thread_count > 1
    // 且非默认值时注入 --kcov-collector-count / --kcov-premap-count。
    // 范围: kcov_collector_count [1, 64]、kcov_premap_count [0,
    // kcov_collector_count]。
    uint32_t kcov_collector_count = 8;
    uint32_t kcov_premap_count    = 3;

    // [当前版本 per-call-timeout-config] threaded mode worker thread WaitCallDone
    // 单条 syscall 超时(ms)。对齐 syzkaller upstream fuzz 路径:
    //   targets.go:857 Syscall = 50 * Millisecond (base)
    //   executor.cc:1158 timeout_ms = syscall_timeout_ms + attrs.timeout*slowdown
    //   QEMU slowdown_scale=10 → per-call ≈ 500ms
    // executor.cc:1647 的 5000ms 是 stdio fallback,manager 未下发 RPC 时才用,
    // 不是真实 fuzz 路径的值;之前的 5000ms 默认把 program tail latency 放大 10×。
    // 默认 500ms 跟 QEMU 主路径;native/KASAN 等 slowdown 不同时可调。
    // 拖完整 program 的最坏成本就是这个超时 × n_call。serial mode 不读此字段。
    uint32_t per_call_timeout_ms = 500;

    // [v2 Epic 7 PR-4.6] 全局执行模式开关。
    //   kSerial   (default):所有 outgoing task wire flag = TASK_FLAG_INTRA_SERIAL,
    //                       worker 走 serial fast path,行为等价历史。
    //   kThreaded         :所有 outgoing task wire flag |= TASK_FLAG_INTRA_THREADED,
    //                       worker 走 KernelThreadPool 调度。要求 thread_count > 1,
    //                       否则 config_parser fail-closed。
    // 这是 stage-agnostic 的全局开关 — channeldispatcher 在 wire 翻译点统一 OR。
    // 单 task override 通过 task.opts.flags |= kExecFlagIntraThreaded 仍生效;
    // 全局 = kSerial 时也可让某 stage 单独 opt-in。
    // 后续若需要 "mixed" 等更细模式,enum 可平滑扩。
    enum class IntraTaskMode : uint8_t {
        kSerial   = 0,
        kThreaded = 1,
    };
    IntraTaskMode intra_task_mode = IntraTaskMode::kSerial;
};

struct HostLoggingConfig {
    bool enable = true;
    bool stream = false;
    std::string path;
    std::chrono::milliseconds flush_interval{250};
    bool console_summary = true;
    uint32_t hot_path_sample_rate = 0;
    uint32_t task_trace_sample_rate = 0;
};

struct OrchestratorConfig {
    std::string profile = "kernel";
    TargetRuntimeConfig target;

    //工作目录模型 — 双轴语义：
    //
    //   work_dir   → "本次运行的基目录"，承载 *瞬态* session。
    //                 空字符串 → "/tmp"。
    //                 每次启动都会在其下建 run-<ts>-<pid>/,里面 logs/ diagnostics/
    //                 vm-N/ repro-N/ 等都是 session 独占、可被 retention 清理。
    //
    //   state_dir  → "跨 run 共享状态"的基目录，承载 *持久* 数据。
    //                 空字符串 → <work_dir>/state （与 run-* 同级，retention 不扫）。
    //                 corpus / coverage / repros 的默认落地点从这里派生。
    //                 用户可在 yaml/json 顶层显式设定 state_dir 指向任意位置。
    //
    //   retention  → 启动期是否扫 <work_dir>/run-*/ 做 mtime 倒序裁剪 (state/ 不碰)。
    //
    // QemuIvshmemLinuxProfile.runtime.instance.workdir 仍由 Assembler 从
    // ChannelBuildContext::vm_workdir（指向 session 内 vm-N/）填入。
    std::string   work_dir;
    std::string   state_dir;
    bool          retention        = false;
    uint32_t      retention_max    = 3;
    SessionLayout layout;

    //两段式 channel 配置（对应 Channel 的聚合 config 入口）：
    //   - channel_common     : 中性 ChannelConfig（所有后端共用的运行参数）
    //   - channel_backend    : 后端专属 Profile，运行时多态（unique_ptr + 虚接口）
    //   - channel_backend_id : yaml/json 里的选择键（与 ChannelCatalog 注册 id 对应）
    //
    // channel_backend 为 unique_ptr 使 OrchestratorConfig 自然 move-only；
    // 没有任何地方需要对整个 OrchestratorConfig 进行值拷贝。
    channel::ChannelConfig                                    channel_common;
    std::unique_ptr<channel::factory::IChannelBackendProfile> channel_backend;
    std::string                                               channel_backend_id;
    uint32_t                                                  fuzz_channel_count = 1;

    // 执行模式诉求（后端无关）：true = 请求 snapshot 执行（每 testcase savevm/loadvm）。
    // 这是一个 MODE/能力诉求，NOT 一个 backend 身份；具体选哪个 backend 由 Resolver
    // 按 "模式 → profile per-mode 默认 + backend 能力" 转译（见 resolver.cpp）。
    bool                                                      snapshot_fuzzing = false;

    channeldispatcher::ExecutorConfig executor;
    std::chrono::milliseconds pop_timeout{5};
    std::chrono::microseconds poll_timeout{1000};
    uint32_t shutdown_grace_ms = 60000;
    control::FuzzerLoopConfig fuzzer;
    telemetry::PolicyEngineConfig policy_engine;
    telemetry::ObservabilityConfig observability;
    telemetry::TerminalDashboardConfig dashboard;
    HostLoggingConfig logging;

    bool coverage_raw_pc = true;
    // [P2] edge-signal corpus admission (syz use_cover_edges). Default ON for the
    // kernel KCOV engine. A/B off via coverage.kcov.cover_edges:false.
    bool coverage_cover_edges = true;
    uint32_t coverage_max_pcs_per_exec = 0;
    double coverage_sample_rate = 1.0;
    // [syz-parity convertCallInfo] Kernel-address sanity filter: drop a coverage
    // slice whole if any PC is outside [text_start, text_end] (corrupted/injected
    // coverage). Default off; range defaults = syz linux/amd64 KernelAddresses.
    bool coverage_filter_signal = false;
    uint64_t coverage_kernel_text_start = 0xffffffff80000000ULL;
    uint64_t coverage_kernel_text_end = 0xffffffffff000000ULL;
    // Worker-side KCOV_INIT_TRACE entry count per collector. Default 512 Ki
    // matches syzkaller/reFuzz historical behavior (4 MiB on 64-bit Linux).
    uint32_t coverage_kcov_entries = 512u << 10;
    std::string coverage_output_dir = "/tmp/refuzz_phase1_coverage";
    // Disk export of coverage_PC_series.log. The cadence is fixed at 10s.
    bool coverage_export_enabled = false;
    // [corpus-pc-export] When non-empty, on shutdown write the corpus-admitted PC
    // set (distinct raw PCs, sorted, 0x%x/line) to this path. Default empty = off;
    // only speed-compare D sets it. yaml: coverage.export.corpus_pc_path.
    std::string coverage_export_corpus_pc_path;
    // [coverage-compare export] siblings to corpus_pc_path. Non-empty → at shutdown
    // dump the corpus-admitted ADMISSION-signal set (corpus_signal_path, fed from
    // CorpusCoverageMetadata.signal_cover_hashes) and the ALL-executed signal set
    // (all_signal_path, fed from every data-plane exec's EngineOutput.new_signal_hashes
    // = the all-exec / syz MaxSignal domain). Element semantics follow
    // coverage.kcov.cover_edges: EDGES when true (default) → corpus_edge/all_edge,
    // raw PCs when false → corpus_pc(signal)/all_pc. Default empty = OFF: the store
    // is left unwired so there is zero per-execution cost. yaml: coverage.export.*.
    std::string coverage_export_corpus_signal_path;
    std::string coverage_export_all_signal_path;

    // [edge-over-time] coverage.export.edge_series_enabled. Independent gate
    // for the all/corpus EDGE metric log (coverage_edge_series.log,
    // over time — reFuzz analog of syz bench "signal"). On (default) → the
    // edge gauges are recorded every 10s; set the
    // JSON key false to opt out. Plumbed to ObservabilityConfig::edge_series_enabled.
    bool coverage_export_edge_series_enabled = true;


    bool corpus_persist_enable = true;
    std::string corpus_persist_dir;
    bool corpus_load_on_start = true;
    bool coverage_persist_enable = true;
    std::string coverage_persist_path;
    bool coverage_load_on_start = true;
    bool crash_repros_as_seeds = true;

    //成功 repro 的跨 run 落地目录。
    //   默认：<state_dir>/repros （空串由 config_parser 兜底填充）。
    //   旧路径 session_layout.repros_dir 已删除,不再每次 run 重新生成空目录。
    std::string repros_persist_dir;

    crash::ReproConfig repro;

    std::string worker_bin_host_path =
        "/workspace/talaria/build-llvm20/executor/channel/worker/ivshmem_worker";
    uint32_t vm_id = 0;

    // worker 端诊断日志开关。开启后 orchestrator 会给 worker_start_cmd 追加
    // `--enable-worker-log`,VM 内 worker 会把 [Worker] child[...]: exec ...
    // 行写到 /dev/ttyS0,host 侧通过 qemu serial socket 可以实时看到真实
    // per-task 耗时分布。生产/性能默认关闭,需要诊断时显式打开。
    bool worker_log_enabled = false;
    // Worker-side low-frequency performance sampling. Parsed from
    // `fuzzer.worker_perf` and injected into worker_start_cmd as explicit
    // worker CLI flags.
    bool worker_perf_enabled = false;
    uint32_t worker_perf_sample_rate = 1;
    uint32_t worker_perf_report_every = 256;
    // 运行上限模式：
    //   kBoth      : 时间和任务数任一达到即停止（默认）
    //   kTaskCount : 仅按任务数停止
    //   kRuntime   : 仅按运行时间停止
    RunLimitMode run_limit_mode = RunLimitMode::kBoth;
    std::chrono::seconds runtime{20};
    uint64_t total_tasks = 5000;
    std::string mutator_policy;

    // [fixed request stream] see RunMode/ReplayConfig above.
    RunMode run_mode = RunMode::kFuzzing;
    ReplayConfig replay;
};

bool ParseConfig(const std::string& path, OrchestratorConfig& out);

} // namespace refuzz::orchestrator
