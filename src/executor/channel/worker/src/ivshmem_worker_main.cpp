// Copyright 2026 reFuzz project author -------youngkk.
//
// ivshmem_worker 入口点：瘦组装层
// 逻辑分工：
//   - IvshmemWorkerAdapter (adapter/)：ivshmem 传输层（PCI发现/mmap/心跳/CAS/doorbell）
//   - ExecutionEngine (engine/)：通用主循环 + child 进程管理
//   - KernelChildDriver (driver/)：syscall 执行调度 (= SyzExecCodec + SyscallOrPseudoDispatcher)
//   - ObservationBus (observation/)：KCOV / step event 等多 sink 总线
//
// [R5] main 退化为 "解析 args → 选 profile factory → RunWorkerProfile"。
//      旧的逐组件构造路径全部 v1 注释保留供 ROLLBACK。
//      未来 family (AFL CLI / SQLite / V8 / ...) 加 profile = 加一个 factory + 在 switch 增一行。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/adapter/ivshmem_adapter.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/coverage/coverage_collector.hpp"      // [R2] (ROLLBACK 路径直接用)
#include "worker/coverage/kcov_collector.hpp"
#include "worker/dispatcher/syscall_or_pseudo.hpp"     // [R1]
#include "worker/engine/execution_engine.hpp"
#include "worker/env/env_probe.hpp"                        // [Step C] per-VM env probe
#include "worker/log/log_macros.hpp"
#include "worker/observation/ivshmem_step_event_sink.hpp"  // [R2]
#include "worker/observation/kcov_sink.hpp"                // [R2]
#include "worker/observation/observation_bus.hpp"          // [R2]
#include "worker/perf/worker_perf.hpp"
#include "worker/profile/worker_profile.hpp"               // [v2 R5]
#include "worker/sandbox.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>
#include <string>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

// [Exp A] --mm-dump-only:exec 完 worker binary 后,跳过所有 init,直接 dump
// /proc/self/maps 行数 + anon VMA 数 + smaps_rollup + status 到 stdout 后 exit。
// 给 dynamic vs static 链接 binary 做 A/B mm shape 对比用。
static void DumpMmAndExit()
{
    auto cat = [](const char* tag, const char* path) {
        std::printf("==== %s ====\n", tag);
        if (FILE* f = std::fopen(path, "r"); f != nullptr) {
            char buf[4096];
            size_t n;
            while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
                std::fwrite(buf, 1, n, stdout);
            }
            std::fclose(f);
        }
    };
    cat("maps", "/proc/self/maps");
    cat("smaps_rollup", "/proc/self/smaps_rollup");
    cat("status", "/proc/self/status");
    size_t maps_lines = 0, anon_vmas = 0;
    if (FILE* f = std::fopen("/proc/self/maps", "r"); f != nullptr) {
        char line[1024];
        while (std::fgets(line, sizeof(line), f) != nullptr) {
            ++maps_lines;
            char* tok = std::strtok(line, " \t\n");
            int col = 1;
            const char* inode = nullptr;
            const char* path  = nullptr;
            while (tok != nullptr) {
                if (col == 5) inode = tok;
                if (col == 6) { path = tok; break; }
                tok = std::strtok(nullptr, " \t\n");
                ++col;
            }
            if (inode != nullptr && std::strcmp(inode, "0") == 0 && path == nullptr) {
                ++anon_vmas;
            }
        }
        std::fclose(f);
    }
    std::printf("==== summary ====\nmaps_lines=%zu anon_vmas=%zu\n",
                maps_lines, anon_vmas);
    std::fflush(stdout);
    _exit(0);
}

// ==================== 全局运行标志 ====================
// adapter / engine 通过 extern 引用
volatile sig_atomic_t g_running = 1;

namespace {

enum class SanitizerMode : uint8_t {
    kNone = 0,
    kKasan,
    kKcsan,
    kUbsan,
};

void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

bool ParseCoverageModeArg(const std::string& value, refuzz::worker::CoverageMode* out)
{
    if (out == nullptr) return false;
    if (value == "none") { *out = refuzz::worker::CoverageMode::kNone; return true; }
    if (value == "kcov") { *out = refuzz::worker::CoverageMode::kKcov; return true; }
    return false;
}

bool ParseSanitizerModeArg(const std::string& value, SanitizerMode* out)
{
    if (out == nullptr) return false;
    if (value == "none")  { *out = SanitizerMode::kNone;  return true; }
    if (value == "kasan") { *out = SanitizerMode::kKasan; return true; }
    if (value == "kcsan") { *out = SanitizerMode::kKcsan; return true; }
    if (value == "ubsan") { *out = SanitizerMode::kUbsan; return true; }
    return false;
}

const char* SanitizerModeName(SanitizerMode mode)
{
    switch (mode) {
    case SanitizerMode::kKasan: return "kasan";
    case SanitizerMode::kKcsan: return "kcsan";
    case SanitizerMode::kUbsan: return "ubsan";
    case SanitizerMode::kNone:
    default: return "none";
    }
}

} // namespace

// ==================== main: 瘦组装点 ====================
int main(int argc, char** argv)
{
    // [Exp A] argv 扫到 --mm-dump-only 立即 dump + exit;不跑任何 init。
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--mm-dump-only") == 0) {
            DumpMmAndExit();
        }
    }

    // ---- 1. 参数解析 ----
    uint32_t worker_id = 0;
    uint32_t vm_id = 0;
    int peer_id = 1;
    int poll_ms = 1;
    uint32_t exec_timeout_ms = 5000;
    // 0 derives syzkaller's outer 3×exec-timeout watchdog.
    uint32_t daemon_watchdog_ms = 0;
    uint32_t domain_startup_timeout_ms =
        refuzz::worker::topology::kDefaultDomainStartupTimeoutMs;
    uint32_t recycle_after = 600;
    refuzz::worker::CoverageMode coverage_mode = refuzz::worker::CoverageMode::kKcov;
    SanitizerMode sanitizer_mode = SanitizerMode::kNone;
    refuzz::worker::SandboxMode sandbox_mode = refuzz::worker::SandboxMode::kNone;
    bool enable_log = false;       // --enable-worker-log：控制 WorkerLog 输出到 /dev/ttyS0
    bool enable_step_events = false;
    bool snapshot_mode = false;        // [Brick 4a] --snapshot: single-process in-place snapshot loop
    uint32_t thread_count = 1;     // [v2 Epic 7 PR-4] --thread-count N: KCOV per-thread fd 池 (1 = serial only)
    uint32_t kcov_entries = static_cast<uint32_t>(refuzz::worker::kDefaultKcovEntries);
    // [当前版本 kcov-pool-config / per-call-timeout-config] 0 留给 profile factory 走默认。
    uint32_t kcov_collector_count = 0;
    uint32_t kcov_premap_count    = 0;
    uint32_t per_call_timeout_ms  = 0;
    bool worker_perf = false;
    uint32_t worker_perf_sample = 1;
    uint32_t worker_perf_report_every = 256;
    bool debug_mount_timing = false;
    bool debug_topology_probe = false;
    // b15 cold-VM warmup. When set, worker opens+closes a hardcoded set of
    // common /dev/* paths once before accepting tasks. Goal: warm VFS /
    // dentry / page cache so the FIRST syz_open_dev$* request in the
    // replayed trace doesn't pay cold-path KCOV cost that syz-manager's
    // pre-fuzz feature probing already absorbed on the capture side.
    // Purely diagnostic / oracle-side; production worker leaves it off.
    bool warmup_devices = false;
    std::string metric_dump_path; // [FUP-METRIC-VM 2026-05-10] --metric-dump-path PATH (支持 {worker_id} 占位符)
    std::string pseudo_workdir;
    std::string pseudo_run_id;
    std::string profile_name = "kernel-syz";  // [v2 R5] 默认 profile;未来 family 通过 --profile= 选
    // After V1 retirement the worker accepts only the syzkaller-equivalent
    // varint exec wire (Layer-2 §3.3) streamed straight into KernelWireDriver.
    refuzz::worker::KernelSyzArgs::DriverKind driver_kind =
        refuzz::worker::KernelSyzArgs::DriverKind::kWire;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](uint32_t& out) {
            if (i + 1 >= argc) return false;
            out = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
            return true;
        };
        if (arg == "--worker-id" && i + 1 < argc) {
            next(worker_id);
        } else if (arg == "--vm-id" && i + 1 < argc) {
            next(vm_id);
        } else if (arg == "--peer-id" && i + 1 < argc) {
            peer_id = static_cast<int>(strtol(argv[++i], nullptr, 10));
        } else if (arg == "--poll-ms" && i + 1 < argc) {
            poll_ms = atoi(argv[++i]);
        } else if (arg == "--coverage-mode" && i + 1 < argc) {
            if (!ParseCoverageModeArg(argv[++i], &coverage_mode)) {
                LOG("invalid coverage mode");
                return 2;
            }
        } else if (arg == "--sanitizer-mode" && i + 1 < argc) {
            if (!ParseSanitizerModeArg(argv[++i], &sanitizer_mode)) {
                LOG("invalid sanitizer mode");
                return 2;
            }
        } else if (arg == "--sandbox" && i + 1 < argc) {
            if (!refuzz::worker::ParseSandboxMode(argv[++i], &sandbox_mode)) {
                LOG("invalid sandbox mode");
                return 2;
            }
        } else if (arg == "--exec-timeout-ms" && i + 1 < argc) {
            exec_timeout_ms = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--daemon-watchdog-ms" && i + 1 < argc) {
            // Explicit override; default 0 derives 3×exec_timeout_ms.
            daemon_watchdog_ms =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--domain-startup-timeout-ms" && i + 1 < argc) {
            domain_startup_timeout_ms =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--recycle-after" && i + 1 < argc) {
            recycle_after = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--enable-worker-log") {
            enable_log = true;
        } else if (arg == "--worker-perf") {
            worker_perf = true;
        } else if (arg == "--worker-perf-sample" && i + 1 < argc) {
            worker_perf_sample =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--worker-perf-report-every" && i + 1 < argc) {
            worker_perf_report_every =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--enable-step-events") {
            enable_step_events = true;
        } else if (arg == "--snapshot") {
            // [Brick 4a] dedicated snapshot worker mode: single process, no
            // per-program fork, spin-wait on TaskSlot + in-place execute (syz
            // snapshot.h model). Host (qemu_ivshmem_snapshot_linux backend) takes
            // savevm S0 after the worker registers ready, then drives per-program
            // loadvm. See docs/plans/snapshot-brick4a-worker.md.
            snapshot_mode = true;
        } else if (arg == "--debug-smaps") {
            // [debug instrumentation] LoopRuntime 进 main loop 前 dump
            // /proc/self/smaps 紧凑摘要 + fd 数到 ttyS0,定位 fork_avg 成本来源。
            // 走 setenv 喂给 loop_runtime.cpp 的 ShouldDumpStartupSmaps()。
            ::setenv("REFUZZ_DEBUG_SMAPS", "1", 1);
        } else if (arg == "--debug-empty-fork") {
            // [debug instrumentation] ForkingProgramExecutor child 分支跳过
            // ProgramRuntimeRunInline,只 commit 空 result page 并 _exit。给
            // 纯 fork+exit floor 量底。走 setenv 喂给 program_runtime.cpp。
            ::setenv("REFUZZ_EMPTY_FORK_BENCH", "1", 1);
        } else if (arg == "--debug-mount-timing") {
            // [debug instrumentation] syz_mount_image / loop reset timing
            // line trace. 走 env 喂给 mount_helpers / execution_engine,并在
            // logging setup 处强制打开 WorkerLog。
            debug_mount_timing = true;
        } else if (arg == "--debug-topology-probe") {
            // [debug instrumentation] double-fork topology evidence:
            // loop/program child identity, cgroup pids, and post-exit cleanup.
            debug_topology_probe = true;
        } else if (arg == "--warmup-devices") {
            // b15 cold-VM warmup; see decl above.
            warmup_devices = true;
        } else if (arg == "--thread-count" && i + 1 < argc) {
            // [v2 Epic 7 PR-4] worker 内 KCOV per-thread fd 池大小。
            //   1 (default) → driver Execute 走 serial fast path,KCOV
            //                 行为与 Epic 7 PR-1~PR-3 完全等价。
            //   >1          → driver 构造 KernelThreadPool,IntraTaskMode::
            //                 kThreaded task 由 worker thread 调度;
            //                 kSerial task 仍走 serial path。
            //                 上限 32 (profile 内钳)。
            // host 端在 OrchestratorConfig.target 加同名字段后,
            // config_parser 透传到 worker_start_cmd 此处。
            thread_count = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--kcov-entries" && i + 1 < argc) {
            const unsigned long value = strtoul(argv[++i], nullptr, 10);
            if (value < refuzz::worker::kMinKcovEntries ||
                value > refuzz::worker::kMaxKcovEntries) {
                LOG("invalid --kcov-entries %lu (supported range: %zu..%zu)",
                    value,
                    refuzz::worker::kMinKcovEntries,
                    refuzz::worker::kMaxKcovEntries);
                return 2;
            }
            kcov_entries = static_cast<uint32_t>(value);
        } else if (arg == "--kcov-collector-count" && i + 1 < argc) {
            // [当前版本 kcov-pool-config] 见 KernelSyzArgs::kcov_collector_count。
            // 0 = 走 profile 默认(8)。
            kcov_collector_count =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--kcov-premap-count" && i + 1 < argc) {
            // [当前版本 kcov-pool-config] 见 KernelSyzArgs::kcov_premap_count。
            // 0 = 走 profile 默认(3)。
            kcov_premap_count =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--per-call-timeout-ms" && i + 1 < argc) {
            // [当前版本 per-call-timeout-config] threaded path 内 WaitCallDone
            // 超时。0 = 走 profile 默认(5000)。
            per_call_timeout_ms =
                static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--metric-dump-path" && i + 1 < argc) {
            // [FUP-METRIC-VM 2026-05-10] host 端 OrchestratorConfig.target.metric_dump_path
            // 非空时由 config_parser 注入到 worker_start_cmd。Path 支持 {worker_id}
            // 占位符;空字符串等价于禁用 dump。worker child 把该值流入 KernelSyzArgs
            // → WorkerProfile,在 RunWorkerProfile 末尾(engine.Run 后)替代 getenv
            // 触发 dump (env fallback 仍保留给 host-side dev / unit-test)。
            metric_dump_path = argv[++i];
        } else if (arg == "--pseudo-workdir" && i + 1 < argc) {
            pseudo_workdir = argv[++i];
        } else if (arg == "--pseudo-run-id" && i + 1 < argc) {
            pseudo_run_id = argv[++i];
        } else if (arg == "--profile" && i + 1 < argc) {
            profile_name = argv[++i];
        } else if (arg == "--driver" && i + 1 < argc) {
            std::string v = argv[++i];
            if (v == "wire" || v == "syz-exec-wire") {
                driver_kind = refuzz::worker::KernelSyzArgs::DriverKind::kWire;
            } else {
                LOG("invalid driver: %s (expected wire)", v.c_str());
                return 2;
            }
        } else if (arg == "--help" || arg == "-h") {
            fprintf(stderr,
                    "Usage: %s --worker-id N [--vm-id N] [--peer-id N] [--poll-ms N] "
                    "[--profile NAME (default: kernel-syz)] "
                    "[--driver wire (default: wire)] "
                    "[--coverage-mode MODE] [--sanitizer-mode MODE] "
                    "[--sandbox none|setuid|namespace] "
                    "[--exec-timeout-ms N] [--daemon-watchdog-ms N (default 3x exec timeout)] "
                    "[--domain-startup-timeout-ms N (default 60000)] "
                    "[--recycle-after N] "
                    "[--enable-worker-log] [--enable-step-events] "
                    "[--worker-perf] [--worker-perf-sample N] "
                    "[--worker-perf-report-every N] "
                    "[--debug-smaps] [--debug-empty-fork] [--debug-mount-timing] "
                    "[--debug-topology-probe] "
                    "[--warmup-devices] "
                    "[--thread-count N (default: 1; >1 enables threaded KCOV path)] "
                    "[--kcov-entries N (default: 524288; range: 1024..524288)] "
                    "[--kcov-collector-count N (default: 8)] "
                    "[--kcov-premap-count N (default: 3)] "
                    "[--per-call-timeout-ms N (default: 5000)] "
                    "[--metric-dump-path PATH (supports {worker_id} placeholder)] "
                    "[--pseudo-workdir DIR --pseudo-run-id ID]\n",
                    argv[0]);
            return 0;
        } else {
            LOG("unknown argument: %s", arg.c_str());
            return 2;
        }
    }

    // ---- 2. 信号处理 + 日志开关 ----
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    refuzz::worker::perf::Configure(worker_perf,
                                    worker_perf_sample,
                                    worker_perf_report_every);
    if (debug_mount_timing) {
        ::setenv("REFUZZ_MOUNT_TIMING_DIAG", "1", 1);
        enable_log = true;
    }
    if (debug_topology_probe) {
        ::setenv("REFUZZ_TOPOLOGY_PROBE", "1", 1);
        enable_log = true;
    }
    if (enable_log || refuzz::worker::perf::Enabled()) {
        refuzz::worker::log::EnableWorkerLog();
    }

    if (!pseudo_workdir.empty() && !pseudo_run_id.empty()) {
        const uint32_t reclaimed = refuzz::worker::ReclaimStalePseudoRuntimeRoots(
            pseudo_workdir + "/pseudo/linux-amd64", pseudo_run_id);
        if (reclaimed != 0) {
            LOG("pseudo startup cleanup reclaimed=%u", reclaimed);
        }
    }

    // b15: warm the kernel's VFS/dentry/page caches before forking children
    // so the first replayed syz_open_dev$* doesn't pay cold-path KCOV cost.
    // syz-manager-side captures benefit from feature-probing that touches
    // the same dentry tree; replayer-side starts cold, and the resulting
    // dentry-walk + page-fault PCs show up only on the ref side (b14 finding:
    // 34/42 low-band are syz_open_dev$*, ref_cov ~8-12× syz_cov).
    //
    // Strategy: walk a handful of /dev subtrees with opendir+readdir+stat.
    // stat() warms the dentry + inode cache without holding fds (open on a
    // char device can block / SIGIO / change device state). Failed lookups
    // still walk the parent dir, so e.g. /dev/snd that's empty on this image
    // is cheap. This covers /dev/snd/midiCNDM, /dev/dri/cardN, etc. that the
    // earlier fixed-path warmup missed (b15 first iteration only opened
    // (card=0, device=0) and left other indices cold).
    // [Step C] Per-VM startup work — warmup + env probe — runs ONCE on the
    // designated init worker (worker_id 0). The environment (kernel/rootfs/
    // sandbox) is shared by all workers in this VM, so workers 1..N-1 skip both
    // (avoids N redundant probes + N-way /dev contention).
    const bool vm_init_worker = (worker_id == 0);

    if (warmup_devices && vm_init_worker) {
        static const char* kWarmupDirs[] = {
            "/dev/snd",
            "/dev/dri",
            "/dev/input",
            "/dev/bus/usb",  // contains BUSID dirs; one-level recurse below
            "/dev",          // top-level char devices: loop*, vcsa*, video*,
                             // rtc*, hidraw*, midi*, audio*, cec*, etc.
        };
        unsigned dirs_seen = 0, entries_seen = 0, stat_hits = 0;
        auto warm_dir = [&](const char* path, int depth) {
            DIR* d = ::opendir(path);
            if (d == nullptr) return;
            ++dirs_seen;
            char buf[512];
            struct dirent* ent;
            while ((ent = ::readdir(d)) != nullptr) {
                if (ent->d_name[0] == '.') continue;
                ++entries_seen;
                std::snprintf(buf, sizeof(buf), "%s/%s", path, ent->d_name);
                struct stat st;
                if (::stat(buf, &st) == 0) ++stat_hits;
                // /dev/bus/usb: depth=0 entries are BUSID dirs (001, 002, ...).
                // Recurse one level so /dev/bus/usb/001/001-style devices are
                // also stat'd. depth limited to avoid runaway on weird mounts.
                if (depth == 0 && ent->d_type == DT_DIR) {
                    DIR* sub = ::opendir(buf);
                    if (sub != nullptr) {
                        ++dirs_seen;
                        struct dirent* sub_ent;
                        while ((sub_ent = ::readdir(sub)) != nullptr) {
                            if (sub_ent->d_name[0] == '.') continue;
                            ++entries_seen;
                            char sub_buf[512];
                            std::snprintf(sub_buf, sizeof(sub_buf),
                                          "%s/%s", buf, sub_ent->d_name);
                            struct stat sst;
                            if (::stat(sub_buf, &sst) == 0) ++stat_hits;
                        }
                        ::closedir(sub);
                    }
                }
            }
            ::closedir(d);
        };
        for (const char* d : kWarmupDirs) warm_dir(d, 0);
        LOG("warmup_devices: dirs=%u entries=%u stat_ok=%u",
            dirs_seen, entries_seen, stat_hits);
    }

    // [syscall-support-detection Step C] Per-VM environment probe (worker-0
    // only). Result is per-VM (same kernel/rootfs/sandbox for all workers). C4
    // publishes it into the ivshmem ShmHeader for the host to fold into
    // SupportEnv + rebuild the ChoiceTable; for now we probe + log so the path
    // is exercised in the live VM.
    if (vm_init_worker) {
        ::EnvFeatures ef;
        refuzz::worker::env::ProbeEnvFeatures(&ef);
        unsigned fs_count = 0;
        for (uint32_t k = 0; k < ef.filesystems_len; ++k) {
            if (ef.filesystems[k] == '\n') ++fs_count;
        }
        LOG("env_probe: fs=%u flags=0x%x raw_gadget=%d kvm=%d tun=%d "
            "kernel=%u.%u lsm_present=%d lsm_len=%u",
            fs_count, ef.flags,
            env_features_has_flag(&ef, ENV_FEAT_RAW_GADGET) ? 1 : 0,
            env_features_has_flag(&ef, ENV_FEAT_KVM) ? 1 : 0,
            env_features_has_flag(&ef, ENV_FEAT_TUN) ? 1 : 0,
            ef.kernel_major, ef.kernel_minor,
            env_features_has_flag(&ef, ENV_FEAT_LSM_PRESENT) ? 1 : 0,
            ef.lsm_len);
    }

    // [v2 R5 — 当前版本: profile factory + RunWorkerProfile 通用入口] -------------------
    // 解析 family,装配 profile (含 sandbox 预检 / Init / late sink / engine / Run / Cleanup)
    LOG("worker %u sanitizer_mode=%s profile=%s",
        worker_id,
        SanitizerModeName(sanitizer_mode),
        profile_name.c_str());

    refuzz::worker::WorkerProfile profile;
    if (profile_name == "kernel-syz") {
        refuzz::worker::KernelSyzArgs syz_args;
        syz_args.worker_id = worker_id;
        syz_args.vm_id = vm_id;
        syz_args.peer_id = peer_id;
        syz_args.poll_ms = poll_ms;
        syz_args.exec_timeout_ms = exec_timeout_ms;
        // [D12 plan §3] CLI override 透传;未传时保留 KernelSyzArgs 默认 60s。
        syz_args.daemon_watchdog_ms = daemon_watchdog_ms;
        syz_args.domain_startup_timeout_ms = domain_startup_timeout_ms;
        syz_args.recycle_after = recycle_after;
        syz_args.coverage_mode = coverage_mode;
        syz_args.sandbox_mode = sandbox_mode;
        syz_args.enable_step_events = enable_step_events;
        syz_args.enable_worker_log = enable_log;
        syz_args.enable_worker_perf = worker_perf;
        syz_args.worker_perf_sample_rate = worker_perf_sample;
        syz_args.worker_perf_report_every = worker_perf_report_every;
        syz_args.driver_kind = driver_kind;
        syz_args.snapshot = snapshot_mode;       // [Brick 4a]
        syz_args.thread_count = thread_count;    // [v2 Epic 7 PR-4]
        syz_args.kcov_entries = kcov_entries;
        // [当前版本 kcov-pool-config / per-call-timeout-config] 0 在 profile
        // factory / KcovSink / KernelWireDriver 内分别回退到默认值;CLI 未
        // 显式传时不破坏向后兼容。
        if (kcov_collector_count != 0) {
            syz_args.kcov_collector_count = kcov_collector_count;
        }
        if (kcov_premap_count != 0) {
            syz_args.kcov_premap_count = kcov_premap_count;
        }
        if (per_call_timeout_ms != 0) {
            syz_args.per_call_timeout_ms = per_call_timeout_ms;
        }
        syz_args.metric_dump_path = metric_dump_path;  // [FUP-METRIC-VM]
        profile = refuzz::worker::MakeKernelSyzProfile(syz_args);
    } else {
        // TODO(R5+): 加入 afl-cli / db-sqlite / browser / ... 的 factory
        LOG("unknown profile=%s (only kernel-syz registered)", profile_name.c_str());
        return 2;
    }

    return refuzz::worker::RunWorkerProfile(profile);
}
