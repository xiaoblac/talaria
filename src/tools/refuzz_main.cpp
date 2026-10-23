// Copyright 2026 reFuzz project author -------youngkk.
//
// reFuzz 正式入口:JSON/CLI → LaunchPlan → Orchestrator。
// 用法: refuzz [config.json] [-- --profile xxx --mutator-engine yyy ...]

#include "refuzz/orchestrator/orchestrator.hpp"
#include "refuzz/startup/parse_launch_plan.hpp"

// [v2 PR-K-E2 — graceful shutdown 新增]
#include <atomic>
#include <csignal>
#include <cstring>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>

// [v2 PR-K-E2 — SIGINT/SIGTERM 触发 orch.RequestStop(),让主线程的 Stop()
// 跑完 SaveToFile / StopAndDrain / final metrics flush。第二次信号强退,
// 防 graceful 卡住。handler 内只做 async-signal-safe 操作:
//   - std::atomic<T*>::load / std::atomic<int>::fetch_add 在主流平台
//     是 lock-free,Linux x86_64 上等价于 mov+lock,signal-safe;
//   - ::write(2) 是 POSIX 明文规定 async-signal-safe;
//   - 不调任何 stdio (fprintf/std::cerr) —— 它们持锁,handler 触发会死锁。]
namespace {
std::atomic<refuzz::orchestrator::Orchestrator*> g_orch_for_signal{nullptr};
std::atomic<int> g_signal_count{0};

extern "C" void HandleShutdownSignal(int sig)
{
    const int n = g_signal_count.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (n == 1) {
        auto* orch = g_orch_for_signal.load(std::memory_order_acquire);
        if (orch != nullptr) {
            orch->RequestStop();
        }
        static const char kMsg[] =
            "\n[refuzz] received signal, requesting graceful stop "
            "(send signal again to force exit)\n";
        (void)::write(STDERR_FILENO, kMsg, sizeof(kMsg) - 1);
        return;
    }
    static const char kMsg2[] = "\n[refuzz] second signal, forcing exit\n";
    (void)::write(STDERR_FILENO, kMsg2, sizeof(kMsg2) - 1);
    // 128 + signo 是 shell 惯例的 "killed by signal N" 退出码。
    ::_exit(128 + sig);
}

void InstallShutdownSignalHandlers()
{
    struct sigaction sa{};
    sa.sa_handler = HandleShutdownSignal;
    ::sigemptyset(&sa.sa_mask);
    // 不设 SA_RESTART:让阻塞的 syscall (epoll_wait/poll/sleep) 立刻返回 EINTR,
    // 上层循环 check stop_requested 后及时退出。fuzzer_thread 内是 RunOnce
    // 循环,本身就 poll-based,EINTR 让它早 1 个 tick 退出。
    sa.sa_flags = 0;
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
}
} // namespace

int main(int argc, char** argv)
{
    const std::string config_path = argc > 1
        ? argv[1]
        : "/workspace/talaria/configs/phase5_sample_config.json";

    refuzz::startup::ParseOptions cli_opts;
    cli_opts.argc = std::max(0, argc - 2);
    cli_opts.argv = argc > 2 ? argv + 2 : nullptr;

    auto parsed = refuzz::startup::ParseLaunchPlan(config_path, cli_opts);
    if (!parsed) {
        std::cerr << "startup: " << parsed.error().message << "\n";
        return 1;
    }

    // [snapshot mode] No special-case here: when qemu.snapshot_fuzzing=true the
    // config parser sets channel_backend_id=qemu_ivshmem_snapshot_linux, so the
    // normal Orchestrator path builds the snapshot Channel via the catalog and the
    // continuous FuzzerLoop / corpus / crash / telemetry drive it unchanged.
    refuzz::orchestrator::Orchestrator orch;
    if (!orch.Build(std::move(parsed->plan),
                    std::move(parsed->ad_hoc_feedback_spec))) {
        return 1;
    }
    if (!orch.Start()) {
        return 1;
    }
    // [v2 PR-K-E2] Start() 之后才装 signal handler,避免 Start 失败时
    // 留下指向已析构 orch 的悬空指针(虽然此时 process 也准备退出,但
    // handler 在 atexit 序列中还可能被触发;严守"装则可用,卸则失效")。
    g_orch_for_signal.store(&orch, std::memory_order_release);
    InstallShutdownSignalHandlers();

    orch.WaitForCompletion();

    // 解除 signal → orch 的指针,Stop() 内可能跑 join + 大量 cleanup,
    // 此时再来信号应当走 default 行为(强退),不要再触发 RequestStop。
    g_orch_for_signal.store(nullptr, std::memory_order_release);

    return orch.Stop();
}
