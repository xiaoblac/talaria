// Layer-3 reFuzz stdio worker profile entry.
//
// Protocol:
//   stdin:  uint32 LE length, then `length` bytes of syz exec wire
//   stdout: JSONL result per input program

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/coverage/coverage_collector.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/profile/worker_profile.hpp"
#include "worker/sandbox.hpp"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

#ifndef REFUZZ_EXECUTOR_DEFAULT_PATH
#define REFUZZ_EXECUTOR_DEFAULT_PATH ""
#endif

volatile sig_atomic_t g_running = 1;

namespace {

void signal_handler(int)
{
    g_running = 0;
}

bool ParseCoverageModeArg(const std::string& value, refuzz::worker::CoverageMode* out)
{
    if (out == nullptr) return false;
    if (value == "none") { *out = refuzz::worker::CoverageMode::kNone; return true; }
    if (value == "kcov") { *out = refuzz::worker::CoverageMode::kKcov; return true; }
    return false;
}

} // namespace

int main(int argc, char** argv)
{
    refuzz::worker::KernelSyzStdioArgs args;
    args.executor_path = REFUZZ_EXECUTOR_DEFAULT_PATH;
    bool enable_log = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--worker-id" && i + 1 < argc) {
            args.worker_id = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--coverage-mode" && i + 1 < argc) {
            if (!ParseCoverageModeArg(argv[++i], &args.coverage_mode)) {
                LOG("invalid coverage mode");
                return 2;
            }
        } else if (arg == "--sandbox" && i + 1 < argc) {
            if (!refuzz::worker::ParseSandboxMode(argv[++i], &args.sandbox_mode)) {
                LOG("invalid sandbox mode");
                return 2;
            }
        } else if (arg == "--exec-timeout-ms" && i + 1 < argc) {
            args.exec_timeout_ms =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--daemon-watchdog-ms" && i + 1 < argc) {
            // Explicit override; default 0 derives 3×exec_timeout_ms.
            args.daemon_watchdog_ms =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--recycle-after" && i + 1 < argc) {
            args.recycle_after =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--thread-count" && i + 1 < argc) {
            args.thread_count =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--max-input-size" && i + 1 < argc) {
            args.max_input_size =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--output-size" && i + 1 < argc) {
            args.output_size =
                static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--executor-path" && i + 1 < argc) {
            args.executor_path = argv[++i];
        } else if (arg == "--enable-worker-log") {
            enable_log = true;
        } else if (arg == "--debug-topology-probe") {
            ::setenv("REFUZZ_TOPOLOGY_PROBE", "1", 1);
            enable_log = true;
        } else if (arg == "--help" || arg == "-h") {
            std::fprintf(stderr,
                         "Usage: %s [--worker-id N] [--coverage-mode none|kcov] "
                         "[--sandbox none|setuid|namespace] "
                         "[--exec-timeout-ms N] [--daemon-watchdog-ms N (default 3x exec timeout)] "
                         "[--recycle-after N] "
                         "[--thread-count N] "
                         "[--max-input-size BYTES] [--output-size BYTES] "
                         "[--executor-path PATH] "
                         "[--enable-worker-log] [--debug-topology-probe]\n",
                         argv[0]);
            std::fprintf(stderr,
                         "Default stdio recycle-after is 1 to match syz-executor "
                         "stdio per-program process state.\n");
            return 0;
        } else {
            LOG("unknown argument: %s", arg.c_str());
            return 2;
        }
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGPIPE, SIG_IGN);

    if (enable_log) {
        refuzz::worker::log::EnableWorkerLog();
    }

    auto profile = refuzz::worker::MakeKernelSyzStdioProfile(args);
    return refuzz::worker::RunWorkerProfile(profile);
}
