#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::crash {

struct ReproConfig {
    bool enable = false;
    uint32_t dedicated_vm_count = 1;
    std::chrono::milliseconds execute_timeout{30000};
    std::string vmlinux_path;
    std::string addr2line_binary = "addr2line";
    size_t repro_queue_capacity = 64;
    // Repro reliability policy by name: "full" (default) / "fast_triage" / "deep".
    // Empty → keep the manager default ("full"). "full" runs the minimize stage;
    // "fast_triage" skips it (Extract→Reliability→Symbolize) with a lenient 0.0
    // re-run gate for crashes that only reproduce intermittently.
    std::string policy;
    // Crash-pipeline triage policy by name: "all_unique" (default) /
    // "high_severity" / "quota_0" / "actionable". Empty → keep the manager
    // default. XiUOS uses "actionable" so its wedge/worker-dead findings (not
    // just kKernelCrash) are enqueued for repro.
    std::string triage_policy;

    // Epic 4 PR-4-A — opt-in C reproducer stage.
    bool produce_c_reproducer            = false;
    bool try_compile_c_reproducer        = false;
    bool keep_c_source_on_build_failure  = true;
};

} // namespace refuzz::crash

