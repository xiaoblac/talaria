#pragma once

#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/crash/infra/crash_context.hpp"

#include <string>
#include <vector>

namespace refuzz::crash {

// 单次执行结果（adapter/core 共享）
struct RunResult {
    bool crashed = false;
    std::string crash_title;
    std::string console_output;
    refuzz::channel::CrashType crash_type = refuzz::channel::CrashType::kUnknown;
    std::vector<uint8_t> output;
    bool timed_out = false;
    bool error = false;
    bool recovered_in_execute = false;
    CrashKind crash_kind = CrashKind::kUnknownIncident;
};

} // namespace refuzz::crash

