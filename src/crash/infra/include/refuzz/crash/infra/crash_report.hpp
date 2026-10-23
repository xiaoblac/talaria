#pragma once

#include "refuzz/channel/health/health_types.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::crash {

struct CrashReport {
    // 中文注释：Crash 现场统一使用 health 命名空间类型，避免旧兼容别名路径。
    refuzz::channel::health::CrashFragment fragment;
    uint64_t crash_hash = 0;
    std::vector<uint8_t> program_payload;
    std::chrono::system_clock::time_point timestamp{};
};

uint64_t HashCrash(const std::string& title,
                   const std::vector<uint8_t>& payload = {});

inline uint64_t HashCrashTitle(const std::string& title)
{
    return HashCrash(title, {});
}

} // namespace refuzz::crash

