#pragma once

#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>

namespace refuzz::telemetry {

// 墙钟本地时间 → "HH:MM:SS"。只保留时分秒(周期性 dump 逐行递进,读的人要的是"几点几分",
// 不是完整日期)。localtime_r 线程安全;转换失败退化成 "??:??:??" 而不是崩。
// 供 CoverageMetricsSink / FuzzerStatsSink 等周期性磁盘 sink 共用,统一 t=<HH:MM:SS> 口径。
inline std::string FormatWallClockHms(std::chrono::system_clock::time_point tp)
{
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
    if (::localtime_r(&t, &tm_buf) == nullptr) {
        return "??:??:??";
    }
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return buf;
}

} // namespace refuzz::telemetry
