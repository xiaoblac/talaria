#pragma once

#include <cstdint>
#include <string>

namespace refuzz::core {

// [6b-3 — 当前版本] RuntimeSnapshot 缩至 3 字段, 其它数据走 MetricRegistry。
struct RuntimeSnapshot {
    uint64_t ts_us = 0;
    std::string policy_phase;
    uint64_t policy_switch_count = 0;
};

struct RuntimeEvent {
    enum class Kind : uint8_t {
        kFault,
        kRecoveryBegin,
        kRecoveryComplete,
        kPolicySwitch,
        kChannelStateChange,
    };

    uint64_t ts_us = 0;
    Kind kind = Kind::kFault;
    uint32_t channel_id = 0;
    uint64_t incident_id = 0;
    std::string subject;
    std::string from_state;
    std::string to_state;
    std::string detail;
};

} // namespace refuzz::core
