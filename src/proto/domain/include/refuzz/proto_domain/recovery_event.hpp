#pragma once

#include "refuzz/proto_domain/fault_event.hpp"

#include <cstdint>
#include <string>

namespace refuzz::proto {

enum class RecoveryAction : uint8_t {
    kNone = 0,
    kRestartAllWorkers,
    kRebootVm,
    kFailChannel,
};

struct RecoveryEvent {
    uint64_t incident_id = 0;
    uint64_t trigger_fault_event_id = 0;
    uint32_t channel_id = 0;
    uint32_t slot_id = 0;
    uint32_t generation_before = 0;
    uint32_t generation_after = 0;

    // [v1 默认 kWorkerHeartbeatLost/kHealthMonitor — ROLLBACK]
    // FaultReason reason = FaultReason::kWorkerHeartbeatLost;
    // FaultSource source = FaultSource::kHealthMonitor;
    // [v2 PR-E 默认 kUnknown 与 FaultEvent 对齐 — 当前版本]
    // 同 FaultEvent: 漏填路径直接暴露成 "unknown",不伪装为合法 reason。
    FaultReason reason = FaultReason::kUnknown;
    FaultSource source = FaultSource::kUnknown;

    RecoveryAction recovery_action = RecoveryAction::kNone;
    bool success = false;
    uint64_t started_ts_us = 0;
    uint64_t completed_ts_us = 0;
    std::string error_message;
};

} // namespace refuzz::proto
