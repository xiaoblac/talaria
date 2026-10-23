#pragma once

// [v3 Phase 1.B] ExecPlan 三轴 — 恢复动作的正交分解
//
// 设计来源：docs/channel-redesign/v3/60_recovery.md §2.1
// 替代 v2 单枚举 RecoveryAction：
//   kNone → {}
//   kRestartSingleWorker → { session=Single, tw=X }
//   kRestartAllWorkers   → { session=All }
//   kRebootVm            → { session=All, substrate=Reboot }
//   kRestartHealthMonitor → { monitor=Restart }
//
// 旧 RecoveryAction 作为 telemetry alias 保留在 core/channel_contract.hpp。

#include <cstdint>

namespace refuzz::channel::recovery {

// SessionAction — 会话层动作
enum class SessionAction : uint8_t {
    kNone = 0,
    kRestartSingleWorker,   // 单 worker 会话重建（Substrate 不动）
    kRestartAllWorkers,     // 全量会话重建（Substrate 不动）
};

// SubstrateAction — 底座层动作
enum class SubstrateAction : uint8_t {
    kNone = 0,
    kRebootInstance,        // Substrate 级 Reboot（必然附带 session=All）
};

// MonitorAction — Health 监控层动作
enum class MonitorAction : uint8_t {
    kNone = 0,
    kRestartMonitor,        // HealthMonitor Stop + Start（不触碰 session / substrate）
};

// ExecPlan — 三轴组合
//
// 合规组合（其他组合 Execute 直接 assert / reject）：
//   {}
//   { session=Single,  target_worker_id=X }
//   { session=All }
//   { session=All,     substrate=Reboot }
//   { monitor=Restart }
//   { monitor=Restart, session=All }        // 允许；执行顺序 monitor → session
struct ExecPlan {
    SessionAction   session   = SessionAction::kNone;
    SubstrateAction substrate = SubstrateAction::kNone;
    MonitorAction   monitor   = MonitorAction::kNone;

    uint32_t target_worker_id = UINT32_MAX;  // session=Single 时有效
};

inline const char* SessionActionName(SessionAction a) noexcept
{
    switch (a) {
    case SessionAction::kNone: return "none";
    case SessionAction::kRestartSingleWorker: return "restart_single_worker";
    case SessionAction::kRestartAllWorkers: return "restart_all_workers";
    }
    return "unknown";
}

inline const char* SubstrateActionName(SubstrateAction a) noexcept
{
    switch (a) {
    case SubstrateAction::kNone: return "none";
    case SubstrateAction::kRebootInstance: return "reboot_instance";
    }
    return "unknown";
}

inline const char* MonitorActionName(MonitorAction a) noexcept
{
    switch (a) {
    case MonitorAction::kNone: return "none";
    case MonitorAction::kRestartMonitor: return "restart_monitor";
    }
    return "unknown";
}

} // namespace refuzz::channel::recovery
