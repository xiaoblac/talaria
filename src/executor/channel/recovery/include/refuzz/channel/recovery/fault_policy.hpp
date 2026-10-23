#pragma once

// IFaultPolicy — 可插拔故障策略接口
//
// 将策略决策从 ChannelFaultTracker 中分离：
//   - IFaultPolicy 决定"做什么"（RecoveryAction + AbortScope）
//   - ChannelFaultTracker 负责"机制"（状态管理、event_id、计数、窗口衰减）
//
// 依赖链：recovery_vocab.hpp → recovery_types.hpp → fault_policy.hpp（本文件）
// 本文件通过包含 recovery_types.hpp 获取：
//   - recovery_vocab.hpp 中的枚举（ChannelFaultReason / RecoveryAction / ChannelAbortScope）
//   - recovery_types.hpp 中的 PolicySnapshot（IFaultPolicy::GetSnapshot 返回类型）
#include "refuzz/channel/recovery/recovery_types.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace refuzz::channel::recovery {

// ============================================================
// FaultHistory — 传给策略的机制层统计快照
// ============================================================

struct FaultHistory {
    uint32_t runtime_restart_count = 0;   // 当前窗口内
    uint32_t vm_reboot_count = 0;
    uint32_t consecutive_healthy = 0;
    uint64_t last_fault_ts_us = 0;
    uint32_t source_worker_failed_recovery_count = 0; // 当前窗口内 source worker 恢复失败次数
    // [级联断路] reboot 后的保护窗内（workers 还在重新注册）：心跳路径一律 kNone，
    //   重新注册延迟是预期的、不算故障。由 FaultTracker 维护 recovery_window_until_us。
    bool     in_recovery_window        = false;
    // [级联断路] 一个 cascade 窗（默认 120s）内已发生的**基础设施故障** reboot 数
    //   （真 kernel crash 的 reboot 不计入，见 fault_tracker CompleteRecovery）。
    //   **不随单次成功 reboot 清零**——只按时间或恢复后的健康连续衰减。
    //   RebootOrDamp 用它封顶。
    uint32_t reboots_in_cascade_window = 0;
};

// ============================================================
// FaultContext — 故障上下文（由 Channel 提供）
// ============================================================

struct FaultContext {
    uint32_t source_worker_id = UINT32_MAX;
    uint32_t total_workers = 0;
    uint32_t unusable_workers = 0;
    // [佐证分级] 这次 VM 级故障是"佐证"(qemu 退 / console 命中 panic·KASAN) 还是
    //   "推断"(聚合前进时钟冻结超 vm_dead_timeout / 队列退化阈值)。Channel 从
    //   CrashEvent.inferred + reason 推出后填入。RebootOrDamp 据此决定是否绕过阻尼：
    //   佐证 → 立即 reboot（确凿事件不能被 recovery-window / cascade budget 拖延）；
    //   推断 → 受阻尼治理（自我放大的 liveness 误判才需要被压）。
    bool     corroborated = false;
};

// ============================================================
// PolicyDecision — 策略层返回的决策
// ============================================================

struct PolicyDecision {
    cc::RecoveryAction    action = cc::RecoveryAction::kNone;
    cc::ChannelAbortScope abort_scope = cc::ChannelAbortScope::kNone;
    uint32_t target_worker_id = UINT32_MAX; // [v2] 单 worker 恢复目标，UINT32_MAX 表示全通道
};

// ============================================================
// IFaultPolicy — 策略接口
// ============================================================

class IFaultPolicy {
public:
    virtual ~IFaultPolicy() = default;

    /// @brief 根据故障原因和历史统计决定恢复动作
    virtual PolicyDecision Decide(cc::ChannelFaultReason reason,
                                  const FaultHistory& history,
                                  const FaultContext& context) = 0;

    /// @brief 恢复完成后通知策略（供策略更新内部状态）
    virtual void OnRecoveryComplete(cc::ChannelFaultReason reason,
                                    cc::RecoveryAction action,
                                    bool success) = 0;

    /// @brief 重置策略内部状态
    virtual void Reset() = 0;

    /// @brief 返回当前策略名称 + 参数快照（动态调整后立即反映）
    ///
    /// Recovery::GetSnapshot() 调用此接口，将策略配置并入 RecoverySnapshot，
    /// 使观察者可以同时看到"已用了几次"（机制状态）和"上限是多少"（策略参数）。
    /// 实现应为 const、无副作用、线程安全（与 Decide 可能并发）。
    virtual cc::PolicySnapshot GetSnapshot() const = 0;
};

// ============================================================
// EscalationPolicy — 默认升级策略
// ============================================================
// 升级路径：kRestartAllWorkers → kRebootVm → kFailChannel
// 窗口内逐步升级；替换 policy 实例即可实验其他策略。

class EscalationPolicy : public IFaultPolicy {
public:
    struct Config {
        uint32_t max_runtime_restart_attempts = 3;
        uint32_t max_vm_reboot_attempts = 2;
        uint32_t max_single_worker_restart_attempts = 3;
        // 掉的 worker 占比达到此阈值 → 一次 reboot 收回全队（不在 N-1 上瘸着跑）。
        uint32_t unusable_ratio_reboot_threshold_pct = 50;
        // [级联断路] 一个 cascade 窗内允许的**基础设施故障** reboot 数上限；超过 →
        //   推断型退避（kNone）、佐证型放弃通道（kFailChannel）。真 kernel crash
        //   （kKernelCrash）是发现不是故障，不消耗本预算，见 RebootOnKernelCrash。
        uint32_t cascade_reboot_budget = 2;
    };

    EscalationPolicy() = default;
    explicit EscalationPolicy(Config config) : config_(config) {}

    PolicyDecision Decide(cc::ChannelFaultReason reason,
                          const FaultHistory& history,
                          const FaultContext& context) override;

    void OnRecoveryComplete(cc::ChannelFaultReason reason,
                            cc::RecoveryAction action,
                            bool success) override;

    void Reset() override;

    /// @brief 返回 "escalation" + 当前 Config 字段的直接投影
    cc::PolicySnapshot GetSnapshot() const override;

private:
    Config config_;
};

// ============================================================
// RecoveryConfig — 统一配置收口（机制层 + 策略层）
// ============================================================
// 定义在本文件末尾：依赖 EscalationPolicy::Config 和 IFaultPolicy，
// 必须在两者定义之后出现；recovery_types.hpp 不包含本文件，故不能在那里定义。

struct RecoveryConfig {
    struct Mechanism {
        // [2026-05-13] 60000 → 600000：必须 > boot_timeout=180000ms，否则
        // 每次 reboot 失败间的 wall-time 间隔都触发 MaybeDecayWindow 清零
        // vm_reboot_count，导致永远 escalate 不到 kFailChannel 而死循环。
        // 详见 fault_tracker.hpp 同字段注释。
        uint32_t fault_window_ms         = 600000;
        uint32_t healthy_streak_to_reset = 8;
        // [级联断路] 透传给 FaultTrackerConfig 的保护窗 / cascade 窗参数（测试期可调）。
        uint32_t recovery_window_base_ms = 90000;
        uint32_t recovery_window_cap_ms  = 600000;
        uint32_t cascade_window_ms       = 120000;
    };

    struct Policy {
        EscalationPolicy::Config escalation;
        // 可选策略工厂，为空时默认构造 EscalationPolicy(escalation)
        std::function<std::unique_ptr<IFaultPolicy>(const EscalationPolicy::Config&)> factory;
    };

    Mechanism mechanism;
    Policy    policy;
};

} // namespace refuzz::channel::recovery
