#pragma once

// Health 子组件共享数据类型。
//
// [v3 Phase 1.A] 三类对外可见的数据类型（CrashKind / CrashFragment / CrashType）
// 的权威定义已上移至 refuzz::core::channel_contract；本文件保留兼容 alias。
// CrashEvent / CrashEventOrigin / HealthMonitorView 属于 health 内部诊断层，
// 继续在此定义。
//
// 中文注释：文件内顺序约束 —— CrashType → CrashKind → CrashFragment → CrashEvent
// → HealthMonitorView。别名在前，内部类型随后。

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace refuzz::channel {

// CrashType — alias，兼容 crash 子系统历史枚举名
using CrashType = refuzz::core::channel_contract::CrashType;

} // namespace refuzz::channel

namespace refuzz::channel::health {

// ============================================================
// CrashKind / CrashFragment — alias（权威定义在 core::channel_contract）
// ============================================================

using CrashKind     = refuzz::core::channel_contract::CrashKind;
using CrashFragment = refuzz::core::channel_contract::CrashFragment;

// ============================================================
// CrashEventOrigin — 事件生产者标识（health 内部诊断）
// ============================================================

// 多 Sensor 并行上报：每个生产者独立投递事件，health 层不做来源仲裁
enum class CrashEventOrigin : uint8_t {
    kHeartbeat,      // 心跳 Sensor：worker miss 达阈值
    kSerialEof,      // 串口 Sensor：serial 通道 EOF
    kSerialPattern,  // 串口 Sensor：匹配到 kernel crash pattern
    kVmLiveness,     // VM 存活 Sensor：IsAlive() 返回 false
    kHealthInternal, // 任意 Sensor 线程：不可恢复错误等（§18.9.1）
};

// ============================================================
// CrashEvent — health 侧统一原始事件（§18.4.1，health 内部诊断）
// ============================================================

// [v2 new-approach — 当前版本]
// 多事件 FIFO 队列，producer 持续输出，不丢弃后续 crash。
// QemuChannel 在消费时将其包装为 ChannelFaultEvent（补充编排上下文）。
struct CrashEvent {
    uint64_t event_id = 0;
    CrashEventOrigin origin = CrashEventOrigin::kHealthInternal;
    uint64_t vm_epoch = 0;
    uint64_t detected_ts_us = 0;
    CrashFragment fragment;
    std::string checker_name;   // 报故障的 checker 名称（§18.9.2）
    int         errno_value = 0;
    // [检测器 A 佐证分级] 这次死亡判定是"推断"还是"佐证"：
    //   - false（佐证）：qemu 进程退出、console 命中 panic/KASAN 等确凿事件 →
    //     recovery 必须立即 reboot，不受 recovery-window / cascade budget 阻尼。
    //   - true（推断）：聚合前进时钟冻结超 vm_dead_timeout 推断 VM 死、或队列退化
    //     阈值 → 受阻尼治理（自我放大的 liveness 误判才需要被压）。
    //   消费侧 Channel::HandleFault 读它，决定 RebootOrDamp 的 corroborated 入参。
    bool        inferred = false;
};

// ============================================================
// HealthMonitorView — 注入 HealthMonitor 的 QemuChannel 引用集合
// ============================================================
//
// [v3.5 Phase D/E] 改为指针存储，允许 Assembler 构造 HealthMonitor 时传入空 view；
//   Channel::Boot 再调用 HealthMonitor::BindChannelSignals(view) 完成注入。
//
// 使用时必须判空：HealthMonitor 内部仅在 Start 之后消费 loop_cv / vm_epoch，
// 而 Boot 必须在 Start 之前调用 BindChannelSignals。
struct HealthMonitorView {
    std::condition_variable*     loop_cv  = nullptr;
    const std::atomic<uint64_t>* vm_epoch = nullptr;
    std::function<void()>        wake_poller;
};

// ============================================================
// Sensor-facing 数据参数（yaml / Profile → HealthMonitorConfig 聚合）
// ============================================================
//
// 这些 struct 只承载字段，不被任何 Sensor 实现直接 include；
// Assembler 从 Profile 读出后在装配 Sensor 时按需 copy 到具体 SensorConfig。
// 命名以 Health 前缀强调"health 子系统公共数据"语义（非某个具体 checker 配置）。

struct HealthHeartbeatConfig {
    std::chrono::milliseconds poll_interval{1000};
    uint32_t miss_threshold = 3;
    uint32_t workers_per_round = 1;
    bool     capture_step_events = false;
};

struct HealthSerialWatcherConfig {
    uint32_t pre_context_lines  = 20;
    uint32_t post_context_lines = 60;
    bool     capture_step_events = false;
};

struct HealthVmLivenessConfig {
    std::chrono::milliseconds check_interval{1000};
    // [检测器 A] 聚合前进时钟冻结超此值且 qemu 仍在 → 推断 VM 死。死亡尺度，需 ≫ 最坏
    //   合法全局停顿（2 vCPU + KASAN 重 mount）；测试期调。Assembler 拷进 VmAliveSensorConfig。
    std::chrono::milliseconds vm_dead_timeout{30000};
};

} // namespace refuzz::channel::health
