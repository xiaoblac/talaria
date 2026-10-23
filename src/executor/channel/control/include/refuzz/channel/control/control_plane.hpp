#pragma once

// [v3 Phase 1.B] IControlPlane — 会话管理 & worker 注册 & 心跳采样 & 取消旗
//
// 设计来源：docs/channel-redesign/v3/20_control_plane.md
// 职责：
//   - 会话生命周期：Begin/End/Reset/ResetWorker
//   - Worker 注册监控：RegisteredWorkerCount / IsWorkerRegistered / RevokeWorker
//   - 心跳采样面：SampleHeartbeat（HeartbeatSensor 使用）
//   - 取消旗：RequestCancel / ReadCancelAck
//   - 向 DataPlane 导出 SendabilityView（"能否向 wid 发"的只读视图，唯一耦合点）
//
// 非职责：不碰 shm wire 格式、不解释 console、不知道 RecoveryAction

#include "refuzz/channel/control/registration_hook.hpp"
#include "refuzz/channel/control/session_timing.hpp"
#include "refuzz/channel/result.hpp"
// WorkerSlotState：采样面把后端 wire 值翻成共享词汇。CP 天生是传输专属的
// （IvshmemControlPlane / XiuosUartControlPlane），做这层翻译正是它的职责 ——
// 也正因如此，HeartbeatSensor 才能保持"与具体 ivshmem/shm 协议解耦"。
#include "refuzz/core/channel_contract.hpp"

#include <chrono>
#include <cstdint>
#include <functional>

namespace refuzz::channel::control {

// SessionState — 会话状态（Channel 内部诊断；不进对外 schema）
enum class SessionState : uint8_t {
    kIdle = 0,        // 未 BeginSession
    kHandshaking,     // BeginSession 进行中 / 等待 worker 注册
    kReady,           // 至少一个 worker 已 ready
    kClosing,         // EndSession 进行中
    kClosed,          // 会话已关闭
    kFaulted,         // 会话异常（握手失败等）
};

// WorkerHeartbeatSample — 单次心跳采样结果
//
// 语义：
//   - valid=false：采样失败（worker 未注册 / backbone 不可读）
//   - valid=true：counter 与 sampled_ts_us 有效；HeartbeatSensor 自行维护 miss 计数
//
// [心跳重定义] counter 不再是"某个线程说我还活着"的自增计数，而是 **执行状态机的进度
//   令牌**：daemon 每推进一步（取到任务 / 发布结果 / 触发 watchdog 去轮换 domain /
//   domain 就绪），令牌就变。语义从"存在性"换成"进度"，对齐 syzkaller 用
//   `injectExec`/"executed programs:" 刷新 lastExecuteTime 的做法 —— host 从不向 guest
//   索要存活证明，只看它有没有干活。
//
//   为什么必须换：旧的自增计数由一个 SCHED_FIFO 线程写，而它 (1) 要求被检测方健康到
//   能自证，恰恰是要检测的东西不成立时最先失效；(2) 每 5s 往串口打一条 LOG，串口一
//   拥塞它就卡在自己的日志写上、吃满 vCPU —— 它自己就是故障源。进度令牌全部由已有的
//   执行路径顺手写在 shm 里，零额外线程、零串口、零 guest 开销。
//
//   counter 只被 sensor 做 `!=` 比较（变了=推进了），不要求单调、不解释数值。分量的
//   撕裂读是良性的：撕裂意味着 guest 正在写 = 它活着 = 令牌变 = 判"推进"，结论本就正确；
//   反之若无人推进，各分量稳定，令牌必然稳定。不会有"假死"。
struct WorkerHeartbeatSample {
    uint32_t worker_id = 0;
    uint64_t counter = 0;          // 进度令牌：执行状态机任一推进 → 变化（只做 != 比较）
    uint64_t sampled_ts_us = 0;    // host 侧采样时间戳
    bool     valid = false;
    // 令牌分量。既进判死日志，也经 HealthMonitor 快照上到面板 —— 它们回答 counter
    // 本身（一个不透明哈希）回答不了的问题：
    //
    //   proc_epoch  daemon 只要活着，程序 hang 到点必然去轮换 domain（+1）。所以
    //                 静默 + 它在涨 → daemon 活着，卡的是**被测程序**，正在自救
    //                 静默 + 它冻着 → 连自救都没做 → 卡的是 **daemon 自己**
    //               两者的正确处置完全不同，而心跳时代永远分不清。
    //   slot        取活循环是 1ms 级的（poll_ms=1），所以 kDispatched 停留哪怕一秒就
    //               意味着 daemon 没在 poll —— 一条不必等满判死阈值的快速旁证。
    //               语义值而非 wire 值：ivshmem 的 TASK_EMPTY/READY/TAKEN 由 CP 翻译。
    //   guest_state domain 就绪状态。
    refuzz::core::channel_contract::WorkerSlotState slot =
        refuzz::core::channel_contract::WorkerSlotState::kUnknown;
    uint32_t proc_epoch = 0;
    uint32_t guest_state = 0;      // GuestRegState: CLAIMED / READY / DEAD
};

// SendabilityView — Control → Data 的唯一耦合面（只读视图，lambda 闭包）
//
// 设计决定：不暴露 IControlPlane 指针给 IDataPlane，仅通过函数对象传递最小面
struct SendabilityView {
    std::function<bool(uint32_t /*worker_id*/)> is_registered;
    std::function<uint32_t()>                   registered_worker_count;
};

// IControlPlane — 控制面抽象（ivshmem / vsock / local pipe 实现不同）
class IControlPlane {
public:
    virtual ~IControlPlane() = default;

    // ───── 会话生命周期 ─────
    virtual Result<void> BeginSession() = 0;
    virtual Result<void> WaitAllWorkersReady(std::chrono::milliseconds timeout) = 0;
    virtual Result<void> WaitWorkerReady(uint32_t worker_id,
                                         std::chrono::milliseconds timeout) = 0;
    virtual Result<void> ResetSession() = 0;
    virtual Result<void> ResetWorkerSession(uint32_t worker_id) = 0;
    // Clears proc identities quarantined by abandoned execution domains. This
    // is a VM-lifetime operation and must run only after RebootVM succeeds.
    virtual Result<void> ClearProcIsolationState() = 0;
    virtual Result<void> EndSession() = 0;

    // ───── 状态查询 ─────
    virtual SessionState CurrentState() const = 0;
    virtual uint32_t     RegisteredWorkerCount() const = 0;
    virtual bool         IsWorkerRegistered(uint32_t worker_id) const = 0;

    // ───── 配额 / 隔离 ─────
    //
    // RevokeWorker：把 wid 从"可注册集合"中移除；本次会话内 worker_id=wid 的后续注册
    // 动作被拒绝（Sendability 立刻返回 false）。用于单 worker 隔离期。
    virtual void RevokeWorker(uint32_t worker_id) = 0;

    // ───── Heartbeat 采样面（HeartbeatSensor 唯一依赖） ─────
    virtual WorkerHeartbeatSample SampleHeartbeat(uint32_t worker_id) = 0;

    // ───── 取消旗（与 DataPlane 配合） ─────
    //
    // 语义：host 侧通过 Control 面发起"软取消"信号；具体 wire（如 ivshmem cancel_req
    // 寄存器）由实现决定。DataPlane 在 Poll 返回前读 ReadCancelAck 决定是否报
    // kCancelled。
    virtual Result<void> RequestCancel(uint32_t worker_id, uint64_t executor_id) = 0;
    virtual bool         ReadCancelAck(uint32_t worker_id, uint64_t executor_id) = 0;

    // ───── 向 DataPlane 导出的只读视图 ─────
    virtual SendabilityView GetSendabilityView() = 0;

    // ───── 向 DataPlane 导出的"可写"反向视图（Phase B 升级到接口） ─────
    //
    // 语义：让 DataPlane.Resume 在重建"可发送"视图时把 registered 标志写回 CP。
    // Noop/Mock 实现可返回空闭包（set_registered = nullptr）。
    virtual RegistrationControlHook GetRegistrationHook() = 0;

    // ───── 诊断 / 取消序列读取（Phase B 升级到接口） ─────
    //
    // ReadCancelObservedSeqRaw：DP 的 SnapshotInflight 等场景需要的原始 cancel 序列；
    //                         默认实现返回 0，适用于不需要 cancel 序列追踪的后端。
    // RegistrationEpoch：会话注册轮次；默认 0（无 re-registration 语义的后端可保持不变）。
    virtual uint32_t ReadCancelObservedSeqRaw(uint32_t /*worker_id*/) const noexcept {
        return 0;
    }
    // Atomically consumes a worker-level maintenance failure. Unlike a task
    // completion, this event has no executor_id and is delivered exactly once.
    virtual uint32_t ConsumeWorkerError(uint32_t /*worker_id*/) noexcept {
        return 0;
    }
    virtual uint32_t RegistrationEpoch() const noexcept {
        return 0;
    }

    // ───── 容量查询（Phase B 升级到接口） ─────
    //
    // MaxWorkerSlots：CP 侧已分配的 worker 槽位数（包含已 Revoke / 未注册的）。
    // WorkerCount：已分配且尚未 Revoke 的逻辑 worker 数（一般与 Channel 配置相同）。
    virtual uint32_t MaxWorkerSlots() const noexcept = 0;
    virtual uint32_t WorkerCount()    const noexcept = 0;
};

} // namespace refuzz::channel::control
