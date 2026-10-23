#pragma once

// [v3 Phase 4.3] IvshmemControlPlane — IControlPlane 的 ivshmem 实现（实现自持）
//
// 本阶段重大变化（相对 Phase 4.2）：
//   - 不再委托 Transport；会话握手/注册/取消/Reset 的**实现**全部内聚在本类
//   - 拥有 `worker_registered_[]` / `reg_epoch_` / `cancel_baseline_` 等状态权威
//   - 对外新增 `RegistrationControlHook`：让 DataPlane 的 Resume 可以按 guest
//     state 重建"可发送"视图（唯一的反向写通道；封装在闭包里，不暴露指针）
//
// 设计来源：docs/channel-redesign/v3/20_control_plane.md / 80_migration.md §5.5
//
// 生命周期：
//   - 构造：持 shared_ptr<IvshmemBackbone> + ShmInfra* + SessionTiming
//   - ResetSession → host_ready=0，worker_registered_[] 全清
//   - BeginSession / WaitAllWorkersReady → StartRegistration + per-worker 握手
//   - 析构：不主动清理 wire（本组件不拥有 shm 生命周期）
//
// 线程模型：
//   - BeginSession / WaitAllWorkersReady / ResetSession：Channel 主线程串行
//   - SampleHeartbeat / IsWorkerRegistered / RegistrationControlHook.set_registered：
//     可能被数据面或其他线程调用；worker_registered_[] 使用 atomic 元素，reg_epoch_ 串行
//   - cancel_baseline_ 用 mutex 保护

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/infra/ivshmem_backbone.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace refuzz::channel::control {

// [v3.5 Phase B] SessionTiming / RegistrationControlHook 定义已搬至中性头：
//   - control/session_timing.hpp
//   - control/registration_hook.hpp
// 本文件通过 control_plane.hpp 间接引入；新代码也应直接 include 上述中性头。

class IvshmemControlPlane final : public IControlPlane {
public:
    IvshmemControlPlane(std::shared_ptr<infra::IvshmemBackbone> backbone,
                        infra::ShmInfra*                         shm,
                        SessionTiming                            timing);
    ~IvshmemControlPlane() override;

    IvshmemControlPlane(const IvshmemControlPlane&)            = delete;
    IvshmemControlPlane& operator=(const IvshmemControlPlane&) = delete;

    // ── 会话生命周期 ─────────────────────────────────────────────
    Result<void> BeginSession() override;
    Result<void> WaitAllWorkersReady(std::chrono::milliseconds timeout) override;
    Result<void> WaitWorkerReady(uint32_t worker_id,
                                 std::chrono::milliseconds timeout) override;
    Result<void> ResetSession() override;
    Result<void> ResetWorkerSession(uint32_t worker_id) override;
    Result<void> ClearProcIsolationState() override;
    Result<void> EndSession() override;

    // ── 状态查询 ────────────────────────────────────────────────
    SessionState CurrentState() const override;
    uint32_t     RegisteredWorkerCount() const override;
    bool         IsWorkerRegistered(uint32_t worker_id) const override;

    // ── 配额 / 隔离 ─────────────────────────────────────────────
    void RevokeWorker(uint32_t worker_id) override;

    // ── Heartbeat ──────────────────────────────────────────────
    WorkerHeartbeatSample SampleHeartbeat(uint32_t worker_id) override;

    // ── Cancel ────────────────────────────────────────────────
    Result<void> RequestCancel(uint32_t worker_id, uint64_t executor_id) override;
    bool         ReadCancelAck(uint32_t worker_id, uint64_t executor_id) override;

    // ── SendabilityView 导出 ───────────────────────────────────
    SendabilityView GetSendabilityView() override;

    // ── DP 反向写通道（Phase B：升级为 IControlPlane 虚函数） ───────
    //
    // DataPlane 的 Resume 会扫 guest/host state，判定某 worker 是否"仍注册"，
    // 通过此 hook 把结果写回 CP 的 worker_registered_[]。
    RegistrationControlHook GetRegistrationHook() override;

    // ── 供 DP 使用的原始取值（Phase B：升级为 IControlPlane 虚函数） ─
    //
    // 这个方法**不走** baseline 机制，纯数据读；DP 的 SnapshotInflight 等需要
    // 原始 cancel_observed_seq 时用此接口。
    uint32_t ReadCancelObservedSeqRaw(uint32_t worker_id) const noexcept override;
    uint32_t ConsumeWorkerError(uint32_t worker_id) noexcept override;

    // ── 注册轮次 / 容量查询（Phase B：接口对齐） ────────────────────
    uint32_t RegistrationEpoch() const noexcept override { return reg_epoch_; }
    uint32_t MaxWorkerSlots()    const noexcept override { return n_workers_; }
    uint32_t WorkerCount()       const noexcept override { return n_workers_; }

    // ── 旧的 snake_case 访问器（保留以兼容外部诊断调用）─────────
    uint32_t reg_epoch() const noexcept { return reg_epoch_; }
    uint32_t n_workers() const noexcept { return n_workers_; }

private:
    // 执行 StartRegistration 的"写 host_ready / reg_epoch / 清零" 原子序列
    void InternalStartRegistration();

    Result<void> InternalClaimSingle(uint32_t worker_id,
                                     std::chrono::steady_clock::time_point deadline);
    Result<void> InternalWaitReadySingle(uint32_t worker_id,
                                         std::chrono::steady_clock::time_point deadline);

    std::shared_ptr<infra::IvshmemBackbone> backbone_;
    infra::ShmInfra*                        shm_;      // non-owning；调用方保证生命周期
    SessionTiming                           timing_;
    uint32_t                                n_workers_;

    // 会话状态机
    std::atomic<SessionState> state_{SessionState::kIdle};

    // 注册轮次（单线程写，Send/Poll 路径不读）
    uint32_t reg_epoch_ = 0;

    // worker 注册集合 + revoke 位
    // worker_registered_[i] == 1 表示 daemon owner claim 已被 host 接受；DP 仍以
    // GUEST_REG_READY 单独门控 task commit。Reset / Revoke 会清。
    std::vector<std::atomic<uint8_t>> worker_registered_;

    // revoke 标记（与 registered 解耦：revoke 代表 host 禁发，即使 guest 仍然 ready）
    std::vector<std::atomic<uint8_t>> revoked_;

    // Cancel ack baseline：per-worker baseline，ACK 语义 = observed_seq > baseline
    mutable std::mutex                     cancel_mu_;
    std::unordered_map<uint32_t, uint32_t> cancel_baseline_;
};

} // namespace refuzz::channel::control
