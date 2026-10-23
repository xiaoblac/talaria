#pragma once

// [v3 Phase 4.3] IvshmemDataPlane — IDataPlane 的 ivshmem 实现（实现自持）
//
// 本阶段相对 Phase 4.2 的变化：
//   - 不再委托 Transport；send/recv/poll/doorbell 的**实现**完全内聚本类
//   - 拥有 paused_ / closed_ / doorbell_fd_ / doorbell_epollfd_ / stop_eventfd_ /
//     doorbell_notify_fds_ / doorbell_server_ 等数据面状态权威
//   - 通过 SendabilityView 只读问 CP "wid 是否可发"；通过 RegistrationControlHook
//     在 Resume 时按 guest/host state 回写 registered 集合
//
// 设计来源：docs/channel-redesign/v3/30_data_plane.md / 80_migration.md §5.6

// [v3.5 Phase B] 仅依赖中性头：
//   - control_plane.hpp 提供 SendabilityView
//   - registration_hook.hpp 提供 RegistrationControlHook
// 不再 include ivshmem_control_plane.hpp，打破 CP/DP 具体实现间的交叉耦合。
#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/control/registration_hook.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/infra/ivshmem_backbone.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/data/doorbell_server.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::channel::data {

// IvshmemDataPlaneOptions — DP 层从 TransportConfig 抽出的配置视图
struct IvshmemDataPlaneOptions {
    std::string shm_path;                    // StartDoorbellServer 需要的 shm 路径
    std::string doorbell_socket_path;        // OpenDoorbell 连接的 unix socket
    bool        use_doorbell = false;
    std::chrono::microseconds poll_sleep_us{100};  // plain 模式轮询间隔
};

class IvshmemDataPlane final : public IDataPlane {
public:
    IvshmemDataPlane(std::shared_ptr<infra::IvshmemBackbone>         backbone,
                     infra::ShmInfra*                                shm,
                     control::SendabilityView                         sendability,
                     control::RegistrationControlHook                 reg_hook,
                     IvshmemDataPlaneOptions                          options);
    ~IvshmemDataPlane() override;

    IvshmemDataPlane(const IvshmemDataPlane&)            = delete;
    IvshmemDataPlane& operator=(const IvshmemDataPlane&) = delete;

    // ── 生命周期 ─────────────────────────────────────────────────
    //
    // StartServer(): 启动 DoorbellServer（仅 doorbell 模式），必须在 StartVM 之前调用。
    // Prepare():     QEMU 已连上后，host 作为 peer 1 接入并握手 + 建 mmap/eventfd/epoll。
    //                plain 模式下 StartServer 是 no-op，Prepare 也是 no-op。
    Result<void> StartServer() override;
    Result<void> Prepare() override;
    void         Close() override;

    // ── 暂停 / 恢复 ─────────────────────────────────────────────
    void Pause() override;
    void Resume() override;

    // ── Submit / Poll ──────────────────────────────────────────
    SubmitOutcome Submit(const SubmitInput& req) override;
    void          Poll(std::vector<DispatchOutcome>& out,
                       std::chrono::microseconds timeout) override;
    void          WakePoller() noexcept override;

    // ── Reset ─────────────────────────────────────────────────
    void ResetWorker(uint32_t worker_id) override;
    void ResetAll() override;

    // ── Inflight 盘点 ───────────────────────────────────────────
    std::vector<InflightEntry> SnapshotInflight() const override;

    // ── 状态查询（Phase B：升级为 IDataPlane 虚函数） ──────────────
    bool     IsPaused() const noexcept override { return paused_.load(std::memory_order_relaxed); }
    bool     IsClosed() const noexcept override { return closed_.load(std::memory_order_acquire); }
    uint32_t MaxWorkerSlots() const noexcept override { return n_workers_; }

    // 可发查询（Phase B：升级为 IDataPlane 虚函数）
    bool     IsWorkerSendable(uint32_t worker_id) const override;
    uint32_t CountSendableWorkers() const override;

    // 旧的 snake_case 访问器（保留以兼容外部诊断调用）
    bool     is_paused() const noexcept { return IsPaused(); }
    bool     is_closed() const noexcept { return IsClosed(); }
    uint32_t n_workers() const noexcept { return MaxWorkerSlots(); }

    // [Phase 4.3 转调桥] 允许 Transport 在 OpenDoorbell 时把 shm_path 补进 options。
    // 仅在 Prepare() 之前调用；Prepare 之后再改不会生效。
    void SetShmPathForDoorbell(std::string shm_path) { options_.shm_path = std::move(shm_path); }

private:
    // 内部辅助：Sweep 一个 worker 的 completion slot
    size_t SweepWorker(uint32_t worker_id, std::vector<DispatchOutcome>& out);
    size_t SweepAllSlots(std::vector<DispatchOutcome>& out);

    // doorbell 模式：唤醒 epoll_wait
    void WakeDoorbellPoller() noexcept;

    std::shared_ptr<infra::IvshmemBackbone> backbone_;
    infra::ShmInfra*                        shm_;            // non-owning
    control::SendabilityView                sendability_;
    control::RegistrationControlHook        reg_hook_;       // DP→CP 反向写通道
    IvshmemDataPlaneOptions                 options_;
    uint32_t                                n_workers_;
    std::vector<uint64_t>                   expected_executor_id_;
    std::vector<uint32_t>                   expected_dispatch_gen_;
    std::vector<uint32_t>                   expected_proc_id_;
    std::vector<uint64_t>                   last_completion_exec_seq_;
    // [RTT] per-worker host-observed start tracking, reset at every successful
    // Submit so a recovery re-dispatch of the same executor_id gets a fresh
    // timestamp. pending_start_ack_us_ is attached to the matching completion's
    // DispatchOutcome.
    std::vector<uint64_t>                   last_start_acked_exec_;
    std::vector<uint64_t>                   pending_start_ack_us_;

    // 数据面门控
    std::atomic<bool> paused_{false};
    std::atomic<bool> closed_{false};

    // host-side poll wake：input / health / close / recovery signal 都通过它打断 Poll。
    std::mutex              poll_wake_mutex_;
    std::condition_variable poll_wake_cv_;
    std::atomic<bool>       poll_wake_pending_{false};

    // doorbell 基础设施
    int doorbell_fd_      = -1;
    int doorbell_epollfd_ = -1;
    int stop_eventfd_     = -1;
    std::vector<int>                  doorbell_notify_fds_;
    std::unordered_map<int, uint32_t> notify_fd_to_worker_;
    std::unique_ptr<DoorbellServer> doorbell_server_;
};

} // namespace refuzz::channel::data
