// [v3 Phase 4.3] IvshmemControlPlane 实现
//
// 本文件包含从 transport/src/registration.cpp + reset_snapshot.cpp + lifecycle.cpp
// 搬入的所有控制面逻辑。Transport 侧相应方法将退化为转调（Phase 4.3 后续步骤）。

#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cassert>
#include <cstring>
#include <string>
#include <thread>

namespace refuzz::channel::control {
namespace {

// 内部 atomic helpers（与 transport/src/atomic_helpers.hpp 对齐；
// 不跨目录 include 避免 transport 目录成为 CP 头文件依赖）
inline uint32_t ctrl_load_guest_state(const WorkerCtrl* ctrl) noexcept {
    return __atomic_load_n(&ctrl->guest_state, __ATOMIC_ACQUIRE);
}
inline void ctrl_store_host_state(WorkerCtrl* ctrl, HostRegState s) noexcept {
    __atomic_store_n(&ctrl->host_state, static_cast<uint32_t>(s), __ATOMIC_RELEASE);
}
// 注：CP 不需要 load_state helpers；只写 state（ResetSession 重置）
inline void task_store_state(TaskSlot* slot, TaskSlotState s) noexcept {
    volatile uint32_t* vp = &slot->state;
    __atomic_store_n(const_cast<uint32_t*>(vp), static_cast<uint32_t>(s), __ATOMIC_RELEASE);
}
inline void completion_store_state(CompletionSlot* slot, CompletionSlotState s) noexcept {
    volatile uint32_t* vp = &slot->state;
    __atomic_store_n(const_cast<uint32_t*>(vp), static_cast<uint32_t>(s), __ATOMIC_RELEASE);
}

inline uint64_t steady_now_us() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count());
}

} // namespace

IvshmemControlPlane::IvshmemControlPlane(std::shared_ptr<infra::IvshmemBackbone> backbone,
                                         infra::ShmInfra*                         shm,
                                         SessionTiming                            timing)
    : backbone_(std::move(backbone))
    , shm_(shm)
    , timing_(timing)
    , n_workers_(backbone_ ? backbone_->NWorkers() : 0)
    , worker_registered_(n_workers_) // atomic<uint8_t>: 值初始化 = 0
    , revoked_(n_workers_)
{
    assert(backbone_ != nullptr);
    assert(shm_ != nullptr);
    assert(shm_->initialized());
}

IvshmemControlPlane::~IvshmemControlPlane() = default;

// ────────────────────────────────────────────────────────────────
// 会话生命周期
// ────────────────────────────────────────────────────────────────

Result<void> IvshmemControlPlane::BeginSession()
{
    state_.store(SessionState::kHandshaking, std::memory_order_relaxed);
    InternalStartRegistration();
    return Result<void>::Ok();
}

void IvshmemControlPlane::InternalStartRegistration()
{
    // 步骤 1：前缀递增（确保每轮 epoch > 0 且单调）
    ++reg_epoch_;

    // 步骤 2：先清 host_ready（防止 guest 在写 epoch 前误读旧 ready=1）
    shm_->WriteHostReady(0);

    // 步骤 3：写新注册轮次
    shm_->WriteRegEpoch(reg_epoch_);

    // 步骤 4：清零 per-worker 注册标记
    for (auto& r : worker_registered_) r.store(0, std::memory_order_relaxed);

    // 步骤 5：广播注册门控开启
    shm_->WriteHostReady(1);
}

Result<void> IvshmemControlPlane::WaitAllWorkersReady(std::chrono::milliseconds timeout)
{
    // 优先使用调用方传入的 timeout；若为 0 则回退到 timing_ 中的默认值
    std::chrono::microseconds tmo_us = (timeout.count() > 0)
        ? std::chrono::duration_cast<std::chrono::microseconds>(timeout)
        : timing_.wait_ready_timeout_us;

    const auto deadline = std::chrono::steady_clock::now() + tmo_us;

    // Per-worker grant/startup remains serialized. Domain startup touches
    // VM-global devices and cgroup state, so granting every daemon first can
    // deadlock or starve concurrent sandbox/KCOV initialization.
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto r = InternalClaimSingle(i, deadline);
        if (!r.ok()) return r.error();
        r = InternalWaitReadySingle(i, deadline);
        if (!r.ok()) return r.error();
    }

    state_.store(SessionState::kReady, std::memory_order_relaxed);
    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::WaitWorkerReady(uint32_t worker_id,
                                                   std::chrono::milliseconds timeout)
{
    if (worker_id >= n_workers_) {
        return Error{ErrorKind::kProtocol,
                     "WaitWorkerReady: worker_id " + std::to_string(worker_id) + " out of range"};
    }
    std::chrono::microseconds tmo_us = (timeout.count() > 0)
        ? std::chrono::duration_cast<std::chrono::microseconds>(timeout)
        : timing_.wait_ready_timeout_us;
    const auto deadline = std::chrono::steady_clock::now() + tmo_us;
    auto claimed = InternalClaimSingle(worker_id, deadline);
    if (!claimed.ok()) return claimed.error();
    auto ready = InternalWaitReadySingle(worker_id, deadline);
    if (!ready.ok()) return ready.error();

    bool all_ready = true;
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid() ||
            ctrl_load_guest_state(wv.ctrl()) != static_cast<uint32_t>(GUEST_REG_READY)) {
            all_ready = false;
            break;
        }
    }
    if (all_ready) {
        state_.store(SessionState::kReady, std::memory_order_relaxed);
    }
    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::InternalClaimSingle(
    uint32_t worker_id,
    std::chrono::steady_clock::time_point deadline)
{
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) {
        return Error{ErrorKind::kProtocol,
                     "Handshake: invalid WorkerView for worker " + std::to_string(worker_id)};
    }
    WorkerCtrl* ctrl = wv.ctrl();

    const auto poll_interval = timing_.wait_ready_poll_us;

    while (true) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return Error{ErrorKind::kTimeout,
                         "Handshake: timeout waiting GUEST_REG_CLAIMED on worker " +
                             std::to_string(worker_id)};
        }
        const uint32_t guest_state = ctrl_load_guest_state(ctrl);
        const bool owner_claimed =
            guest_state == static_cast<uint32_t>(GUEST_REG_CLAIMED) ||
            guest_state == static_cast<uint32_t>(GUEST_REG_READY);
        if (owner_claimed) {
            break;
        }
        if (guest_state == static_cast<uint32_t>(GUEST_REG_DEAD)) {
            return Error{ErrorKind::kProtocol,
                         "Handshake: GUEST_REG_DEAD on worker " + std::to_string(worker_id)};
        }
        std::this_thread::sleep_for(poll_interval);
    }

    // Registration means daemon ownership, not execution-domain readiness.
    // Publish it before GRANTED so an acquire observation of the grant also
    // observes the registration bit.
    worker_registered_[worker_id].store(1, std::memory_order_release);
    ctrl_store_host_state(ctrl, HOST_REG_GRANTED);
    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::InternalWaitReadySingle(
    uint32_t worker_id,
    std::chrono::steady_clock::time_point deadline)
{
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) {
        return Error{ErrorKind::kProtocol,
                     "Handshake: invalid WorkerView for worker " + std::to_string(worker_id)};
    }
    WorkerCtrl* ctrl = wv.ctrl();
    const auto poll_interval = timing_.wait_ready_poll_us;

    while (true) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return Error{ErrorKind::kTimeout,
                         "Handshake: timeout waiting GUEST_REG_READY on worker " +
                             std::to_string(worker_id)};
        }
        uint32_t guest_state = ctrl_load_guest_state(ctrl);
        if (guest_state == static_cast<uint32_t>(GUEST_REG_READY)) break;
        if (guest_state == static_cast<uint32_t>(GUEST_REG_DEAD)) {
            worker_registered_[worker_id].store(0, std::memory_order_release);
            return Error{ErrorKind::kProtocol,
                         "Handshake: GUEST_REG_DEAD after GRANTED on worker " +
                             std::to_string(worker_id)};
        }
        std::this_thread::sleep_for(poll_interval);
    }

    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::ResetSession()
{
    // 搬自 transport::Transport::ResetSlots()
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid()) continue;

        task_store_state(wv.task_slot(), TASK_EMPTY);
        completion_store_state(wv.completion_slot(), COMP_EMPTY);
        if (wv.result_page() != nullptr) {
            std::memset(wv.result_page(), 0, sizeof(ProgramResultPageV3));
        }

        WorkerCtrl* ctrl = wv.ctrl();
        // 只清会话字段；proc 隔离状态（active_proc_id / proc_epoch /
        // proc_state_magic / dirty_proc_mask）保持原值且**不由 host 回写**。
        // 整块 memset + 快照回写会形成 read-modify-write 竞态：旧 guest 在
        // 快照与恢复之间发布的新 dirty mask 会被旧快照覆盖，reboot 失败时
        // dirty 账本就不完整。host 不写这些字段后，guest 的发布天然保留。
        __atomic_store_n(&ctrl->guest_state, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->heartbeat_counter, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->last_hb_us, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->error_latch, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->cancel_requested, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->cancel_observed_seq, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->paused, 0u, __ATOMIC_RELEASE);
        ctrl->reserved[0] = 0;
        ctrl->reserved[1] = 0;
        ctrl_store_host_state(ctrl, HOST_REG_IDLE);
    }

    // step event ring 归零
    if (auto* step_hdr = shm_->StepEventHeader(); step_hdr != nullptr) {
        __atomic_store_n(&step_hdr->head, 0ULL, __ATOMIC_RELEASE);
        __atomic_store_n(&step_hdr->tail, 0ULL, __ATOMIC_RELEASE);
    }

    // 清零 worker_registered_
    for (auto& r : worker_registered_) r.store(0, std::memory_order_relaxed);
    // revoke 状态也清空：一轮会话结束后，下一轮重新注册不应继承上轮 revoke
    for (auto& r : revoked_) r.store(0, std::memory_order_relaxed);

    // 清取消 baseline
    {
        std::lock_guard<std::mutex> lg(cancel_mu_);
        cancel_baseline_.clear();
    }

    // 关闭注册门控
    shm_->WriteHostReady(0);

    // Reset 完毕后回到 Idle（下一个 BeginSession 周期）
    state_.store(SessionState::kIdle, std::memory_order_relaxed);

#ifndef NDEBUG
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid()) continue;
        WorkerCtrl* ctrl = wv.ctrl();
        assert(__atomic_load_n(&ctrl->cancel_requested, __ATOMIC_RELAXED) == 0);
        assert(__atomic_load_n(&ctrl->cancel_observed_seq, __ATOMIC_RELAXED) == 0);
        assert(__atomic_load_n(&ctrl->paused, __ATOMIC_RELAXED) == 0);
    }
#endif

    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::ResetWorkerSession(uint32_t worker_id)
{
    if (worker_id >= n_workers_) {
        return Error{ErrorKind::kProtocol,
                     "ResetWorkerSession: worker_id " + std::to_string(worker_id) + " out of range"};
    }

    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) {
        return Error{ErrorKind::kProtocol,
                     "ResetWorkerSession: invalid WorkerView for worker " + std::to_string(worker_id)};
    }

    task_store_state(wv.task_slot(), TASK_EMPTY);
    completion_store_state(wv.completion_slot(), COMP_EMPTY);
    if (wv.result_page() != nullptr) {
        std::memset(wv.result_page(), 0, sizeof(ProgramResultPageV3));
    }

    WorkerCtrl* ctrl = wv.ctrl();
    // 同 ResetSession：不整块 memset + 快照回写，避免覆盖旧 guest 在重置
    // 期间新发布的 dirty mask / proc 状态。
    __atomic_store_n(&ctrl->guest_state, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->heartbeat_counter, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->last_hb_us, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->error_latch, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->cancel_requested, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->cancel_observed_seq, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl->paused, 0u, __ATOMIC_RELEASE);
    ctrl->reserved[0] = 0;
    ctrl->reserved[1] = 0;
    ctrl_store_host_state(ctrl, HOST_REG_IDLE);

    worker_registered_[worker_id].store(0, std::memory_order_relaxed);
    revoked_[worker_id].store(0, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lg(cancel_mu_);
        cancel_baseline_.erase(worker_id);
    }

#ifndef NDEBUG
    assert(__atomic_load_n(&ctrl->cancel_requested, __ATOMIC_RELAXED) == 0);
    assert(__atomic_load_n(&ctrl->cancel_observed_seq, __ATOMIC_RELAXED) == 0);
    assert(__atomic_load_n(&ctrl->paused, __ATOMIC_RELAXED) == 0);
#endif

    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::ClearProcIsolationState()
{
    for (uint32_t worker_id = 0; worker_id < n_workers_; ++worker_id) {
        auto wv = shm_->worker(worker_id);
        if (!wv.valid()) {
            return Error{ErrorKind::kProtocol,
                         "ClearProcIsolationState: invalid WorkerView for worker " +
                             std::to_string(worker_id)};
        }
        WorkerCtrl* ctrl = wv.ctrl();
        // Invalidate first so a concurrently starting worker cannot observe a
        // partially reset identity. Recovery calls this while workers are down.
        __atomic_store_n(&ctrl->proc_state_magic, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->active_proc_id, PROC_ID_ANY, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->proc_epoch, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ctrl->dirty_proc_mask, 0u, __ATOMIC_RELEASE);
    }
    return Result<void>::Ok();
}

Result<void> IvshmemControlPlane::EndSession()
{
    state_.store(SessionState::kClosing, std::memory_order_relaxed);
    for (auto& r : worker_registered_) r.store(0, std::memory_order_relaxed);
    state_.store(SessionState::kClosed, std::memory_order_relaxed);
    return Result<void>::Ok();
}

// ────────────────────────────────────────────────────────────────
// 状态查询
// ────────────────────────────────────────────────────────────────

SessionState IvshmemControlPlane::CurrentState() const
{
    return state_.load(std::memory_order_relaxed);
}

uint32_t IvshmemControlPlane::RegisteredWorkerCount() const
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < n_workers_; ++i) {
        if (revoked_[i].load(std::memory_order_relaxed) != 0) continue;
        if (worker_registered_[i].load(std::memory_order_relaxed) != 0) ++count;
    }
    return count;
}

bool IvshmemControlPlane::IsWorkerRegistered(uint32_t worker_id) const
{
    if (worker_id >= n_workers_) return false;
    if (revoked_[worker_id].load(std::memory_order_relaxed) != 0) return false;
    return worker_registered_[worker_id].load(std::memory_order_relaxed) != 0;
}

// ────────────────────────────────────────────────────────────────
// 配额 / 隔离
// ────────────────────────────────────────────────────────────────

void IvshmemControlPlane::RevokeWorker(uint32_t worker_id)
{
    if (worker_id >= n_workers_) return;
    revoked_[worker_id].store(1, std::memory_order_relaxed);
    // 同步清零注册位：revoke 后外部语义等价于"未注册"
    worker_registered_[worker_id].store(0, std::memory_order_relaxed);
}

// ────────────────────────────────────────────────────────────────
// Heartbeat 采样
// ────────────────────────────────────────────────────────────────

WorkerHeartbeatSample IvshmemControlPlane::SampleHeartbeat(uint32_t worker_id)
{
    WorkerHeartbeatSample out;
    out.worker_id = worker_id;
    if (worker_id >= n_workers_) return out;
    if (!IsWorkerRegistered(worker_id)) return out;
    WorkerControlAreaV3* area = backbone_->WorkerControl(worker_id);
    if (area == nullptr) return out;

    // [心跳重定义] 令牌由执行状态机的四个分量合成。每个分量对应 DomainSupervisor 的一次
    //   状态迁移入口，合起来覆盖全部 6 个状态 —— daemon 换状态必然在 shm 留痕：
    //
    //     start_ts_us   ← adapter:348，取到任务时无条件写      → 进 kExecuting
    //     exec_seq      ← adapter:430，发布结果时 ++           → 出 kExecuting
    //     proc_epoch    ← StartAttempt:322，60s boot 之前发布  → 进 kStarting（= daemon 在自救）
    //     guest_state   ← EnterState:224/238 进出 {kReady,kExecuting} 时翻
    //                                                          → 进 kStopping/kStarting/kFailed/kStopped
    //
    //   最长的合法静止期 = domain_startup_timeout_ms(60s)，即 proc_epoch 发布到 kReady 之间那次
    //   boot。判死阈值必须 > 它，否则会把正在自救的 daemon 误判成死的。这个上界由 host 侧配置
    //   决定，不依赖 guest 的死活 —— 这正是本判据成立的根据。
    //
    //   task.state 与 start_ts_us/exec_seq 信息重叠，纳入只为让令牌对 EMPTY↔READY 的
    //   host 侧投递也敏感（worker 空闲时无在飞任务，本就不计时，属冗余但零成本）。
    const uint64_t start_ts    = __atomic_load_n(&area->completion.start_ts_us, __ATOMIC_ACQUIRE);
    const uint64_t exec_seq    = __atomic_load_n(&area->completion.exec_seq, __ATOMIC_ACQUIRE);
    const uint32_t proc_epoch  = __atomic_load_n(&area->ctrl.proc_epoch, __ATOMIC_ACQUIRE);
    const uint32_t guest_state = __atomic_load_n(&area->ctrl.guest_state, __ATOMIC_ACQUIRE);
    const uint32_t task_state  = task_slot_load_state_v3(&area->task);  // state 是 volatile,走现成 helper

    // FNV-1a 式混合。只要求"任一分量变 → 令牌变"，sensor 只做 != 比较。
    constexpr uint64_t kPrime = 1099511628211ULL;
    uint64_t token = 14695981039346656037ULL;
    token = (token ^ start_ts) * kPrime;
    token = (token ^ exec_seq) * kPrime;
    token = (token ^ proc_epoch) * kPrime;
    token = (token ^ (static_cast<uint64_t>(guest_state) << 32 | task_state)) * kPrime;

    out.counter       = token;
    out.sampled_ts_us = steady_now_us();
    out.valid         = true;
    out.proc_epoch    = proc_epoch;
    out.guest_state   = guest_state;
    // wire 值 → 共享语义。sensor / telemetry / renderer 都不该认识 TASK_* 的编码。
    namespace cc = refuzz::core::channel_contract;
    switch (task_state) {
    case TASK_EMPTY: out.slot = cc::WorkerSlotState::kEmpty;      break;
    case TASK_READY: out.slot = cc::WorkerSlotState::kDispatched; break;
    case TASK_TAKEN: out.slot = cc::WorkerSlotState::kExecuting;  break;
    default:         out.slot = cc::WorkerSlotState::kUnknown;    break;
    }
    return out;
}

// ────────────────────────────────────────────────────────────────
// Cancel
// ────────────────────────────────────────────────────────────────

Result<void> IvshmemControlPlane::RequestCancel(uint32_t worker_id, uint64_t /*executor_id*/)
{
    if (worker_id >= n_workers_) {
        return Error{ErrorKind::kProtocol, "RequestCancel: out of range"};
    }
    if (!IsWorkerRegistered(worker_id)) {
        return Error{ErrorKind::kProtocol, "RequestCancel: worker not registered"};
    }

    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) {
        return Error{ErrorKind::kProtocol, "RequestCancel: invalid view"};
    }

    // baseline = 记录发起取消前的 observed_seq；ACK 语义 = observed_seq > baseline
    uint32_t baseline = __atomic_load_n(&wv.ctrl()->cancel_observed_seq, __ATOMIC_ACQUIRE);
    {
        std::lock_guard<std::mutex> lg(cancel_mu_);
        cancel_baseline_[worker_id] = baseline;
    }

    __atomic_store_n(&wv.ctrl()->cancel_requested, 1u, __ATOMIC_RELEASE);
    return Result<void>::Ok();
}

bool IvshmemControlPlane::ReadCancelAck(uint32_t worker_id, uint64_t /*executor_id*/)
{
    if (worker_id >= n_workers_) return false;
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) return false;

    uint32_t current = __atomic_load_n(&wv.ctrl()->cancel_observed_seq, __ATOMIC_ACQUIRE);
    uint32_t baseline = 0;
    {
        std::lock_guard<std::mutex> lg(cancel_mu_);
        auto it = cancel_baseline_.find(worker_id);
        if (it == cancel_baseline_.end()) return false;
        baseline = it->second;
    }
    return current > baseline;
}

uint32_t IvshmemControlPlane::ReadCancelObservedSeqRaw(uint32_t worker_id) const noexcept
{
    if (worker_id >= n_workers_) return 0;
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) return 0;
    return __atomic_load_n(&wv.ctrl()->cancel_observed_seq, __ATOMIC_ACQUIRE);
}

uint32_t IvshmemControlPlane::ConsumeWorkerError(uint32_t worker_id) noexcept
{
    if (worker_id >= n_workers_) {
        return 0;
    }
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) {
        return 0;
    }
    return __atomic_exchange_n(&wv.ctrl()->error_latch,
                               0u,
                               __ATOMIC_ACQ_REL);
}

// ────────────────────────────────────────────────────────────────
// Sendability 视图 & Registration 反向 hook
// ────────────────────────────────────────────────────────────────

SendabilityView IvshmemControlPlane::GetSendabilityView()
{
    SendabilityView v;
    v.is_registered = [this](uint32_t wid) { return IsWorkerRegistered(wid); };
    v.registered_worker_count = [this]() { return RegisteredWorkerCount(); };
    return v;
}

RegistrationControlHook IvshmemControlPlane::GetRegistrationHook()
{
    RegistrationControlHook h;
    h.set_registered = [this](uint32_t wid, bool registered) {
        if (wid >= n_workers_) return;
        worker_registered_[wid].store(registered ? 1u : 0u, std::memory_order_release);
    };
    return h;
}

} // namespace refuzz::channel::control
