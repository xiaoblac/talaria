// [v3 Phase 4.3] IvshmemDataPlane 实现
//
// 搬自：
//   - transport/src/send_recv.cpp  (TrySend / Send / Poll / Sweep*)
//   - transport/src/doorbell.cpp    (StartDoorbellServer / OpenDoorbell / Close* / WakePollerIfDoorbell)
//   - transport/src/lifecycle.cpp   (Pause / Resume 数据面部分 / Close)
//   - transport/src/reset_snapshot.cpp (SnapshotInflight/Full，slot 状态部分)

#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "refuzz/core/time.hpp"  // [RTT] MonotonicNowUs() for worker_start_ack_host stamp

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace refuzz::channel::data {
namespace {

constexpr uint32_t kHostWakeEventTag = UINT32_MAX;

// ── 内部 atomic helpers（与 CP 文件保持一致，不跨目录引用 transport/src） ──

inline uint32_t task_load_state(const TaskSlot* slot) noexcept {
    const volatile uint32_t* vp = &slot->state;
    return __atomic_load_n(const_cast<const uint32_t*>(vp), __ATOMIC_ACQUIRE);
}
inline void task_store_state(TaskSlot* slot, TaskSlotState s) noexcept {
    volatile uint32_t* vp = &slot->state;
    __atomic_store_n(const_cast<uint32_t*>(vp), static_cast<uint32_t>(s), __ATOMIC_RELEASE);
}
inline uint32_t completion_load_state(const CompletionSlot* slot) noexcept {
    const volatile uint32_t* vp = &slot->state;
    return __atomic_load_n(const_cast<const uint32_t*>(vp), __ATOMIC_ACQUIRE);
}
inline void completion_store_state(CompletionSlot* slot, CompletionSlotState s) noexcept {
    volatile uint32_t* vp = &slot->state;
    __atomic_store_n(const_cast<uint32_t*>(vp), static_cast<uint32_t>(s), __ATOMIC_RELEASE);
}
inline uint32_t ctrl_load_guest_state(const WorkerCtrl* ctrl) noexcept {
    return __atomic_load_n(&ctrl->guest_state, __ATOMIC_ACQUIRE);
}
inline void ctrl_store_paused(WorkerCtrl* ctrl, uint32_t v) noexcept {
    __atomic_store_n(&ctrl->paused, v, __ATOMIC_RELEASE);
}

// COMP_STATUS_CRASHED 仅保留 daemon-child 协议错的真信号（NotifyChild pipe broken 等）。
// 新增 COMP_STATUS_CHILD_ABORTED 单独翻译为 kChildAborted。
// COMP_STATUS_HUNG 单独翻译为 kHang（daemon task hang / 执行阶段结果丢失），
// 不再与 program watchdog 的 kTimeout 共用。
// wire status → 语义 kind。**纯翻译,不做分类决策**:error_code / crash_signal /
// output 原样透传给 Channel,由它读 (kind, error_code) 二元组决定 Completion/Abnormal。
DispatchOutcomeKind TranslateStatus(uint32_t status) noexcept {
    switch (status) {
        case COMP_STATUS_OK:            return DispatchOutcomeKind::kOk;
        case COMP_STATUS_NO_RESULT:     return DispatchOutcomeKind::kNoResult;
        case COMP_STATUS_TIMEOUT:       return DispatchOutcomeKind::kTimeout;
        case COMP_STATUS_HUNG:          return DispatchOutcomeKind::kHang;
        case COMP_STATUS_CANCELLED:     return DispatchOutcomeKind::kCancelled;
        case COMP_STATUS_CRASHED:       return DispatchOutcomeKind::kWorkerSignaled;
        case COMP_STATUS_CHILD_ABORTED: return DispatchOutcomeKind::kChildAborted;
        case COMP_STATUS_PARTIAL:       return DispatchOutcomeKind::kPartial;
        case COMP_STATUS_HARNESS_FATAL: return DispatchOutcomeKind::kHarnessFatal;
        case COMP_STATUS_HARNESS_RECOVERED:
            return DispatchOutcomeKind::kHarnessRecovered;
        case COMP_STATUS_INFRA_FAULT:   return DispatchOutcomeKind::kInfraFault;
        case COMP_STATUS_UNKNOWN:       return DispatchOutcomeKind::kUnknown;
        // 未知 wire status = 协议已错位。曾兜底成 kExecError,把"协议错"伪装成
        // 一次普通执行错误静默吞掉;现在如实报 kUnknown。
        default:                        return DispatchOutcomeKind::kUnknown;
    }
}

// ── 内部辅助：recvmsg + 可选 SCM_RIGHTS（搬自 transport/src/doorbell.cpp） ──

struct MsgWithFd {
    uint64_t value = 0;
    int      fd    = -1;
};

MsgWithFd RecvMsgWithFd(int sock) noexcept {
    uint8_t buf[8] = {};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    std::memset(&ctrl, 0, sizeof(ctrl));

    struct iovec iov{};
    iov.iov_base = buf;
    iov.iov_len  = sizeof(buf);

    struct msghdr msg{};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    ssize_t n = recvmsg(sock, &msg, 0);
    if (n != static_cast<ssize_t>(sizeof(buf))) {
        return {0, -2};
    }
    uint64_t value = 0;
    std::memcpy(&value, buf, 8);

    MsgWithFd result{value, -1};
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != nullptr &&
        cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type  == SCM_RIGHTS &&
        cmsg->cmsg_len   == CMSG_LEN(sizeof(int))) {
        std::memcpy(&result.fd, CMSG_DATA(cmsg), sizeof(int));
    }
    return result;
}

void DrainEventFd(int fd) noexcept
{
    if (fd < 0) return;
    uint64_t val = 0;
    while (true) {
        const ssize_t n = read(fd, &val, sizeof(val));
        if (n == static_cast<ssize_t>(sizeof(val))) return;
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
}

} // namespace

// ────────────────────────────────────────────────────────────────
// 构造 / 析构
// ────────────────────────────────────────────────────────────────

IvshmemDataPlane::IvshmemDataPlane(std::shared_ptr<infra::IvshmemBackbone> backbone,
                                   infra::ShmInfra*                         shm,
                                   control::SendabilityView                 sendability,
                                   control::RegistrationControlHook         reg_hook,
                                   IvshmemDataPlaneOptions                  options)
    : backbone_(std::move(backbone))
    , shm_(shm)
    , sendability_(std::move(sendability))
    , reg_hook_(std::move(reg_hook))
    , options_(std::move(options))
    , n_workers_(backbone_ ? backbone_->NWorkers() : 0)
    , expected_executor_id_(n_workers_, 0)
    , expected_dispatch_gen_(n_workers_, 0)
    , expected_proc_id_(n_workers_, PROC_ID_ANY)
    , last_completion_exec_seq_(n_workers_, 0)
    , last_start_acked_exec_(n_workers_, 0)
    , pending_start_ack_us_(n_workers_, 0)
{
    assert(backbone_ != nullptr);
    assert(shm_ != nullptr);
    assert(shm_->initialized());
}

IvshmemDataPlane::~IvshmemDataPlane()
{
    Close();
}

// ────────────────────────────────────────────────────────────────
// 生命周期
// ────────────────────────────────────────────────────────────────

// [v3.G] StartServer:只做 DoorbellServer 的监听启动(Part 1);
//         必须在 Substrate.StartVM() 之前调用,否则 QEMU 启动时连不上 socket → 秒退。
//         plain 模式为 no-op。
Result<void> IvshmemDataPlane::StartServer()
{
    if (!options_.use_doorbell) {
        return Result<void>::Ok();
    }

    if (options_.doorbell_socket_path.empty()) {
        return Error{ErrorKind::kConfig,
                     "IvshmemDataPlane::StartServer: doorbell_socket_path is empty (use_doorbell=true)"};
    }
    if (options_.shm_path.empty()) {
        return Error{ErrorKind::kConfig,
                     "IvshmemDataPlane::StartServer: shm_path is empty"};
    }

    if (doorbell_server_) {
        // Reboot recovery needs a fresh accept loop for the next QEMU peer.
        for (int fd : doorbell_notify_fds_) {
            if (fd >= 0) ::close(fd);
        }
        doorbell_notify_fds_.clear();
        notify_fd_to_worker_.clear();
        if (doorbell_fd_ >= 0)      { ::close(doorbell_fd_);      doorbell_fd_ = -1; }
        if (stop_eventfd_ >= 0)     { ::close(stop_eventfd_);     stop_eventfd_ = -1; }
        if (doorbell_epollfd_ >= 0) { ::close(doorbell_epollfd_); doorbell_epollfd_ = -1; }
        doorbell_server_->Stop();
        doorbell_server_.reset();
    }

    closed_.store(false, std::memory_order_release);

    auto server = std::make_unique<DoorbellServer>(
        options_.doorbell_socket_path,
        options_.shm_path,
        static_cast<int>(n_workers_));
    if (!server->Start()) {
        return Error{ErrorKind::kConnection,
                     "IvshmemDataPlane::StartServer: failed to start DoorbellServer (socket=" +
                         options_.doorbell_socket_path + ")"};
    }
    doorbell_server_ = std::move(server);
    return Result<void>::Ok();
}

Result<void> IvshmemDataPlane::Prepare()
{
    if (!options_.use_doorbell) {
        return Result<void>::Ok();
    }

    // [v3.G] Part 1 (DoorbellServer::Start) 已经由 StartServer() 完成；
    //         这里只做 Part 2:作为 peer 1 反向连回 server,完成握手 + 建 epoll。
    //         若外层忘了调 StartServer 而直接 Prepare,兜底补启动(不隐藏错误)。
    if (!doorbell_server_) {
        auto r = StartServer();
        if (!r.ok()) {
            return r;
        }
    }

    // ── OpenDoorbell(握手 Part 2) ────────────

    auto cleanup = [this]() {
        for (int fd : doorbell_notify_fds_) {
            if (fd >= 0) ::close(fd);
        }
        doorbell_notify_fds_.clear();
        notify_fd_to_worker_.clear();
        if (doorbell_fd_ >= 0)      { ::close(doorbell_fd_);      doorbell_fd_ = -1; }
        if (stop_eventfd_ >= 0)     { ::close(stop_eventfd_);     stop_eventfd_ = -1; }
        if (doorbell_epollfd_ >= 0) { ::close(doorbell_epollfd_); doorbell_epollfd_ = -1; }
    };

    // Prepare may run again after a VM reboot. Keep the DoorbellServer alive so
    // QEMU can reconnect, but rebuild the host peer fd/epoll/eventfd state.
    cleanup();

    doorbell_epollfd_ = epoll_create1(EPOLL_CLOEXEC);
    if (doorbell_epollfd_ < 0) {
        const int err = errno;
        return Error{ErrorKind::kConnection,
                     std::string("Prepare: epoll_create1 failed: ") + std::strerror(err)};
    }

    stop_eventfd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (stop_eventfd_ < 0) {
        const int err = errno;
        cleanup();
        return Error{ErrorKind::kConnection,
                     std::string("Prepare: eventfd failed: ") + std::strerror(err)};
    }
    {
        struct epoll_event ev{};
        ev.events  = EPOLLIN;
        ev.data.u32 = kHostWakeEventTag;
        if (epoll_ctl(doorbell_epollfd_, EPOLL_CTL_ADD, stop_eventfd_, &ev) < 0) {
            const int err = errno;
            cleanup();
            return Error{ErrorKind::kConnection,
                         std::string("Prepare: epoll_ctl(stop_eventfd) failed: ") + std::strerror(err)};
        }
    }

    doorbell_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (doorbell_fd_ < 0) {
        const int err = errno;
        cleanup();
        return Error{ErrorKind::kConnection,
                     std::string("Prepare: socket() failed: ") + std::strerror(err)};
    }
    {
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (options_.doorbell_socket_path.size() >= sizeof(addr.sun_path)) {
            cleanup();
            return Error{ErrorKind::kConfig,
                         "Prepare: doorbell_socket_path too long (>107 bytes)"};
        }
        std::strncpy(addr.sun_path, options_.doorbell_socket_path.c_str(),
                     sizeof(addr.sun_path) - 1);
        if (connect(doorbell_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            const int err = errno;
            cleanup();
            return Error{ErrorKind::kConnection,
                         std::string("Prepare: connect(") + options_.doorbell_socket_path +
                             ") failed: " + std::strerror(err)};
        }
    }

    // 3 条初始握手帧（value + 校验）
    uint64_t handshake_values[3] = {};
    for (int i = 0; i < 3; ++i) {
        auto m = RecvMsgWithFd(doorbell_fd_);
        if (m.fd == -2) {
            cleanup();
            return Error{ErrorKind::kConnection,
                         "Prepare: failed to receive initial handshake message " +
                             std::to_string(i + 1)};
        }
        handshake_values[i] = m.value;
        if (m.fd >= 0) ::close(m.fd);
    }
    if (handshake_values[0] != 0) {
        cleanup();
        return Error{ErrorKind::kConnection,
                     "Prepare: handshake frame 1 expected value=0, got " +
                         std::to_string(handshake_values[0])};
    }
    if (handshake_values[1] != 1) {
        cleanup();
        return Error{ErrorKind::kConnection,
                     "Prepare: handshake frame 2 expected peer_id=1, got " +
                         std::to_string(handshake_values[1])};
    }
    if (handshake_values[2] != static_cast<uint64_t>(-1)) {
        cleanup();
        return Error{ErrorKind::kConnection,
                     "Prepare: handshake frame 3 expected value=-1 (shm_fd marker), got " +
                         std::to_string(handshake_values[2])};
    }

    const uint32_t n = n_workers_;

    // host_eventfd × n（host→guest 方向，本组件丢弃）
    for (uint32_t i = 0; i < n; ++i) {
        auto m = RecvMsgWithFd(doorbell_fd_);
        if (m.fd == -2) {
            cleanup();
            return Error{ErrorKind::kConnection,
                         "Prepare: failed to receive host_eventfd[" + std::to_string(i) + "]"};
        }
        if (m.fd >= 0) ::close(m.fd);
    }

    // vm_eventfd × n（guest→host 方向，注册到 epoll）
    doorbell_notify_fds_.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto m = RecvMsgWithFd(doorbell_fd_);
        if (m.fd == -2 || m.fd < 0) {
            cleanup();
            return Error{ErrorKind::kConnection,
                         "Prepare: failed to receive vm_eventfd[" + std::to_string(i) + "]"};
        }
        doorbell_notify_fds_.push_back(m.fd);
    }
    if (doorbell_notify_fds_.size() != static_cast<size_t>(n)) {
        cleanup();
        return Error{ErrorKind::kConnection,
                     "Prepare: expected " + std::to_string(n) +
                         " vm_eventfds, got " + std::to_string(doorbell_notify_fds_.size())};
    }
    for (uint32_t i = 0; i < n; ++i) {
        int fd = doorbell_notify_fds_[i];
        struct epoll_event ev{};
        ev.events   = EPOLLIN;
        ev.data.u32 = i;
        if (epoll_ctl(doorbell_epollfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            const int err = errno;
            cleanup();
            return Error{ErrorKind::kConnection,
                         std::string("Prepare: epoll_ctl(vm_eventfd[") +
                             std::to_string(i) + "]) failed: " + std::strerror(err)};
        }
        notify_fd_to_worker_[fd] = i;
    }
    return Result<void>::Ok();
}

void IvshmemDataPlane::Close()
{
    if (closed_.exchange(true, std::memory_order_acq_rel)) return;

    paused_.store(true, std::memory_order_relaxed);
    WakePoller();

    for (int fd : doorbell_notify_fds_) {
        if (fd >= 0) ::close(fd);
    }
    doorbell_notify_fds_.clear();
    notify_fd_to_worker_.clear();

    if (doorbell_fd_ >= 0)      { ::close(doorbell_fd_);      doorbell_fd_ = -1; }
    if (stop_eventfd_ >= 0)     { ::close(stop_eventfd_);     stop_eventfd_ = -1; }
    if (doorbell_epollfd_ >= 0) { ::close(doorbell_epollfd_); doorbell_epollfd_ = -1; }

    if (doorbell_server_) {
        doorbell_server_->Stop();
        doorbell_server_.reset();
    }
}

// ────────────────────────────────────────────────────────────────
// Pause / Resume
// ────────────────────────────────────────────────────────────────

void IvshmemDataPlane::Pause()
{
    paused_.store(true, std::memory_order_relaxed);
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid()) continue;
        ctrl_store_paused(wv.ctrl(), 1u);
    }
    WakePoller();
}

void IvshmemDataPlane::Resume()
{
    // 重建 daemon registration 视图。CLAIMED/READY 都表示 owner alive；
    // Submit 另行以 READY 门控 execution-domain sendability。
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid()) {
            if (reg_hook_.set_registered) reg_hook_.set_registered(i, false);
            continue;
        }
        WorkerCtrl* ctrl = wv.ctrl();
        uint32_t guest_state = ctrl_load_guest_state(ctrl);
        uint32_t host_state  = __atomic_load_n(&ctrl->host_state, __ATOMIC_ACQUIRE);
        const bool daemon_claimed =
            guest_state == static_cast<uint32_t>(GUEST_REG_CLAIMED) ||
            guest_state == static_cast<uint32_t>(GUEST_REG_READY);
        bool registered = daemon_claimed &&
                          host_state == static_cast<uint32_t>(HOST_REG_GRANTED);
        if (reg_hook_.set_registered) reg_hook_.set_registered(i, registered);
        ctrl_store_paused(ctrl, 0u);
    }
    paused_.store(false, std::memory_order_relaxed);
}

// ────────────────────────────────────────────────────────────────
// Submit
// ────────────────────────────────────────────────────────────────

SubmitOutcome IvshmemDataPlane::Submit(const SubmitInput& req)
{
    // 前置检查：越界
    if (req.worker_id >= n_workers_) return SubmitOutcome::kInvalid;

    // 暂停检查
    if (paused_.load(std::memory_order_relaxed)) return SubmitOutcome::kPaused;

    // Sendability（CP 权威）
    if (sendability_.is_registered && !sendability_.is_registered(req.worker_id)) {
        return SubmitOutcome::kWorkerDown;
    }

    auto wv = shm_->worker(req.worker_id);
    if (!wv.valid()) return SubmitOutcome::kInvalid;

    // Control-plane registration and execution-domain readiness are distinct.
    // CLAIMED keeps heartbeat/ownership alive during startup or recycle, while
    // only READY permits a task to cross the commit edge.
    if (ctrl_load_guest_state(wv.ctrl()) !=
        static_cast<uint32_t>(GUEST_REG_READY)) {
        return SubmitOutcome::kWorkerDown;
    }

    // payload 尺寸
    if (req.payload_size > wv.input_pool_size()) return SubmitOutcome::kInvalid;

    TaskSlot* task = wv.task_slot();
    CompletionSlot* completion = wv.completion_slot();
    WorkerCtrl* ctrl = wv.ctrl();

    // slot 繁忙
    if (task_load_state(task) != static_cast<uint32_t>(TASK_EMPTY)) return SubmitOutcome::kBusy;
    if (completion_load_state(completion) != static_cast<uint32_t>(COMP_EMPTY)) {
        return SubmitOutcome::kBusy;
    }

    // 写 payload（先于 state=READY）
    if (req.payload_data != nullptr && req.payload_size > 0) {
        std::memcpy(wv.input_pool(), req.payload_data, req.payload_size);
    }
    // result_page 不在 host 端清零：guest 侧 loop child 在 fork program 前
    // InitProgramResultPage() 写入本轮 executor_id/dispatch_gen 并把 state
    // 设为 RUNNING。host 永不直接读 result_page；commit-edge 仍是
    // CompletionSlot.state = COMP_READY + matching exec_seq/dispatch_gen。

    // 元数据
    task->executor_id  = req.executor_id;
    __atomic_store_n(&task->proc_id, req.proc_id, __ATOMIC_RELEASE);
    task->dispatch_gen = req.dispatch_gen;
    task->input_off    = 0;
    task->input_len    = static_cast<uint32_t>(req.payload_size);
    task->timeout_ms   = 0;  // 语义：Submit 层不再绑定 per-task timeout（由 Channel 监管）
    // [v2 Epic 5 PR-5-B — 当前版本] 透传 exec_flags (TaskSlot.flags wire 编码)
    task->flags        = req.exec_flags;
    // [RTT] sentinel: the guest overwrites this with the dispatch's executor_id
    // at TASK_TAKEN (sampled tasks only). Cleared here, before the TASK_READY
    // release store below, so the guest never reads a stale prior-task value.
    // Atomic RELEASE (not a plain store) to keep access to this cross-process
    // word uniformly atomic — the guest writes it with __ATOMIC_RELEASE and the
    // host reads it with __ATOMIC_ACQUIRE (SweepWorker); a bare store here would
    // be a non-atomic access to an otherwise-atomically-accessed object.
    __atomic_store_n(&task->worker_started_executor_id, 0ULL, __ATOMIC_RELEASE);
    completion->start_ts_us = 0;
    completion->finish_ts_us = 0;
    completion->exec_seq = 0;
    expected_executor_id_[req.worker_id] = req.executor_id;
    expected_dispatch_gen_[req.worker_id] = req.dispatch_gen;
    expected_proc_id_[req.worker_id] = req.proc_id;
    // A recovery re-dispatch keeps the same executor_id. Reset the per-slot
    // start observation here so that dispatch receives a fresh host timestamp
    // instead of reusing the previous attempt's acknowledgement.
    last_start_acked_exec_[req.worker_id] = 0;
    pending_start_ack_us_[req.worker_id] = 0;
    __atomic_store_n(&ctrl->cancel_requested, 0u, __ATOMIC_RELEASE);

    // 最后 RELEASE 写 state=TASK_READY
    task_store_state(task, TASK_READY);
    return SubmitOutcome::kSent;
}

// ────────────────────────────────────────────────────────────────
// Poll (含 Sweep 辅助)
// ────────────────────────────────────────────────────────────────

size_t IvshmemDataPlane::SweepWorker(uint32_t worker_id, std::vector<DispatchOutcome>& out)
{
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) return 0;

    CompletionSlot* completion = wv.completion_slot();
    TaskSlot*       task       = wv.task_slot();

    // [RTT] observe worker start BEFORE the completion-ready gate: read the
    // DURABLE marker (TaskSlot.worker_started_executor_id), NOT the volatile
    // TASK_TAKEN state — a fast task that already went TASK_EMPTY still leaves
    // the marker, so it is never missed. Stamp the host clock once per new start
    // that matches the in-flight executor_id for this worker.
    if (worker_id < expected_executor_id_.size() &&
        expected_executor_id_[worker_id] != 0) {
        const uint64_t started =
            __atomic_load_n(&task->worker_started_executor_id, __ATOMIC_ACQUIRE);
        if (started == expected_executor_id_[worker_id] &&
            started != last_start_acked_exec_[worker_id]) {
            pending_start_ack_us_[worker_id] = refuzz::core::MonotonicNowUs();
            last_start_acked_exec_[worker_id] = started;
        }
    }

    uint32_t state = completion_load_state(completion);
    if (state != static_cast<uint32_t>(COMP_READY)) return 0;

    auto discard_stale_completion = [&](const char* reason,
                                        bool may_clear_stale_task) {
        const uint64_t stale_executor_id = completion->executor_id;
        const uint32_t stale_dispatch_gen = completion->dispatch_gen;
        const uint64_t stale_exec_seq = completion->exec_seq;
        const uint32_t task_state = task_load_state(task);
        const bool task_matches_stale =
            task->executor_id == stale_executor_id &&
            task->dispatch_gen == stale_dispatch_gen;
        const bool task_matches_expected =
            worker_id < expected_executor_id_.size() &&
            expected_executor_id_[worker_id] != 0 &&
            task->executor_id == expected_executor_id_[worker_id] &&
            task->dispatch_gen == expected_dispatch_gen_[worker_id];
        const bool clear_task = may_clear_stale_task &&
            task_matches_stale && !task_matches_expected &&
            task_state != static_cast<uint32_t>(TASK_TAKEN);

        completion_store_state(completion, COMP_CONSUMED);
        completion_store_state(completion, COMP_EMPTY);
        if (clear_task) {
            task_store_state(task, TASK_EMPTY);
        }
        refuzz::logging::HostLogger::Instance().Log(
            "IvshmemDataPlane", "stale_completion_dropped",
            {refuzz::logging::Field("worker_id", worker_id),
             refuzz::logging::Field("reason", reason),
             refuzz::logging::Field("executor_id", stale_executor_id),
             refuzz::logging::Field("dispatch_gen", stale_dispatch_gen),
             refuzz::logging::Field("exec_seq", stale_exec_seq),
             refuzz::logging::Field("task_cleared", clear_task ? 1 : 0)});
    };

    if (worker_id < expected_executor_id_.size() &&
        expected_executor_id_[worker_id] != 0 &&
        (completion->executor_id != expected_executor_id_[worker_id] ||
         completion->dispatch_gen != expected_dispatch_gen_[worker_id])) {
        discard_stale_completion("identity_mismatch", true);
        return 0;
    }
    if (worker_id < last_completion_exec_seq_.size() &&
        completion->exec_seq != 0 &&
        completion->exec_seq <= last_completion_exec_seq_[worker_id]) {
        discard_stale_completion("non_monotonic_exec_seq", false);
        return 0;
    }
    const bool trace_sampled =
        (task->flags & TASK_FLAG_TRACE_SAMPLED) != 0;
    const uint64_t completion_observed_host_ts_us = trace_sampled
        ? refuzz::core::MonotonicNowUs() : 0;

    DispatchOutcome r;
    r.worker_id     = worker_id;
    r.proc_id       = __atomic_load_n(&task->proc_id, __ATOMIC_ACQUIRE);
    r.executor_id   = completion->executor_id;
    r.dispatch_gen  = completion->dispatch_gen;
    r.vendor_status = completion->status;
    r.kind          = TranslateStatus(completion->status);
    // [v3 Phase 4.4] 透传 worker-side 诊断信息：error_code / crash_signal
    //   供 QemuChannel AbnormalCompletion.diagnostics 使用；kind 翻译以 status 为准
    r.error_code    = completion->error_code;
    r.crash_signal  = completion->crash_signal;
    const bool proc_id_mismatch =
        worker_id < expected_proc_id_.size() &&
        expected_proc_id_[worker_id] != PROC_ID_ANY &&
        r.proc_id != expected_proc_id_[worker_id];
    if (proc_id_mismatch) {
        r.kind = DispatchOutcomeKind::kHarnessFatal;
        r.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
        r.crash_signal = 0;
    }
    r.worker_start_ts_us = completion->start_ts_us;
    r.worker_done_ts_us  = completion->finish_ts_us;
    // [RTT] attach the host-observed start ack iff we stamped a start for THIS
    // completion's executor_id (host clock, same steady_clock epoch as the other
    // trace timestamps). 0 when not sampled / no start observed.
    if (worker_id < pending_start_ack_us_.size() &&
        last_start_acked_exec_[worker_id] == completion->executor_id) {
        r.worker_start_ack_host_ts_us = pending_start_ack_us_[worker_id];
    }
    r.completion_observed_host_ts_us = completion_observed_host_ts_us;
    r.worker_clock_is_guest_monotonic = true;

    uint32_t out_off = completion->output_off;
    uint32_t out_len = completion->output_len;
    const size_t max_out = wv.output_pool_size();
    if (out_off >= max_out) out_len = 0;
    if (out_len > max_out - out_off) out_len = static_cast<uint32_t>(max_out - out_off);
    if (!proc_id_mismatch && out_len > 0) {
        r.output.resize(out_len);
        std::memcpy(r.output.data(), wv.output_pool() + out_off, out_len);
    }
    if (trace_sampled) {
        r.output_copied_host_ts_us = refuzz::core::MonotonicNowUs();
    }

    out.push_back(std::move(r));

    // 释放 slot
    completion_store_state(completion, COMP_CONSUMED);
    completion_store_state(completion, COMP_EMPTY);
    task_store_state(task, TASK_EMPTY);

    // 防御性清零 cancel_requested
    __atomic_store_n(&wv.ctrl()->cancel_requested, 0u, __ATOMIC_RELEASE);
    // 水位线只由“通过 expected 校验的完成”推进。孤儿 completion（没有在途
    // 任务时到达，例如旧 loop 死亡未被确认后仍写入）照常交付给上层按
    // executor_id 丢弃，但绝不能推进 last_completion_exec_seq_：新 daemon
    // 实例的 exec_seq 从 1 重新开始，被孤儿污染的水位线会把新实例前 N 条
    // 合法完成误判为 non-monotonic 丢弃。
    const bool had_expected_task =
        worker_id < expected_executor_id_.size() &&
        expected_executor_id_[worker_id] != 0;
    if (worker_id < expected_executor_id_.size()) {
        expected_executor_id_[worker_id] = 0;
        expected_dispatch_gen_[worker_id] = 0;
        expected_proc_id_[worker_id] = PROC_ID_ANY;
    }
    if (had_expected_task &&
        worker_id < last_completion_exec_seq_.size() &&
        completion->exec_seq != 0) {
        last_completion_exec_seq_[worker_id] = completion->exec_seq;
    }
    return 1;
}

size_t IvshmemDataPlane::SweepAllSlots(std::vector<DispatchOutcome>& out)
{
    size_t count = 0;
    for (uint32_t i = 0; i < n_workers_; ++i) {
        count += SweepWorker(i, out);
    }
    return count;
}

void IvshmemDataPlane::Poll(std::vector<DispatchOutcome>& out,
                             std::chrono::microseconds timeout)
{
    if (timeout <= std::chrono::microseconds{0}) {
        SweepAllSlots(out);
        if (poll_wake_pending_.exchange(false, std::memory_order_acq_rel) &&
            options_.use_doorbell) {
            DrainEventFd(stop_eventfd_);
        }
        return;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;

    if (!options_.use_doorbell) {
        // plain 模式没有 completion fd：用短 cv wait + wake flag 给出有界延迟，
        // 同时允许 host input / health / close 立即打断 blocking Poll。
        while (true) {
            if (closed_.load(std::memory_order_acquire)) return;

            size_t n = SweepAllSlots(out);
            if (n > 0) return;

            if (poll_wake_pending_.exchange(false, std::memory_order_acq_rel)) return;

            if (std::chrono::steady_clock::now() >= deadline) return;

            auto wait_until = std::chrono::steady_clock::now() + options_.poll_sleep_us;
            if (wait_until > deadline) wait_until = deadline;

            std::unique_lock<std::mutex> lock(poll_wake_mutex_);
            poll_wake_cv_.wait_until(lock, wait_until, [this] {
                return poll_wake_pending_.load(std::memory_order_acquire) ||
                       closed_.load(std::memory_order_acquire);
            });
        }
    }

    // doorbell 模式
    if (doorbell_epollfd_ < 0) return;
    while (true) {
        const auto now = std::chrono::steady_clock::now();

        if (closed_.load(std::memory_order_acquire)) return;

        size_t immediate = SweepAllSlots(out);
        if (immediate > 0) return;
        if (poll_wake_pending_.exchange(false, std::memory_order_acq_rel)) {
            DrainEventFd(stop_eventfd_);
            return;
        }
        if (now >= deadline) return;

        auto remaining_us = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - now).count();
        // [当前版本 防尾部忙轮询] epoll_wait 只有 ms 粒度。此处 remaining_us 恒 >0
        //   (上方 now>=deadline 已 return),(0,1000)µs 的正余时整除会得 0 →
        //   epoll_wait(0) 立即返回 → 本 while 在 deadline 尾部 epoll_wait(0)+
        //   SweepAllSlots 紧循环忙转,烧 host 核并抢 QEMU/worker。截不到 1ms 时
        //   兜底为 1ms,让 epoll 真阻塞:真 completion 由 doorbell 立即唤醒,故
        //   只影响"空闲超时"路径,过冲 <1ms,对 1ms 软轮询节奏可接受。
        int timeout_ms = static_cast<int>(remaining_us / 1000);
        if (timeout_ms < 1) timeout_ms = 1;

        struct epoll_event events[8];
        int nev = epoll_wait(doorbell_epollfd_, events, 8, timeout_ms);
        if (nev < 0) {
            if (errno == EINTR) continue;
            // 其他错误：扫描一次后退出，防止死循环
            SweepAllSlots(out);
            return;
        }
        bool host_wake = false;
        for (int e = 0; e < nev; ++e) {
            const uint32_t tag = events[e].data.u32;
            if (tag == kHostWakeEventTag) {
                DrainEventFd(stop_eventfd_);
                host_wake = true;
            } else if (tag < doorbell_notify_fds_.size()) {
                DrainEventFd(doorbell_notify_fds_[tag]);
            }
        }
        size_t n = SweepAllSlots(out);
        if (n > 0) return;
        if (host_wake ||
            poll_wake_pending_.exchange(false, std::memory_order_acq_rel)) {
            return;
        }
        // doorbell 提前触发但未就绪 → 继续等到 deadline
    }
}

// ────────────────────────────────────────────────────────────────
// Reset
// ────────────────────────────────────────────────────────────────
//
// DP 的 Reset 只清"数据面 slot 状态"（task/completion）；
// 控制面字段（ctrl host_state / cancel）由 CP 的 ResetSession 统一管。

void IvshmemDataPlane::ResetWorker(uint32_t worker_id)
{
    if (worker_id >= n_workers_) return;
    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) return;
    task_store_state(wv.task_slot(), TASK_EMPTY);
    completion_store_state(wv.completion_slot(), COMP_EMPTY);
    if (worker_id < expected_executor_id_.size()) {
        expected_executor_id_[worker_id] = 0;
        expected_dispatch_gen_[worker_id] = 0;
        expected_proc_id_[worker_id] = PROC_ID_ANY;
    }
    if (worker_id < last_completion_exec_seq_.size()) {
        last_completion_exec_seq_[worker_id] = 0;
    }
    if (worker_id < last_start_acked_exec_.size()) {
        last_start_acked_exec_[worker_id] = 0;
        pending_start_ack_us_[worker_id] = 0;
    }
}

void IvshmemDataPlane::ResetAll()
{
    for (uint32_t i = 0; i < n_workers_; ++i) {
        ResetWorker(i);
    }
}

// ────────────────────────────────────────────────────────────────
// Inflight 盘点
// ────────────────────────────────────────────────────────────────

std::vector<InflightEntry> IvshmemDataPlane::SnapshotInflight() const
{
    std::vector<InflightEntry> out;
    for (uint32_t i = 0; i < n_workers_; ++i) {
        auto wv = shm_->worker(i);
        if (!wv.valid()) continue;

        const TaskSlot* task = wv.task_slot();
        const uint32_t state = task_load_state(task);
        if (state == static_cast<uint32_t>(TASK_EMPTY)) continue;

        InflightEntry e;
        e.worker_id    = i;
        e.executor_id  = task->executor_id;
        e.dispatch_gen = task->dispatch_gen;
        // [crash-terminal] TASK_TAKEN = worker actively executing (crash-suspect);
        // TASK_READY = submitted but not yet picked up (innocent, never ran).
        e.was_running  = (state == static_cast<uint32_t>(TASK_TAKEN));

        const WorkerCtrl* ctrl = wv.ctrl();
        e.cancel_requested =
            __atomic_load_n(&ctrl->cancel_requested, __ATOMIC_ACQUIRE) != 0;
        e.cancel_observed_seq =
            __atomic_load_n(&ctrl->cancel_observed_seq, __ATOMIC_ACQUIRE);
        out.push_back(e);
    }
    return out;
}

// ────────────────────────────────────────────────────────────────
// 可发检查 + Doorbell 唤醒
// ────────────────────────────────────────────────────────────────

bool IvshmemDataPlane::IsWorkerSendable(uint32_t worker_id) const
{
    if (worker_id >= n_workers_) return false;
    if (sendability_.is_registered && !sendability_.is_registered(worker_id)) return false;
    if (paused_.load(std::memory_order_relaxed)) return false;

    auto wv = shm_->worker(worker_id);
    if (!wv.valid()) return false;
    if (task_load_state(wv.task_slot()) != static_cast<uint32_t>(TASK_EMPTY)) return false;
    if (completion_load_state(wv.completion_slot()) != static_cast<uint32_t>(COMP_EMPTY)) return false;
    return true;
}

uint32_t IvshmemDataPlane::CountSendableWorkers() const
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < n_workers_; ++i) {
        if (IsWorkerSendable(i)) ++count;
    }
    return count;
}

void IvshmemDataPlane::WakePoller() noexcept
{
    poll_wake_pending_.store(true, std::memory_order_release);
    poll_wake_cv_.notify_all();
    WakeDoorbellPoller();
}

void IvshmemDataPlane::WakeDoorbellPoller() noexcept
{
    if (!options_.use_doorbell || stop_eventfd_ < 0) return;
    const uint64_t val = 1;
    const ssize_t n = write(stop_eventfd_, &val, sizeof(val));
    (void)n;
}

} // namespace refuzz::channel::data
