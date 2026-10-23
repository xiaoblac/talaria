#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/adapter/ivshmem_adapter.hpp"
#include "worker/ivshmem_attach.hpp"
#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <cstddef>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <chrono>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

#define IVSHMEM_IOCTL_CLEAR 0x01
#define IVSHMEM_IOCTL_RING 0x02
#define IVSHMEM_IOCTL_SET_VECTOR 0x03

extern volatile sig_atomic_t g_running;

namespace refuzz::worker {
namespace {

void ring_doorbell(int driver_fd, void* bar0, int peer_id, uint32_t vector)
{
    uint32_t val = (static_cast<uint32_t>(peer_id) << 16) | (vector & 0xFFFFU);
    if (driver_fd >= 0) {
        (void)ioctl(driver_fd, IVSHMEM_IOCTL_RING, &val);
        return;
    }
    if (bar0 != nullptr) {
        volatile uint32_t* reg = reinterpret_cast<volatile uint32_t*>(
            reinterpret_cast<uint8_t*>(bar0) + IVSHMEM_REG_DOORBELL);
        *reg = val;
    }
}

uint32_t normalize_input_len(const TaskSlot* task)
{
    const uint32_t in_off = task->input_off;
    const uint32_t in_len = task->input_len;
    if (in_off >= MAX_INPUT_SIZE) {
        return 0;
    }
    const uint32_t cap = MAX_INPUT_SIZE - in_off;
    return (in_len <= cap) ? in_len : cap;
}

bool IsKnownCompletionStatus(uint32_t status)
{
    switch (status) {
        case COMP_STATUS_OK:
        case COMP_STATUS_CRASHED:
        case COMP_STATUS_TIMEOUT:
        case COMP_STATUS_CANCELLED:
        case COMP_STATUS_NO_RESULT:
        case COMP_STATUS_CHILD_ABORTED:
        case COMP_STATUS_PARTIAL:
        case COMP_STATUS_HARNESS_FATAL:
        case COMP_STATUS_HARNESS_RECOVERED:
        case COMP_STATUS_INFRA_FAULT:
        case COMP_STATUS_UNKNOWN:
        case COMP_STATUS_HUNG:
            return true;
        default:
            return false;
    }
}

} // namespace

IvshmemWorkerAdapter::IvshmemWorkerAdapter(Config config)
    : config_(config)
{
}

IvshmemWorkerAdapter::~IvshmemWorkerAdapter()
{
    Cleanup();
}

int IvshmemWorkerAdapter::Init()
{
    IvshmemMapping mapping;
    std::string error_message;
    if (!AttachIvshmemMapping(&mapping, &error_message)) {
        LOG("%s", error_message.c_str());
        return -1;
    }

    shm_ = mapping.shm;
    bar2_size_ = mapping.shm_size;
    bar0_ = mapping.bar0;
    bar0_size_ = mapping.bar0_size;
    driver_fd_ = mapping.driver_fd;
    resource2_fd_ = mapping.resource2_fd;

    // BAR0 = doorbell/MSI-X 寄存器，只有 daemon 需要写 doorbell。把 BAR0 标记
    // DONTFORK：daemon→loop_child→program_child 链条上的所有 fork 都不再继承
    // BAR0，program child 拿不到 doorbell 寄存器 → 不能伪造完成中断。
    // 这是 "唯一提交边 = CompletionSlot.state = COMP_READY" 的硬前提之一，
    // madvise 失败 = 致命。
    if (bar0_ != nullptr && bar0_size_ != 0) {
        if (::madvise(bar0_, bar0_size_, MADV_DONTFORK) != 0) {
            LOG("madvise BAR0 MADV_DONTFORK failed: %s (size=%zu)",
                strerror(errno), bar0_size_);
            return -1;
        }
    }

    hdr_ = reinterpret_cast<ShmHeader*>(shm_);
    if (hdr_ == nullptr || hdr_->magic != IVSHMEM_MAGIC || hdr_->version != PROTOCOL_VERSION) {
        LOG("invalid shm header (magic=0x%x, version=%u)",
            hdr_ ? hdr_->magic : 0,
            hdr_ ? hdr_->version : 0);
        return -1;
    }
    if (config_.worker_id >= hdr_->n_workers) {
        LOG("worker_id out of range: %u >= %u", config_.worker_id, hdr_->n_workers);
        return -1;
    }
    if (!shm_header_has_v3_layout(hdr_)) {
        LOG("invalid V3 shm layout descriptors");
        return -1;
    }
    // V3 layout 是唯一布局，header 必须显式把 worker_area_size
    // 置零；非零意味着 host 还在按旧节奏写 layout，layout/descriptor 不可信。
    if (hdr_->worker_area_size != 0) {
        LOG("invalid V3 header: worker_area_size must be 0 in version=%u (got %u)",
            hdr_->version, hdr_->worker_area_size);
        return -1;
    }

    control_area_ = get_worker_control_area_v3(shm_, config_.worker_id);
    data_window_ = get_worker_data_window_v3(shm_, config_.worker_id);
    if (control_area_ == nullptr || data_window_ == nullptr) {
        LOG("failed to map worker control/data for worker=%u", config_.worker_id);
        return -1;
    }

    ctrl_ = &control_area_->ctrl;
    task_ = &control_area_->task;
    completion_ = &control_area_->completion;

    step_event_hdr_ = get_step_event_ring_header_v3(shm_);
    step_event_slots_ = get_step_event_slots_v3(shm_);
    step_event_capacity_ = (step_event_hdr_ != nullptr) ? step_event_hdr_->capacity : 0;

    completion_slot_store_state_v3(completion_, COMP_EMPTY);
    task_slot_store_state_v3(task_, TASK_EMPTY);

    reg_epoch_ = 0;
    exec_seq_ = 0;
    current_executor_id_ = 0;
    current_dispatch_gen_ = 0;
    current_timeout_ms_ = 0;
    current_input_len_ = 0;
    current_cancel_requested_ = false;
    domain_ready_.store(false, std::memory_order_release);
    transport_failed_.store(false, std::memory_order_release);
    __atomic_store_n(&task_->proc_id, PROC_ID_ANY, __ATOMIC_RELEASE);

    LOG("adapter init ok: worker=%u driver_fd=%d bar2_size=%llu",
        config_.worker_id,
        driver_fd_,
        static_cast<unsigned long long>(bar2_size_));
    return 0;
}

int IvshmemWorkerAdapter::Handshake()
{
    while (g_running && load_host_ready_v3(hdr_) != 1U) {
        usleep(10000);
    }
    return g_running ? 0 : -1;
}

int IvshmemWorkerAdapter::Register()
{
    if (hdr_ == nullptr || ctrl_ == nullptr || task_ == nullptr || completion_ == nullptr) {
        return -1;
    }

    const uint32_t epoch = __atomic_load_n(&hdr_->reg_epoch, __ATOMIC_ACQUIRE);
    reg_epoch_ = epoch;

    __atomic_store_n(&ctrl_->error_latch, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl_->cancel_observed_seq, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl_->guest_state, static_cast<uint32_t>(GUEST_REG_CLAIMED), __ATOMIC_RELEASE);

    if (driver_fd_ >= 0) {
        uint32_t v = config_.worker_id;
        if (ioctl(driver_fd_, IVSHMEM_IOCTL_SET_VECTOR, &v) < 0) {
            LOG("ioctl SET_VECTOR failed: %s", strerror(errno));
            return -1;
        }
    }

    // CLAIMED means the daemon/control loop owns this worker slot. The store at
    // guest_state above is itself the host-observable proof that we got here —
    // it is one of the components of the progress token the host samples (see
    // control_plane.hpp WorkerHeartbeatSample). No separate liveness thread.

    while (g_running) {
        const uint32_t host_ready = load_host_ready_v3(hdr_);
        const uint32_t host_state = __atomic_load_n(&ctrl_->host_state, __ATOMIC_ACQUIRE);
        const uint32_t reg_epoch = __atomic_load_n(&hdr_->reg_epoch, __ATOMIC_ACQUIRE);
        if (reg_epoch != reg_epoch_) {
            reg_epoch_ = reg_epoch;
        }
        if (host_ready == 1U && host_state == static_cast<uint32_t>(HOST_REG_GRANTED)) {
            break;
        }
        usleep(1000);
    }
    if (!g_running) {
        return -1;
    }

    __atomic_store_n(&ctrl_->host_state, static_cast<uint32_t>(HOST_REG_GRANTED), __ATOMIC_RELEASE);
    SetDomainReady(domain_ready_.load(std::memory_order_acquire));

    LOG("registered daemon worker=%u reg_epoch=%u domain_ready=%u",
        config_.worker_id, reg_epoch_,
        domain_ready_.load(std::memory_order_acquire) ? 1u : 0u);
    return 0;
}

bool IvshmemWorkerAdapter::NeedReregister()
{
    if (hdr_ == nullptr || ctrl_ == nullptr) {
        return false;
    }
    const uint32_t host_ready = load_host_ready_v3(hdr_);
    const uint32_t reg_epoch = __atomic_load_n(&hdr_->reg_epoch, __ATOMIC_ACQUIRE);
    const uint32_t guest_state = __atomic_load_n(&ctrl_->guest_state, __ATOMIC_ACQUIRE);
    return host_ready != 1U || reg_epoch != reg_epoch_ ||
           guest_state == static_cast<uint32_t>(GUEST_REG_DEAD);
}

bool IvshmemWorkerAdapter::CancelRequested() const
{
    if (ctrl_ == nullptr) {
        return false;
    }
    return __atomic_load_n(&ctrl_->cancel_requested, __ATOMIC_ACQUIRE) != 0U;
}

void IvshmemWorkerAdapter::SetDomainReady(bool ready)
{
    if (ready && transport_failed_.load(std::memory_order_acquire)) {
        return;
    }
    domain_ready_.store(ready, std::memory_order_release);
    if (ctrl_ == nullptr) {
        return;
    }
    const uint32_t guest_state =
        __atomic_load_n(&ctrl_->guest_state, __ATOMIC_ACQUIRE);
    if (guest_state != static_cast<uint32_t>(GUEST_REG_CLAIMED) &&
        guest_state != static_cast<uint32_t>(GUEST_REG_READY)) {
        return;
    }
    const uint32_t host_state =
        __atomic_load_n(&ctrl_->host_state, __ATOMIC_ACQUIRE);
    const GuestRegState publish_state =
        ready && host_state == static_cast<uint32_t>(HOST_REG_GRANTED)
        ? GUEST_REG_READY : GUEST_REG_CLAIMED;
    __atomic_store_n(&ctrl_->guest_state,
                     static_cast<uint32_t>(publish_state),
                     __ATOMIC_RELEASE);
}

std::optional<WorkerIO> IvshmemWorkerAdapter::WaitTask(std::chrono::milliseconds timeout)
{
    if (NeedReregister()) {
        if (Register() != 0) {
            LOG("worker %u re-registration failed", config_.worker_id);
            return std::nullopt;
        }
    }

    if (ctrl_ == nullptr || task_ == nullptr || completion_ == nullptr) {
        return std::nullopt;
    }

    if (__atomic_load_n(&ctrl_->paused, __ATOMIC_ACQUIRE) != 0U) {
        return std::nullopt;
    }

    const int wait_ms = static_cast<int>(timeout.count());
    if (driver_fd_ >= 0) {
        struct pollfd pfd;
        pfd.fd = driver_fd_;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = poll(&pfd, 1, wait_ms);
        // [当前版本] 只在真有 POLLIN（doorbell 中断到达）时才 CLEAR。poll 超时/
        //   出错（pr<=0 或无 POLLIN）时没有 pending 中断可清，原先无条件 ioctl 让
        //   每次空等都白进一次驱动 syscall。漏清不会出错：若中断在 poll 检查后才
        //   到，下一次 poll 立即返回 POLLIN 时再清；task 就绪由 shm state 判定
        //   （下方 TASK_READY），与中断清除解耦。
        if (pr > 0 && (pfd.revents & POLLIN)) {
            (void)ioctl(driver_fd_, IVSHMEM_IOCTL_CLEAR, 0);
        }
    } else if (wait_ms > 0) {
        usleep(static_cast<useconds_t>(wait_ms) * 1000U);
    }

    const uint32_t task_state = task_slot_load_state_v3(task_);
    if (task_state != static_cast<uint32_t>(TASK_READY)) {
        return std::nullopt;
    }

    uint32_t expected = static_cast<uint32_t>(TASK_READY);
    if (!__atomic_compare_exchange_n(const_cast<uint32_t*>(&task_->state),
                                     &expected,
                                     static_cast<uint32_t>(TASK_TAKEN),
                                     false,
                                     __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        return std::nullopt;
    }

    current_executor_id_ = task_->executor_id;
    current_dispatch_gen_ = task_->dispatch_gen;
    current_timeout_ms_ = task_->timeout_ms;
    current_input_len_ = normalize_input_len(task_);
    current_cancel_requested_ = CancelRequested();
    completion_->start_ts_us = now_us();
    completion_->finish_ts_us = 0;
    // [RTT] host-observed start: for sampled tasks publish a DURABLE marker
    // (this dispatch's executor_id) — it survives the later TASK_EMPTY, unlike
    // the volatile `state`, so the host never misses a fast task — then ring the
    // doorbell so the host wakes and stamps its own (host) clock. Gated on the
    // wire flag => zero cost when the task is not RTT-sampled. See
    // docs/plans/rtt-host-start-ack.md.
    if (task_->flags & TASK_FLAG_TRACE_SAMPLED) {
        __atomic_store_n(&task_->worker_started_executor_id,
                         current_executor_id_, __ATOMIC_RELEASE);
        RingDoorbell();
    }

    WorkerIO io{};
    ProgramResultPageV3* result_page = &data_window_->result_page;
    io.input_buf = data_window_->input_pool + task_->input_off;
    io.input_len = current_input_len_;
    io.output_buf = data_window_->output_pool;
    io.output_cap = MAX_OUTPUT_SIZE;
    io.crash_output_len = &result_page->crash_len;
    io.result_page = result_page;
    io.executor_id = current_executor_id_;
    io.dispatch_gen = current_dispatch_gen_;
    io.timeout_ms = current_timeout_ms_;
    io.flags = task_->flags;
    io.target_proc_id = __atomic_load_n(&task_->proc_id, __ATOMIC_ACQUIRE);
    io.cancel_requested = current_cancel_requested_;
    io.buffers.source = ProgramBufferSource::kIvshmemDataWindowV3;
    io.buffers.worker_id = config_.worker_id;
    const uint64_t worker_data_offset = static_cast<uint64_t>(
        get_worker_data_offset_v3(hdr_, config_.worker_id));
    io.buffers.input_offset =
        worker_data_offset + static_cast<uint64_t>(hdr_->data_input_offset) + task_->input_off;
    io.buffers.output_offset =
        worker_data_offset + static_cast<uint64_t>(hdr_->data_output_offset);
    io.buffers.result_page_offset =
        worker_data_offset + static_cast<uint64_t>(hdr_->data_result_offset);

    if (config_.enable_step_events && !io.cancel_requested) {
        WriteStepEvent(io.executor_id, STEP_PHASE_BEFORE, COMP_STATUS_OK, 0);
    }

    return io;
}

void IvshmemWorkerAdapter::ReportDone(const TaskResult& result)
{
    if (completion_ == nullptr || task_ == nullptr || ctrl_ == nullptr) {
        transport_failed_.store(true, std::memory_order_release);
        return;
    }

    // [v1 gate <= COMP_STATUS_EXEC_ERROR — ROLLBACK: uncomment below and remove v2]
    // CompletionStatus completion_status = StatusFromTaskResult(result);
    // if (result.completion_status <= static_cast<uint32_t>(COMP_STATUS_EXEC_ERROR)) {
    //     completion_status = static_cast<CompletionStatus>(result.completion_status);
    // }
    // Explicit status passthrough. Do not use numeric <= gates: new statuses
    // such as PARTIAL may be appended after older enum values.
    CompletionStatus completion_status = StatusFromTaskResult(result);
    if (IsKnownCompletionStatus(result.completion_status)) {
        completion_status = static_cast<CompletionStatus>(result.completion_status);
    }

    uint32_t spins = 0;
    while (g_running &&
           completion_slot_load_state_v3(completion_) != static_cast<uint32_t>(COMP_EMPTY)) {
        if (++spins > 1000) {
            break;
        }
        usleep(1000);
    }

    if (completion_slot_load_state_v3(completion_) !=
        static_cast<uint32_t>(COMP_EMPTY)) {
        LOG("completion publication blocked worker=%u executor_id=%llu "
            "dispatch_gen=%u occupied_executor_id=%llu occupied_dispatch_gen=%u "
            "occupied_state=%u",
            config_.worker_id,
            static_cast<unsigned long long>(
                result.executor_id != 0 ? result.executor_id
                                        : current_executor_id_),
            result.dispatch_gen != 0 ? result.dispatch_gen
                                     : current_dispatch_gen_,
            static_cast<unsigned long long>(completion_->executor_id),
            completion_->dispatch_gen,
            completion_slot_load_state_v3(completion_));
        SetDomainReady(false);
        transport_failed_.store(true, std::memory_order_release);
        if (!PublishMaintenanceError(ERR_HARNESS_FORK_SERVER_PROTOCOL)) {
            LOG("completion publication fault latch failed worker=%u",
                config_.worker_id);
        }
        return;
    }

    completion_->executor_id = (result.executor_id != 0)
        ? result.executor_id : current_executor_id_;
    completion_->dispatch_gen = (result.dispatch_gen != 0) ? result.dispatch_gen : current_dispatch_gen_;
    completion_->status = static_cast<uint32_t>(completion_status);
    completion_->error_code = result.error_code;
    completion_->crash_signal = result.crash_signal;
    completion_->output_off = 0;
    completion_->output_len = (result.output_len <= MAX_OUTPUT_SIZE) ? result.output_len : MAX_OUTPUT_SIZE;
    completion_->finish_ts_us = now_us();
    completion_->exec_seq = ++exec_seq_;

    __atomic_store_n(&task_->proc_id, result.proc_id, __ATOMIC_RELEASE);
    if (data_window_ != nullptr) {
        data_window_->result_page.proc_id = result.proc_id;
    }

    completion_slot_store_state_v3(completion_, COMP_READY);

    if (completion_status == COMP_STATUS_CANCELLED || result.cancel_observed || current_cancel_requested_) {
        MarkCancelObserved();
    }

    task_slot_store_state_v3(task_, TASK_EMPTY);

    if (config_.enable_step_events) {
        WriteStepEvent(completion_->executor_id,
                       STEP_PHASE_AFTER,
                       completion_status,
                       0);
    }

    current_executor_id_ = 0;
    current_dispatch_gen_ = 0;
    current_timeout_ms_ = 0;
    current_input_len_ = 0;
    current_cancel_requested_ = false;

    RingDoorbell();
}

// [心跳重定义 — 2026-07-17] 这里原本有一个 SCHED_FIFO 心跳线程(counter++ / sleep 1s /
//   每 5s 往串口打一条 tick 日志),已整体删除。host 判 worker 存活改读**执行状态机的进度
//   令牌**(见 control_plane.hpp WorkerHeartbeatSample):令牌由 start_ts_us / exec_seq /
//   proc_epoch / guest_state 合成,全部是执行路径本来就会写的 shm 字段。
//
//   删掉的理由,按分量记在这里,免得日后有人"补一个心跳回来":
//
//   (1) **它证明不了要证明的东西。** 心跳只说"有个线程还在 tick",而我们要判的是
//       "daemon 还能不能干活"。存在性证明要求被检测方健康到能自证 —— 恰恰在它不健康时
//       最先失效。而 completion / proc_epoch 是 work product:不干活就发不出来。
//
//   (2) **它自己就是头号故障嫌疑。** 那条每 5s 一次的 LOG × 6 worker 常年往串口刷;串口
//       一拥塞(一次 dump_stack 风暴就够),这个 **RT 优先级** 线程就卡在自己的日志写上,
//       SCHED_OTHER 抢不走它,2vCPU 下直接吃满一颗 → 整机失联。原注释断言"计数器只在
//       【进程真死 / VM 整体冻死 / panic】时才停"—— 漏了第四种:**心跳卡在自己的串口写上**。
//       这与 2026-07-16 那次事故的症状严丝合缝(心跳停 + SSH 死 + 内核毫无报告)。
//
//   (3) **它买不到任何延迟优势。** 它的阈值曾被 orchestrator_config.cpp 的地板强制
//       ≥ exec_timeout + 2×poll —— 这条地板的存在本身就证明它会被饿死到一整个程序执行
//       时长,即它的检测延迟本来就锁在 exec_timeout 量级,和 host 侧纯推导的判据同一尺度。
//
//   对齐 syzkaller:host 从不向 guest 索要存活证明。它只看进度
//   (injectExec / "executed programs:" 刷新 lastExecuteTime),超时兜底交给 NoOutput。

void IvshmemWorkerAdapter::WriteStepEvent(uint64_t executor_id,
                                          StepEventPhase phase,
                                          CompletionStatus status,
                                          uint32_t op_index)
{
    if (step_event_hdr_ == nullptr || step_event_slots_ == nullptr) {
        return;
    }
    if (!is_power_of_two_u32(step_event_capacity_)) {
        return;
    }

    const uint64_t pos = step_event_head_fetch_add_v3(step_event_hdr_, 1);
    StepEventSlot* slot = &step_event_slots_[static_cast<uint32_t>(pos & (step_event_capacity_ - 1U))];

    step_event_seq_store_v3(slot, 0ULL);
    slot->worker_id = config_.worker_id;
    slot->actor_id = config_.worker_id;
    slot->executor_id = executor_id;
    slot->op_index = op_index;
    slot->phase = static_cast<uint32_t>(phase);
    slot->status = static_cast<uint32_t>(status);
    slot->ts_us = now_us();
    __atomic_thread_fence(__ATOMIC_RELEASE);
    step_event_seq_store_v3(slot, pos + 1ULL);
}

void IvshmemWorkerAdapter::MarkCancelObserved()
{
    if (ctrl_ == nullptr) {
        return;
    }
    __atomic_add_fetch(&ctrl_->cancel_observed_seq, 1U, __ATOMIC_ACQ_REL);
}

CompletionStatus IvshmemWorkerAdapter::StatusFromTaskResult(const TaskResult& result)
{
    if (result.error_code == ERR_TASK_CANCELLED) {
        return COMP_STATUS_CANCELLED;
    }
    if (result.error_code == ERR_PROGRAM_CHILD_CRASHED) {
        return COMP_STATUS_CHILD_ABORTED;
    }
    if (result.error_code == ERR_TIMEOUT) {
        return COMP_STATUS_TIMEOUT;
    }
    // hang-evidence 原因（daemon watchdog 11 / reap 类 8/9/12）→ HUNG。
    if (result.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT ||
        result.error_code == ERR_HARNESS_MAIN_REAP_FAILED ||
        result.error_code == ERR_HARNESS_STOPPED_REAP_TIMEOUT ||
        result.error_code == ERR_HARNESS_CLEANUP_FAILED) {
        return COMP_STATUS_HUNG;
    }
    // infra 原因（outer fork 6/7 / post-exit 协议错 10 / KCOV 13）→ HARNESS_FATAL。
    if (result.error_code == ERR_HARNESS_OUTER_FORK_EAGAIN ||
        result.error_code == ERR_HARNESS_OUTER_FORK_FAILED ||
        result.error_code == ERR_HARNESS_FORK_SERVER_PROTOCOL ||
        result.error_code == ERR_HARNESS_KCOV_STATE_INVALID) {
        return COMP_STATUS_HARNESS_FATAL;
    }
    if (result.error_code == ERR_WORKER_CRASHED || result.crash_signal != 0) {
        return COMP_STATUS_CRASHED;
    }
    if (result.error_code == ERR_INVALID_INPUT ||
        result.error_code == ERR_EXECUTOR_ERROR) {
        return COMP_STATUS_INFRA_FAULT;   // 配置错 / worker 运行时故障,程序无罪
    }
    if (result.error_code == ERR_OK && result.status == 0) {
        return COMP_STATUS_OK;
    }
    // fallback 兜底:error_code 不认识(含阶段相关的 14/15 —— 执行阶段是 HUNG、
    // rebind 是 HARNESS_FATAL,无阶段信息时不能猜)。domain_supervisor 恒显式设
    // completion_status,走到这里只在旧调用方漏设 → 报 UNKNOWN 让它显形,
    // 不伪装成 exec_error。
    return COMP_STATUS_UNKNOWN;
}

void IvshmemWorkerAdapter::Cleanup()
{
    domain_ready_.store(false, std::memory_order_release);

    if (ctrl_ != nullptr) {
        __atomic_store_n(&ctrl_->guest_state, static_cast<uint32_t>(GUEST_REG_DEAD), __ATOMIC_RELEASE);
    }

    if (bar0_ != nullptr) {
        munmap(bar0_, bar0_size_);
        bar0_ = nullptr;
    }
    if (shm_ != nullptr) {
        munmap(shm_, bar2_size_);
        shm_ = nullptr;
    }
    if (driver_fd_ >= 0) {
        close(driver_fd_);
        driver_fd_ = -1;
    }
    if (resource2_fd_ >= 0) {
        close(resource2_fd_);
        resource2_fd_ = -1;
    }

    hdr_ = nullptr;
    control_area_ = nullptr;
    data_window_ = nullptr;
    ctrl_ = nullptr;
    task_ = nullptr;
    completion_ = nullptr;
    step_event_hdr_ = nullptr;
    step_event_slots_ = nullptr;
    step_event_capacity_ = 0;
}

void IvshmemWorkerAdapter::RingDoorbell()
{
    ring_doorbell(driver_fd_, bar0_, config_.peer_id, config_.worker_id);
}

void IvshmemWorkerAdapter::BumpExecSeq()
{
    ++exec_seq_;
}

PersistedProcState IvshmemWorkerAdapter::LoadProcState() const
{
    PersistedProcState state{};
    if (ctrl_ == nullptr ||
        __atomic_load_n(&ctrl_->proc_state_magic, __ATOMIC_ACQUIRE) !=
            PROC_ID_STATE_MAGIC) {
        return state;
    }
    state.proc_id = __atomic_load_n(&ctrl_->active_proc_id, __ATOMIC_ACQUIRE);
    state.epoch = __atomic_load_n(&ctrl_->proc_epoch, __ATOMIC_ACQUIRE);
    state.dirty_proc_mask =
        __atomic_load_n(&ctrl_->dirty_proc_mask, __ATOMIC_ACQUIRE);
    state.valid = state.proc_id < 32u;
    return state;
}

bool IvshmemWorkerAdapter::PublishProcState(uint32_t proc_id, uint32_t epoch)
{
    if (ctrl_ == nullptr || proc_id >= 32u) {
        return false;
    }
    __atomic_store_n(&ctrl_->active_proc_id, proc_id, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl_->proc_epoch, epoch, __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl_->proc_state_magic,
                     PROC_ID_STATE_MAGIC,
                     __ATOMIC_RELEASE);
    return true;
}

bool IvshmemWorkerAdapter::PublishDirtyProcMask(uint32_t dirty_proc_mask)
{
    if (ctrl_ == nullptr) {
        return false;
    }
    __atomic_store_n(&ctrl_->dirty_proc_mask,
                     dirty_proc_mask,
                     __ATOMIC_RELEASE);
    return true;
}

bool IvshmemWorkerAdapter::PublishMaintenanceError(uint32_t error_code)
{
    if (ctrl_ == nullptr || error_code == ERR_OK) {
        return false;
    }
    uint32_t expected = ERR_OK;
    if (!__atomic_compare_exchange_n(&ctrl_->error_latch,
                                     &expected,
                                     error_code,
                                     false,
                                     __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        return false;
    }
    RingDoorbell();
    return true;
}

// V3 typed 接口:暴露 child-visible data window,不暴露 control region。
WorkerDataWindowV3* IvshmemWorkerAdapter::GetWorkerDataWindow()
{
    return data_window_;
}

uint32_t IvshmemWorkerAdapter::GetCrashOutputLen() const
{
    if (data_window_ == nullptr) {
        return 0U;
    }
    return __atomic_load_n(&data_window_->result_page.crash_len, __ATOMIC_ACQUIRE);
}

bool IvshmemWorkerAdapter::GetExecutionDomainTransport(
    ExecutionDomainTransport* out) const
{
    if (out == nullptr || hdr_ == nullptr || data_window_ == nullptr ||
        resource2_fd_ < 0) {
        return false;
    }
    const uint64_t window_offset = static_cast<uint64_t>(
        get_worker_data_offset_v3(hdr_, config_.worker_id));
    out->backing_fd = resource2_fd_;
    out->mapping.source = ProgramBufferSource::kIvshmemDataWindowV3;
    out->mapping.worker_id = config_.worker_id;
    out->mapping.local_base = static_cast<uint8_t*>(shm_) + window_offset;
    out->mapping.resource_offset = window_offset;
    out->mapping.mapped_size = hdr_->per_worker_data_stride;
    out->mapping.input_offset =
        window_offset + static_cast<uint64_t>(hdr_->data_input_offset);
    out->mapping.input_size = hdr_->data_input_size;
    out->mapping.output_offset =
        window_offset + static_cast<uint64_t>(hdr_->data_output_offset);
    out->mapping.output_size = hdr_->data_output_size;
    out->mapping.result_page_offset =
        window_offset + static_cast<uint64_t>(hdr_->data_result_offset);
    out->mapping.result_page_size = hdr_->data_result_size;
    out->step_ring_offset = hdr_->step_ring_offset;
    out->step_ring_size = hdr_->step_ring_size;
    out->step_ring_capacity = hdr_->step_event_ring_capacity;
    return true;
}

void IvshmemWorkerAdapter::ResetOutputLen()
{
    // result_page 的权威清零由 loop child 在 InitProgramResultPage() 完成
    // (loop_runtime.cpp)。daemon 这层只需把 host-visible 的 CompletionSlot.output_len
    // 归零即可，避免 daemon 越 fork 边界去写 data window 上的 page。
    if (completion_ != nullptr) {
        completion_->output_len = 0;
    }
}

} // namespace refuzz::worker
