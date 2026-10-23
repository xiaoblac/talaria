#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"

#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/program/xiuos/xiuos_result.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>

namespace refuzz::channel::data {

namespace {

using refuzz::channel::Result;

std::uint64_t NowMicros() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace

XiuosUartDataPlane::XiuosUartDataPlane(Config cfg)
    : config_(std::move(cfg)) {
    if (!config_.backbone) {
        throw std::invalid_argument(
            "XiuosUartDataPlane: backbone must be non-null");
    }
    if (config_.poll_slice <= std::chrono::milliseconds(0)) {
        config_.poll_slice = std::chrono::milliseconds(10);
    }
}

std::uint16_t XiuosUartDataPlane::SeqFromExecutor(std::uint64_t executor_id) noexcept {
    return static_cast<std::uint16_t>(executor_id & 0xFFFFu);
}

DispatchOutcomeKind
XiuosUartDataPlane::TranslateStatus(
    refuzz::program::xiuos::XiuosResultStatus s) noexcept {
    using refuzz::program::xiuos::XiuosResultStatus;
    switch (s) {
        case XiuosResultStatus::Ok:              return DispatchOutcomeKind::kOk;
        case XiuosResultStatus::ProgramRejected: return DispatchOutcomeKind::kInfraFault;
        case XiuosResultStatus::UnsupportedApi:  return DispatchOutcomeKind::kInfraFault;
        case XiuosResultStatus::WorkerError:     return DispatchOutcomeKind::kInfraFault;
        // StateViolation is a VALID response (the worker answered) that carries
        // a detected heap/state-corruption finding in aux — map it to kOk so it
        // surfaces as a Completion the v1 oracle reads vendor_aux from; callers
        // distinguish it via vendor_status == XIUOS_STATUS_STATE_VIOLATION.
        case XiuosResultStatus::StateViolation:  return DispatchOutcomeKind::kOk;
        // ContractViolation, like StateViolation, is a VALID response (worker
        // healthy): map to kOk so it surfaces as a Completion; callers distinguish
        // it via vendor_status == XIUOS_STATUS_CONTRACT_VIOLATION.
        case XiuosResultStatus::ContractViolation: return DispatchOutcomeKind::kOk;
        // PriorityInversion: valid response (worker healthy) — surface as Completion;
        // callers distinguish via vendor_status == XIUOS_STATUS_PRIORITY_INVERSION.
        case XiuosResultStatus::PriorityInversion: return DispatchOutcomeKind::kOk;
        case XiuosResultStatus::StackOverflow:   return DispatchOutcomeKind::kOk;
        case XiuosResultStatus::Trap:            return DispatchOutcomeKind::kWorkerSignaled;
    }
    return DispatchOutcomeKind::kInfraFault;
}

Result<void> XiuosUartDataPlane::StartServer() {
    return Result<void>::Ok();  // no host-side server (XiUOS UART is client-of-QEMU)
}

Result<void> XiuosUartDataPlane::Prepare() {
    return config_.backbone->Connect();
}

void XiuosUartDataPlane::Close() {
    closed_.store(true);
    config_.backbone->Close();
    WakePoller();
}

void XiuosUartDataPlane::Pause()  { paused_.store(true);  WakePoller(); }
void XiuosUartDataPlane::Resume() { paused_.store(false); WakePoller(); }

SubmitOutcome
XiuosUartDataPlane::Submit(const IDataPlane::SubmitInput& req) {
    if (closed_.load())              return SubmitOutcome::kPaused;
    if (paused_.load())              return SubmitOutcome::kPaused;
    if (req.worker_id != 0)          return SubmitOutcome::kInvalid;
    if (req.payload_size == 0 ||
        req.payload_data == nullptr) return SubmitOutcome::kInvalid;
    if (req.payload_size > XIUOS_MAX_PAYLOAD) return SubmitOutcome::kInvalid;

    std::lock_guard<std::mutex> lock(inflight_mu_);
    if (inflight_.has_value()) {
        return SubmitOutcome::kBusy;  // single worker, single in-flight
    }

    const std::uint16_t seq = SeqFromExecutor(req.executor_id);
    auto send = config_.backbone->SendFrame(
        infra::XiuosFrameType::Program, seq,
        std::span<const std::uint8_t>(req.payload_data, req.payload_size));
    if (!send.ok()) {
        return SubmitOutcome::kWorkerDown;
    }

    InflightEntry entry;
    entry.worker_id = req.worker_id;
    entry.executor_id = req.executor_id;
    entry.dispatch_gen = req.dispatch_gen;
    entry.cancel_requested = false;
    entry.cancel_observed_seq = 0;
    inflight_ = entry;
    inflight_start_ts_us_ = NowMicros();
    return SubmitOutcome::kSent;
}

void XiuosUartDataPlane::Poll(std::vector<DispatchOutcome>& out,
                              std::chrono::microseconds timeout) {
    if (closed_.load()) return;

    // Snapshot inflight under lock; we read it back at the end to clear
    // the slot on successful match.
    InflightEntry inflight_snapshot;
    std::uint64_t inflight_started_us = 0;
    bool have_inflight = false;
    {
        std::lock_guard<std::mutex> lock(inflight_mu_);
        if (inflight_.has_value()) {
            inflight_snapshot   = *inflight_;
            inflight_started_us = inflight_start_ts_us_;
            have_inflight = true;
        }
    }

    if (!have_inflight) {
        // Nothing to wait for; consume any wake flag and return.
        wake_pending_.store(false);
        return;
    }

    // [Stage 3 fix] 有 inflight 时至少阻塞 poll_slice,即使 timeout==0。
    // 背景:Channel::LoopMain 每轮先调 DrainTransport()(timeout=0)做"非阻塞收割",
    // 只在 input_queue 空时才调阻塞的 DrainTransport(loop_interval)。fuzz 稳态
    // task_queue 总有货 → input 持续 pending → 阻塞分支永不到达,Poll 永远以
    // timeout==0 被调。若此时纯非阻塞返回,loop_thread_ 会 100% busy-spin
    //(DrainTransport(0)+DrainInputAndSend),把 CPU 占满 → 同机的 QEMU worker 被饿,
    // 迟迟产不出 RESULT 帧 → inflight 卡死(单 socket 的 XiUOS 不像 ivshmem 那样
    // Poll(0) 能从 shm 立即拿到已就绪结果)。
    // 解法:既然永远只有 1 个 in-flight(单 worker),timeout==0 时把有效等待抬到
    // poll_slice —— 用 PollReadable(poll_slice) 阻塞让出 CPU 给 QEMU,同时及时收割
    // 就绪的 RESULT。idle(无 inflight)早已在上面 return,不受影响。
    const auto eff_timeout = std::max(
        timeout,
        std::chrono::duration_cast<std::chrono::microseconds>(config_.poll_slice));
    const auto deadline = std::chrono::steady_clock::now() + eff_timeout;
    const std::uint16_t want_seq = SeqFromExecutor(inflight_snapshot.executor_id);

    // [Stage 3 wedge timeout] Per-program wall-clock budget since Submit().
    // A wedging single-threaded worker never returns its RESULT; this is the
    // de-siloed XiuosFuzzSession::Step wedge_initial_drain_ms deadline. When
    // exceeded we emit kTimeout + free the single slot (so the dispatcher gets
    // a terminal and IsWorkerSendable opens again). The worker is still wedged,
    // so the Channel still needs to recover (reboot) on this outcome — that is
    // the next step; freeing the slot here is the precondition. 0 disables.
    const std::uint64_t prog_budget_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(config_.program_timeout).count());

    for (;;) {
        if (wake_pending_.exchange(false)) return;
        if (closed_.load() || paused_.load()) return;

        if (prog_budget_us != 0 && inflight_started_us != 0) {
            const std::uint64_t now_us = NowMicros();
            if (now_us >= inflight_started_us + prog_budget_us) {
                DispatchOutcome oc;
                oc.worker_id = inflight_snapshot.worker_id;
                oc.executor_id = inflight_snapshot.executor_id;
                oc.dispatch_gen = inflight_snapshot.dispatch_gen;
                oc.kind = DispatchOutcomeKind::kTimeout;
                oc.worker_start_ts_us = inflight_started_us;
                oc.worker_done_ts_us = now_us;
                oc.worker_clock_is_guest_monotonic = false;
                out.push_back(std::move(oc));

                {
                    std::lock_guard<std::mutex> lock(inflight_mu_);
                    // Only clear if this is still the same in-flight program (guard
                    // against a RESULT having landed + a new Submit racing in).
                    if (inflight_.has_value() &&
                        inflight_->executor_id == inflight_snapshot.executor_id) {
                        inflight_.reset();
                        inflight_start_ts_us_ = 0;
                    }
                }
                // The wedging program is harvested as an exec_timeout finding via the
                // standard FaultSignal path (Channel attaches rec.payload to the
                // kTimeout AbnormalCompletion → crash_pipeline → DiagnosticStore).
                // Latch the wedge so the health relay sensor triggers a reboot:
                // freeing the slot above lets the loop continue, but the
                // single-threaded worker is still spinning on this program and
                // only un-wedges via a QEMU reboot (the recovery path).
                wedge_pending_.store(true);
                return;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return;
        const auto remaining_us =
            std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        const auto slice_us =
            std::chrono::duration_cast<std::chrono::microseconds>(config_.poll_slice);
        const auto slice = std::chrono::duration_cast<std::chrono::milliseconds>(
            (remaining_us < slice_us) ? remaining_us : slice_us);

        auto frame = config_.backbone->WaitFrame(
            infra::XiuosFrameType::Result, want_seq, slice);
        if (!frame.ok()) {
            if (frame.error().kind == refuzz::channel::ErrorKind::kTimeout) {
                continue;  // slice expired, re-check wake / deadline
            }
            // kConnection / kProtocol etc. — surface as kWorkerSignaled so the
            // Channel recovery path treats the worker as dead.
            DispatchOutcome oc;
            oc.worker_id = inflight_snapshot.worker_id;
            oc.executor_id = inflight_snapshot.executor_id;
            oc.dispatch_gen = inflight_snapshot.dispatch_gen;
            oc.kind = DispatchOutcomeKind::kWorkerSignaled;
            oc.worker_start_ts_us = inflight_start_ts_us_;
            oc.worker_done_ts_us = NowMicros();
            oc.worker_clock_is_guest_monotonic = false;
            out.push_back(std::move(oc));

            std::lock_guard<std::mutex> lock(inflight_mu_);
            inflight_.reset();
            return;
        }

        // Got our RESULT. Decode and translate.
        refuzz::program::xiuos::XiuosDecodedResult decoded;
        try {
            decoded = refuzz::program::xiuos::XiuosDecodeResult(
                std::span<const std::uint8_t>(frame.value().payload.data(),
                                              frame.value().payload.size()));
        } catch (const std::exception&) {
            // Malformed RESULT — treat as exec error.
            DispatchOutcome oc;
            oc.worker_id = inflight_snapshot.worker_id;
            oc.executor_id = inflight_snapshot.executor_id;
            oc.dispatch_gen = inflight_snapshot.dispatch_gen;
            oc.kind = DispatchOutcomeKind::kInfraFault;
            oc.worker_start_ts_us = inflight_start_ts_us_;
            oc.worker_done_ts_us = NowMicros();
            oc.worker_clock_is_guest_monotonic = false;
            out.push_back(std::move(oc));

            std::lock_guard<std::mutex> lock(inflight_mu_);
            inflight_.reset();
            return;
        }

        DispatchOutcome oc;
        oc.worker_id = inflight_snapshot.worker_id;
        oc.executor_id = inflight_snapshot.executor_id;
        oc.dispatch_gen = inflight_snapshot.dispatch_gen;
        oc.kind = TranslateStatus(decoded.status);
        oc.vendor_status = static_cast<std::uint32_t>(decoded.status);
        oc.vendor_flags = static_cast<std::uint32_t>(decoded.flags);
        // [XiUOS leak 一等公民化 Phase 5] On the OK path the worker auto-packs the
        // post-cleanup resource residue (waitq | victim<<8 | delay<<16) into
        // trap_or_pc (unused on OK). Only treat it as residue when status==Ok;
        // the Trap path below borrows trap_or_pc as the trap PC, so guard against
        // misreading a trap PC as residue. Parallel to vendor_flags (heap delta).
        // On OK this is the resource residue; on ContractViolation the worker
        // borrows trap_or_pc as (api_id<<8 | call_index). Both ride trap_or_pc and
        // are distinguished downstream by vendor_status. (Trap borrows it as the
        // trap PC — excluded here.)
        oc.vendor_resource_residue =
            (decoded.status == refuzz::program::xiuos::XiuosResultStatus::Ok ||
             decoded.status == refuzz::program::xiuos::XiuosResultStatus::ContractViolation ||
             decoded.status == refuzz::program::xiuos::XiuosResultStatus::PriorityInversion ||
             decoded.status == refuzz::program::xiuos::XiuosResultStatus::StackOverflow)
                ? static_cast<std::uint32_t>(decoded.trap_or_pc)
                : 0;
        oc.worker_start_ts_us = inflight_start_ts_us_;
        oc.worker_done_ts_us = NowMicros();
        oc.worker_clock_is_guest_monotonic = false;

        // error_code / crash_signal usage is status-conditional. For the
        // call-level statuses (Ok / ProgramRejected / UnsupportedApi /
        // WorkerError) they MUST stay zero — XiUOS `aux` there is the
        // worker's `last_ret` (eg. -EINVALED for slot-out-of-range), which
        // is a call-level diagnostic, not worker-level health. Surfacing
        // it would make `channel.cpp:~651` reclassify a healthy Completion
        // as AbnormalKind::kExecError. See 030_worker_abi.md §"Phase 1
        // worker enforcement" and the
        // [[feedback-xiuos-negative-seed-ok-is-feature]] memory.
        //
        // The Trap status is different: the worker hit a CPU exception,
        // TranslateStatus already routes it to kWorkerSignaled (so the
        // is_success_completion gate at channel.cpp:~651 fails on `kind`
        // before looking at error_code/crash_signal), and the bucketing
        // layer in `feedback/bucket/xiuos_crash_bucket.{hpp,cpp}` needs
        // the trap pc + mcause to key buckets. We borrow the two slots
        // for that vendor payload (XiUOS convention: error_code = trap_pc,
        // crash_signal = mcause). Other XiUOS backends pulling from these
        // fields must check vendor_status == XIUOS_STATUS_TRAP first.
        // Output for Trap is the raw RESULT frame payload (self-
        // describing — bucket consumer can re-decode coverage / aux),
        // matching the wire bytes received. Other statuses keep
        // output = coverage so XiuosCoverageSignal works unchanged.
        if (decoded.status == refuzz::program::xiuos::XiuosResultStatus::Trap) {
            oc.error_code = decoded.trap_or_pc;
            oc.crash_signal = static_cast<std::uint32_t>(decoded.aux);
            oc.output = std::move(frame.value().payload);
        } else {
            oc.error_code = 0;
            oc.crash_signal = 0;
            oc.output = std::move(decoded.coverage);
        }
        // Always surface aux as vendor_aux. The wedge-only oracle ignores
        // it, but the v1 call-level oracle (RunOracleSelfTest in
        // XiuosFuzzSession) compares it against expected last_ret per the
        // submitted seed to catch semantic bugs that don't wedge.
        oc.vendor_aux = decoded.aux;
        out.push_back(std::move(oc));

        std::lock_guard<std::mutex> lock(inflight_mu_);
        inflight_.reset();
        return;
    }
}

void XiuosUartDataPlane::WakePoller() noexcept {
    wake_pending_.store(true);
}

void XiuosUartDataPlane::ResetWorker(std::uint32_t worker_id) {
    if (worker_id != 0) return;
    ResetAll();
}

void XiuosUartDataPlane::ResetAll() {
    std::lock_guard<std::mutex> lock(inflight_mu_);
    inflight_.reset();
    inflight_start_ts_us_ = 0;
    // Recovery (reboot) clears the latched wedge — the fresh worker starts clean.
    wedge_pending_.store(false);
}

std::vector<InflightEntry> XiuosUartDataPlane::SnapshotInflight() const {
    std::lock_guard<std::mutex> lock(inflight_mu_);
    if (!inflight_.has_value()) return {};
    return { *inflight_ };
}

bool XiuosUartDataPlane::IsWorkerSendable(std::uint32_t worker_id) const {
    if (worker_id != 0)        return false;
    if (closed_.load())        return false;
    if (paused_.load())        return false;
    std::lock_guard<std::mutex> lock(inflight_mu_);
    return !inflight_.has_value();
}

}  // namespace refuzz::channel::data
