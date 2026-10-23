#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::proto {

enum class ResultCode : uint8_t {
    kOk = 0,
    kExecError = 1,
    kTimeout = 2,
    kCrashed = 3,
    kRestarted = 4,
    kDropped = 5,
    // [XiUOS leak 一等公民化 Phase 1] program completed but left a resource leak
    // (net heap delta / resource residue not reclaimed). NOT a crash and NOT an
    // exec error — its own terminal so it routes to the resource_leak bucket with
    // the leak magnitude preserved. See docs/plans/xiuos-leak-componentization.md.
    kResourceLeak = 6,
    // [Contract oracle §3.1] a call whose precondition held and whose spec mandates
    // success returned a non-EOK value (semantic contract violation, e.g. Class D/E
    // WQ_SUBMIT). NOT a crash/leak — its own terminal → contract_violation bucket.
    // See docs/plans/xiuos-observability-detector-expansion.md.
    kContractViolation = 7,
    // [Priority-inversion detector] a held mutex has a blocked waiter more urgent
    // than the holder (priority-inheritance invariant violated). Own terminal →
    // priority_inversion bucket. See docs/plans/xiuos-observability-detector-expansion.md.
    kPriorityInversion = 8,
    // [Stack-overflow detector] a task stack high-water came within a safety margin
    // of its depth (silent on virt-rv32). Own terminal → stack_overflow bucket.
    kStackOverflow = 9,
};

enum class InfraError : uint8_t {
    kNone = 0,
    kTimeout = 1,
    kWorkerCrashed = 2,
    kInvalidInput = 3,
    kOutputTooLarge = 4,
    kExecutorError = 5,
};

// [v2 Epic 5 PR-5-A] ExecFlag bit allocation.
//
// `flags` is a u32 bitset on `ExecOpts`. Bit values mirror upstream
// `pkg/flatrpc/flatrpc.go::ExecFlagCollectComps = 8` so cross-system
// reasoning stays trivial. Bits 0..2 are reserved for future use; bit 3 is
// CollectComps, bit 5 is host-side threaded opt-in.
//
// Mutual-exclusion contract (D-2 of plan
// `docs/plans/syzkaller-capability-closure-epic-5.md`): when
// `kExecFlagCollectComps` is set, the worker switches KCOV mode to
// KCOV_TRACE_CMP and emits ONLY the cmp wire region; no PC region for
// the same task. Hints stage produces three separate Tasks for the
// 3-replay loop (matches upstream `hintsJob.run`).
enum ExecFlag : uint32_t {
    kExecFlagNone          = 0,
    kExecFlagCollectComps  = 1u << 3,  // = 8, mirrors flatrpc upstream
    // [v2 Epic 7 PR-4.6] IntraTaskMode bit. 不设 = serial(default),设 = threaded。
    // Wire 端落到 TASK_FLAG_INTRA_THREADED (= 1u);channeldispatcher 翻译。
    // Threaded 要求 host config target.thread_count > 1,否则 worker driver
    // 入口拒收返 exec_error (KernelThreadPool 没构造)。
    // Bit 5 选择是因为 ExecFlag 还在 (0..7) 范围里,远离 wire flag 的 INTRA mask
    // (bits 0..1) 和 SHAPE mask (bits 2..3),domain↔wire 翻译时不冲突。
    kExecFlagIntraThreaded = 1u << 5,
    // [RTT] per-task RTT-trace sampling opt-in. Decided ONCE at submit
    // (fuzzer_loop build_task), sticky in TaskTrace.sampled. Wire 端落到
    // TASK_FLAG_TRACE_SAMPLED (bit 5);channeldispatcher 翻译。gate 住 guest 的
    // worker_started_executor_id marker + start-ping,非采样零开销。domain 侧占 bit 6。
    kExecFlagTraceSampled  = 1u << 6,
};

struct ExecOpts {
    uint32_t timeout_ms = 1000;
    uint32_t flags = 0;
};

struct TaskTrace {
    // Host-side monotonic timestamps unless noted otherwise.
    uint64_t task_queue_push_ts_us = 0;
    uint64_t task_queue_pop_ts_us = 0;
    // [RTT] Host-clock instant at which the request finished host-side
    // preparation and is ready to transmit: payload materialized
    // (MaterializeExecWire), wire flags translated, ChannelDispatchRequest
    // assembled -- stamped immediately before the request is handed to
    // Channel::Submit. Splits pop->data_plane_call into the ORCH part
    // (pop -> here, host CPU serialization) and the QUEUE part (here ->
    // data_plane_call, waiting for a free worker slot in
    // deferred_submissions_). Without it those two are inseparable.
    // Semantic counterpart of syzkaller's sent_us, which is likewise stamped
    // after msg assembly and before the write.
    uint64_t dispatch_prep_done_ts_us = 0;
    // Actual submission boundary: immediately before IDataPlane::Submit.
    uint64_t data_plane_call_ts_us = 0;
    // [RTT] Host-clock instant at which the HOST observed the worker had started
    // this task: the host drains the guest's TASK_TAKEN start-ping marker
    // (TaskSlot.worker_started_executor_id) and stamps MonotonicNowUs(). This is
    // semantically syzkaller's executing_us (manager stamps host clock on
    // ExecutingMessage receipt) -- a HOST timestamp, so it IS comparable to the
    // surrounding host fields (unlike worker_start_ts_us below, which is guest
    // clock).
    // 0 = task not sampled / start not observed. See docs/plans/rtt-host-start-ack.md.
    uint64_t worker_start_ack_host_ts_us = 0;
    // Host observed a validated completion for this task. This is stamped by
    // the data plane after COMP_READY identity/generation checks and before
    // copying the output payload. It is an internal split point inside
    // exec_response; the top-level stage still ends at channel_event_queued.
    uint64_t completion_observed_host_ts_us = 0;
    // Host finished copying the completion output into its owned buffer.
    // Also an internal exec_response split point, not a top-level boundary.
    uint64_t output_copied_host_ts_us = 0;
    // Worker-side monotonic timestamps. Consumers must only use worker_done -
    // worker_start; host/guest monotonic epochs are not comparable.
    uint64_t worker_start_ts_us = 0;
    uint64_t worker_done_ts_us = 0;
    uint64_t channel_event_queued_ts_us = 0;
    uint64_t executor_event_forwarded_ts_us = 0;
    uint64_t fuzzer_feedback_processed_ts_us = 0;
    // True when worker_start/done_ts_us came from the worker's own monotonic
    // clock (e.g. ivshmem guest). Consumers only subtract these two fields.
    bool worker_clock_is_guest_monotonic = true;
    // Number of data-plane re-dispatches. Consumers can separate retry-heavy
    // recovery paths from steady-state samples.
    uint32_t submit_attempt = 0;
    // [RTT] sticky per-task RTT-trace sampling decision, made ONCE at submit
    // (fuzzer_loop build_task via HostLogger::ShouldSampleTaskTrace) and carried
    // through the whole lifecycle, so the guest start-ping gate (wire flag) and
    // the completion-time emit gate use the SAME decision — mirrors syzkaller's
    // Request.Trace.Sampled. Re-deciding at completion would draw an independent
    // sample (inconsistent for rate=N: guest pings but host drops, or vice versa).
    bool sampled = false;
};

struct Task {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    bool important = false;
    ExecOpts opts{};
    TaskTrace trace{};
    std::vector<uint8_t> payload;
};

enum class ExecAbnormalKind : uint8_t {
    kNone = 0,
    kCrash,
    kTimeout,
    kExecError,
    kAborted,
};

enum FeedbackFlags : uint16_t {
    kFeedbackFlagNone = 0,
    kFeedbackFlagHasCoverage = 1u << 0,
    kFeedbackFlagEmptyCoverage = 1u << 1,
    kFeedbackFlagMalformedCoverage = 1u << 2,
};

// [v2 Epic 5 PR-5-A] CmpRecord — typed comparison record decoded from
// KCOV_TRACE_CMP. Mirrors the host-side projection of upstream's
// `prog/hints.go` makeCompMap input. Wire layout for a single record
// is 4 × uint64 little-endian (in upstream kernel order: type, arg1,
// arg2, pc). The codec consumes `type & KCOV_CMP_CONST` into
// `is_const`, sign-extends operands according to
// `type & KCOV_CMP_SIZE_MASK`, and stores the upstream ComparisonRaw
// operand order (`arg1` = value that may come from input, i.e. raw
// kernel arg2; `arg2` = raw kernel arg1).
// Upstream stateless filter rules from `executor.cc:1828-1874` apply
// at decode time: invalid type, zero/noise comparisons, and successful
// comparisons are dropped.
struct CmpRecord {
    uint64_t pc       = 0;
    uint64_t arg1     = 0;
    uint64_t arg2     = 0;
    bool     is_const = false;
};

struct FeedbackDelta {
    // 协议版本用于后续平滑扩展，避免破坏旧实现。
    // [v2 Epic 5 PR-5-A] schema_version 1→2: cmp 字段从
    // std::vector<uint64_t>（占位/未消费）切到 std::vector<CmpRecord>。
    // codec 遇到 schema_version=1 旧数据时（理论上不存在 producer，
    // 因为 v1 cmp 一直是 stub），按 cmp 为空处理。
    uint16_t schema_version = 2;
    uint16_t flags = kFeedbackFlagNone;

    bool interesting = false;
    ResultCode exec_status = ResultCode::kOk;
    uint64_t latency_us = 0;

    // 覆盖哈希；cmp 在 Epic 5 PR-5-A 之后承载真实 KCOV_CMP 记录。
    std::vector<uint64_t> cov_hashes;
    // [v1 cmp packed uint64 — ROLLBACK: uncomment + remove v2 below + drop CmpRecord struct + revert schema_version]
    // std::vector<uint64_t> cmp;
    // [v2 Epic 5 PR-5-A — 当前版本]
    std::vector<CmpRecord> cmp;

    // 预留扩展位，后续可用于压缩格式/外部blob引用等。
    uint64_t reserved1 = 0;
    uint64_t reserved2 = 0;
};

enum ExecAnalysisFlags : uint32_t {
    kExecAnalysisFlagNone = 0,
    kExecAnalysisFlagHasFaultEvent = 1u << 0,
};

struct ExecAnalysis {
    uint64_t incident_id = 0;
    ExecAbnormalKind abnormal_kind = ExecAbnormalKind::kNone;
    uint32_t flags = kExecAnalysisFlagNone;
};

struct ExecResult {
    uint64_t executor_id = 0;
    uint32_t worker_id = 0;
    ResultCode code = ResultCode::kOk;
    InfraError infra_error = InfraError::kNone;
    uint64_t start_ts_us = 0;
    uint64_t finish_ts_us = 0;
    uint32_t crash_signal = 0;
    std::vector<uint8_t> output;
    FeedbackDelta feedback;
    ExecAnalysis analysis;
};

} // namespace refuzz::proto
