#ifndef IVSHMEM_PROTOCOL_H
#define IVSHMEM_PROTOCOL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "refuzz/proto_wire/error_codes.h"
#include "refuzz/proto_wire/env_features.h"  // [machine-check C4.6] ShmHeader.env_features

// ==================== Constants ====================
#define IVSHMEM_MAGIC 0xDEADBEEF
// v5: ShmHeader::corpus_triaged gates periodic worker-domain recycle after the
// one-time boot-corpus candidate phase. The field replaces reserved0, so the
// header size and all shared-memory region offsets remain unchanged.
// v6: worker_id and proc_id are distinct. WorkerCtrl persists active proc
// state, TaskSlot carries requested/actual proc_id, and ProgramResultPageV3
// records the actual proc_id. All fields reuse reserved bytes, but old peers
// would interpret a zeroed request as proc 0, so mixed v5/v6 peers must fail.
// v7: remove the unused owner_pid/owner_gen publication. Registration readiness
// is the guest_state/host_state handshake; execution-domain child identity is
// process-local and is not part of the host/guest wire contract.
// v8: persist a per-worker dirty proc-id mask. A domain that cannot be reaped
// is detached from the daemon and its proc-scoped resources must not be reused
// until the VM has been successfully rebooted.
#define PROTOCOL_VERSION 8

#define MAX_WORKERS 16
#define PROC_ID_ANY UINT32_MAX
#define PROC_ID_STATE_MAGIC 0x50524f43u /* "PROC" */
#define MAX_INPUT_SIZE (4 * 1024 * 1024)
// Upstream syzkaller executor output budgets:
//   - signal-only       : 4 MiB
//   - coverage          : 6 MiB
//   - comparisons       : 14 MiB
//
// reFuzz ivshmem BAR2 layout is static across tasks, so its per-worker output
// pool must use one fixed worst-case budget. Align that pool with upstream's
// largest executor output class (`kMaxOutputComparisons` = 14 MiB). stdio path
// can choose a smaller default separately because it owns a private anonymous
// mmap per worker process.
#define SYZKALLER_MAX_OUTPUT_SIGNAL       (4 * 1024 * 1024)
#define SYZKALLER_MAX_OUTPUT_COVERAGE     (6 * 1024 * 1024)
#define SYZKALLER_MAX_OUTPUT_COMPARISONS  (14 * 1024 * 1024)
#define MAX_OUTPUT_SIZE SYZKALLER_MAX_OUTPUT_COMPARISONS

#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096

#define STEPEVENT_RING_MAGIC 0x53544550U /* 'STEP' */
#define STEPEVENT_RING_DEFAULT_CAPACITY 1024U

// ivshmem BAR0 registers (ivshmem-spec.txt)
#define IVSHMEM_REG_INTMASK 0x00
#define IVSHMEM_REG_INTSTATUS 0x04
#define IVSHMEM_REG_IVPOSITION 0x08
#define IVSHMEM_REG_DOORBELL 0x0C

// ==================== State enums ====================
typedef enum {
    GUEST_REG_EMPTY = 0,
    GUEST_REG_CLAIMED = 1, /* daemon registered; heartbeat active; domain gated */
    GUEST_REG_READY = 2,   /* execution domain ACKed and accepts tasks */
    GUEST_REG_DEAD = 3,
} GuestRegState;

typedef enum {
    HOST_REG_IDLE = 0,
    HOST_REG_GRANTED = 1,
    HOST_REG_REVOKED = 2,
} HostRegState;

typedef enum {
    TASK_EMPTY = 0,
    TASK_READY = 1,
    TASK_TAKEN = 2,
} TaskSlotState;

typedef enum {
    COMP_EMPTY = 0,
    COMP_READY = 1,
    COMP_CONSUMED = 2,
} CompletionSlotState;

/* CompletionStatus — worker 对一次执行的**事实**陈述（必须配 error_code 一起读）。
 *
 * 本枚举只说"**怎么结束的**"，不做任何处理决策；具体原因由并列的 error_code 字段承载。
 * 分类（Completion / Abnormal 及其 kind）由 host 侧 Channel::DrainTransport 读
 * (status, error_code) 二元组决定 —— 事实层不压缩信息。
 *
 * 有数据可消费（host 侧走 Completion）：
 *   OK            — 程序跑完，结果已 commit
 *   PARTIAL       — 程序自己提前结束（exit_group(任意码) / 无 handler 的信号）。buffer
 *                   未被 crash handler 动过 → progress cursors 可信。对齐 syzkaller
 *                   `非 kFailStatus → reply_execute(0)`（common.h:736-740）
 *   TIMEOUT + ERR_TIMEOUT
 *                 — program watchdog 判超时；SIGKILL 前已发布的数据可信
 *
 * 无数据（host 侧走 Abnormal）：
 *   HUNG + ERR_DOMAIN_WATCHDOG_TIMEOUT（或恢复失败的 ERR_DOMAIN_*）
 *                 — daemon watchdog 判的 **task hang**，domain 已拿不到结果。
 *                   这是 worker 端对"程序可能仍在内核里（D 态）"的显式判定，
 *                   host 见到 HUNG 即进永久 hang 池。防御性兼容旧
 *                   TIMEOUT + ERR_DOMAIN_WATCHDOG_TIMEOUT 仍按 hang 处理。
 *   HUNG + ERR_HARNESS_MAIN_REAP_FAILED / ERR_HARNESS_STOPPED_REAP_TIMEOUT /
 *         ERR_HARNESS_CLEANUP_FAILED / ERR_DOMAIN_*（执行阶段恢复失败）
 *                 — 执行域在程序执行期间死亡且 kill/reap 未完成，程序可能还
 *                   活着（SIGKILL 对 D 态无效），同样进 hang 池。
 *   NO_RESULT     — 真的没有任何结果（如第一个 call 就卡死后被杀，零 progress）。
 *                   不是错误，就是没产出 → 下游直接不消费，不需要再判 output_len
 *   CHILD_ABORTED — 程序 crash（SEGV/ABRT/BUS/ILL/FPE），handler 跑过、buffer 不可信；
 *                   daemon 健在，**不得**升级成 worker_dead
 *   CRASHED       — daemon-child 协议错（NotifyChild pipe broken 等 daemon-side）
 *   CANCELLED     — host 主动取消
 *   INFRA_FAULT   — **基础设施故障，程序无罪**。两个 error_code 细分：
 *                     ERR_EXECUTOR_ERROR — worker 运行时故障（observation sink /
 *                                          backend 执行失败）
 *                     ERR_INVALID_INPUT  — 配置/协议错（wire 输入非法、exec flags
 *                                          不被支持）
 *   HARNESS_FATAL — **基础设施故障**（程序无罪）：execution domain 无法重建 /
 *                   程序从未进入执行域（启动、rebind、proc 不匹配），或程序已
 *                   证明退出后的机械故障（post-exit 协议错 / KCOV 检查失败）。
 *                   它不是 hang，host 不因 HARNESS_FATAL 进永久池。
 *   HARNESS_RECOVERED — 故障但已重建出干净 domain
 *   UNKNOWN       — 兜底：走到了不该走到的分支。它的出现本身是 bug 信号，不是正常终态
 *
 * 编号 append-only。4 号原为 COMP_STATUS_EXEC_ERROR —— 那是个把「程序行为 / 没结果 /
 * infra 故障 / 配置错 / 兜底」全塞在一起的口袋（一个 status + 一个 ERR_EXECUTOR_ERROR
 * 承载 7 种互不相干的原因），已按上表拆开；4 号原地收窄为语义精确的 NO_RESULT。
 */
typedef enum {
    COMP_STATUS_OK = 0,
    COMP_STATUS_CRASHED = 1,
    COMP_STATUS_TIMEOUT = 2,
    COMP_STATUS_CANCELLED = 3,
    COMP_STATUS_NO_RESULT = 4,
    COMP_STATUS_CHILD_ABORTED = 5,
    COMP_STATUS_PARTIAL = 6,
    COMP_STATUS_HARNESS_FATAL = 7,
    COMP_STATUS_HARNESS_RECOVERED = 8,
    COMP_STATUS_INFRA_FAULT = 9,
    COMP_STATUS_UNKNOWN = 10,
    // 显式的 task hang / 执行阶段结果丢失终态（worker 判定），与 TIMEOUT 的
    // program-watchdog 语义分离；见上方注释表。append-only。
    COMP_STATUS_HUNG = 11,
} CompletionStatus;

typedef enum {
    STEP_PHASE_BEFORE         = 0,  /* task-level: acquired */
    STEP_PHASE_AFTER          = 1,  /* task-level: completed */
    STEP_PHASE_SYSCALL_BEFORE = 2,  /* individual syscall about to execute */
    STEP_PHASE_SYSCALL_AFTER  = 3,  /* individual syscall completed */
    STEP_PHASE_ABORT          = 4,  /* syscall/task aborted (parse error, fallback) */
} StepEventPhase;

typedef enum {
    PROGRAM_RESULT_EMPTY     = 0,
    PROGRAM_RESULT_RUNNING   = 1,
    PROGRAM_RESULT_COMMITTED = 2,
} ProgramResultStateV3;

/* TaskSlot.flags bit layout
 * Bits [1:0]  — IntraTaskMode (0=serial, 1=threaded)
 * Bits [3:2]  — TaskShape     (0=single, 1=forked)
 * Bit  [4]    — CollectComps  (0=PC mode, 1=KCOV_TRACE_CMP mode)
 * Bit  [5]    — sampled RTT start acknowledgement
 * Bits [31:6] — reserved (must be 0)
 */
#define TASK_FLAG_INTRA_MASK     0x03u
#define TASK_FLAG_INTRA_SHIFT    0
#define TASK_FLAG_SHAPE_MASK     0x0Cu
#define TASK_FLAG_SHAPE_SHIFT    2

#define TASK_FLAG_INTRA_SERIAL   0u
#define TASK_FLAG_INTRA_THREADED 1u
#define TASK_FLAG_SHAPE_SINGLE   0u
#define TASK_FLAG_SHAPE_FORKED   1u

/* CollectComps bit — when set, worker switches KCOV mode to KCOV_TRACE_CMP
 * and emits ONLY the cmp wire region (no PC region). Host-side proto bit is
 * refuzz::proto::kExecFlagCollectComps (= 1u<<3); channeldispatcher translates
 * proto → wire when building the ChannelDispatchRequest. */
#define TASK_FLAG_COLLECT_COMPS  (1u << 4)
/* [RTT] gate: guest writes worker_started_executor_id + rings the start-ping
 * doorbell ONLY when this bit is set (host sets it at submit for sampled tasks).
 * Uses bit 5 (INTRA=0..1, SHAPE=2..3, COLLECT_COMPS=4). MUST also be added to
 * exec_mode.hpp kSupportedMask, else the worker rejects the task as unsupported.
 * Pure host-observation gate — no effect on exec mode. */
#define TASK_FLAG_TRACE_SAMPLED  (1u << 5)

static inline uint32_t task_flags_get_intra(uint32_t flags) {
    return (flags & TASK_FLAG_INTRA_MASK) >> TASK_FLAG_INTRA_SHIFT;
}
static inline uint32_t task_flags_get_shape(uint32_t flags) {
    return (flags & TASK_FLAG_SHAPE_MASK) >> TASK_FLAG_SHAPE_SHIFT;
}
static inline uint32_t task_flags_get_collect_comps(uint32_t flags) {
    return (flags & TASK_FLAG_COLLECT_COMPS) ? 1u : 0u;
}

// ==================== V3 structures ====================
//
// V3 is the only protocol. V2/V1 layouts and compatibility shims (WorkerAreaV2,
// Slot, ShmHeader typedef, REG_*/STATE_* legacy enums, sizeof(WorkerAreaV2)-
// derived offset helpers) 已全部移除。consumer 必须用 ShmHeader 内的显式 region
// 字段或下方 typed-view helper，**没有 fallback 路径**。

struct ShmHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t n_workers;
    uint32_t worker_area_size;   /* V3 invariant: 0. Non-zero = layout 错配 */

    uint32_t step_event_ring_capacity;
    uint32_t reg_epoch;
    uint32_t host_ready;
    uint32_t corpus_triaged;

    uint64_t control_region_offset;
    uint64_t control_region_size;
    uint64_t data_region_offset;
    uint64_t data_region_size;
    uint64_t step_ring_offset;
    uint64_t step_ring_size;

    uint32_t per_worker_control_stride;
    uint32_t per_worker_data_stride;
    uint32_t data_input_offset;
    uint32_t data_input_size;
    uint32_t data_output_offset;
    uint32_t data_output_size;
    uint32_t data_result_offset;
    uint32_t data_result_size;

    // [machine-check C4.6] Per-VM environment facts. worker-0 probes the guest
    // and writes `env_features`, then publishes `env_features_ready = 1` (release)
    // BEFORE it signals GUEST_REG_READY. The host reads it after
    // WaitAllWorkersReady (acquire on the flag) and folds it into SupportEnv.
    // Carved from the reserved page (EnvFeatures is ~2.3 KiB < the free space);
    // region offsets above are unchanged, so the data plane is unaffected.
    uint32_t env_features_ready;            /* 0 until env_features written */
    uint32_t env_features_reserved;         /* pad to 8B */
    struct EnvFeatures env_features;

    uint8_t reserved[PAGE_SIZE - 120 - sizeof(struct EnvFeatures)];
} __attribute__((aligned(PAGE_SIZE)));

struct WorkerCtrl {
    uint32_t ctrl_version;
    uint32_t guest_state; /* GuestRegState: daemon claim + domain-ready gate */
    uint32_t host_state;  /* HostRegState */
    uint32_t heartbeat_counter;
    uint64_t last_hb_us;
    uint32_t error_latch;

    uint32_t cancel_requested;
    uint32_t cancel_observed_seq;
    uint32_t paused;
    /* Stable worker slot and resource proc ID are intentionally distinct.
     * These fields survive single-worker control resets so a restarted worker
     * does not reuse a potentially dirty proc ID. */
    uint32_t active_proc_id;
    uint32_t proc_epoch;
    uint32_t proc_state_magic;
    uint32_t dirty_proc_mask;
    uint32_t reserved[2];
} __attribute__((aligned(CACHE_LINE_SIZE)));

struct TaskSlot {
    volatile uint32_t state; /* TaskSlotState */
    /* Host: requested proc ID or PROC_ID_ANY. Guest: actual proc ID used. */
    volatile uint32_t proc_id;
    uint64_t executor_id;
    /* [RTT] host-observed "worker started" marker. The guest writes the
     * executor_id it just CAS'd into TASK_TAKEN here (gated on the sampled
     * flag), then rings the doorbell. Durable: the guest never clears it, so it
     * survives the TASK_TAKEN->TASK_EMPTY transition -- the host reads THIS
     * field (not the volatile `state`) and thus never misses a fast task.
     * 0 = not started this dispatch. Reuses former reserved1 (8B) => zero shm
     * growth, no ring. See docs/plans/rtt-host-start-ack.md. */
    uint64_t worker_started_executor_id;

    uint32_t dispatch_gen;
    uint32_t input_off;
    uint32_t input_len;
    uint32_t timeout_ms;

    uint32_t flags;
    uint8_t reserved[20];
} __attribute__((aligned(CACHE_LINE_SIZE)));

struct CompletionSlot {
    volatile uint32_t state; /* CompletionSlotState */
    uint64_t executor_id;
    uint64_t start_ts_us;

    uint32_t dispatch_gen;
    uint32_t status; /* CompletionStatus */
    uint32_t error_code; /* ErrorCode */
    uint32_t crash_signal;

    uint32_t output_off;
    uint32_t output_len;
    uint64_t finish_ts_us;
    uint64_t exec_seq;
} __attribute__((aligned(CACHE_LINE_SIZE)));

struct ProgramPerfSampleV3 {
    /* Program-child stage payload. Parent/loop stages stay process-local. */
    uint64_t child_setup_us;
    uint64_t child_total_us;
    uint64_t child_finish_us;
    uint64_t child_execute_task_us;
    uint64_t runtime_prepare_us;
    uint64_t runtime_finalize_us;
    uint64_t bus_task_start_us;
    uint64_t backend_execute_us;
    uint64_t program_fd_cleanup_us;
    uint64_t bus_session_end_us;
    uint64_t bus_pack_us;
    uint64_t remote_kcov_settle_sleep_us;

    uint64_t driver_total_us;
    uint64_t driver_decode_us;
    uint64_t scratch_prepare_us;
    uint64_t scratch_clear_us;
    uint64_t wire_walk_us;
    uint64_t post_walk_drain_us;
    uint64_t task_cleanup_us;
    uint64_t copyin_us;
    uint64_t copyout_us;
    uint64_t arg_resolve_us;
    uint64_t fault_inject_us;
    uint64_t fault_check_us;
    uint64_t dispatch_us;
    uint64_t kcov_reset_us;
    uint64_t kcov_collect_us;
    uint64_t coverage_tail_us;
    uint64_t threaded_schedule_us;
    uint64_t threaded_wait_us;
    uint64_t threaded_block_wait_us;
    uint64_t threaded_poll_us;
    /* [fork-breakdown 2026-05-21] worker thread 内拆 worker_total (整个 kCall
     * 分支 NowUs) + kcov_begin (lazy KCOV_ENABLE+BeginCallSession). 跟主线程
     * threaded_wait 差值 = condvar wake latency + scheduler 调度延迟。 */
    uint64_t worker_total_us;
    uint64_t kcov_begin_us;
    /* [sync_gap split 2026-05-22] sync_gap 拆 pickup_gap (main→worker启动) +
     * done_gap (worker完成→main醒来), 让 thread_wait 的 sync 部分能定位到
     * "worker 起步慢" vs "main 醒来慢". */
    uint64_t pickup_gap_us;
    uint64_t done_gap_us;

    uint64_t child_entry_ts_us;
    uint64_t runtime_start_ts_us;
    uint64_t runtime_end_ts_us;
    uint64_t result_ready_ts_us;

    uint32_t calls;
    uint32_t copyins;
    uint32_t copyouts;
    uint32_t kcov_resets;
    uint32_t kcov_collects;
    uint32_t remote_kcov_settles;
    uint32_t cov_entries;
    uint32_t cov_taken;
    uint32_t blocked_calls;
    uint32_t output_len;
    int32_t backend_status;

    uint32_t post_walk_drain_programs;
    uint32_t post_walk_drain_initial_calls;
    uint32_t post_walk_drain_completed_calls;
    uint32_t post_walk_drain_timed_out_calls;
    uint32_t post_walk_drain_deadline_per_call;
    uint32_t post_walk_drain_deadline_program;
    uint32_t post_walk_drain_deadline_extra;
};

struct ProgramResultPageV3 {
    volatile uint32_t state;      /* ProgramResultStateV3; host never consumes directly */
    uint32_t fatal_reason;        /* internal HarnessFatalReason; host does not consume */
    volatile uint64_t commit_seq; /* release-store by program child on final commit */
    uint64_t executor_id;

    uint32_t dispatch_gen;
    uint32_t result_kind;
    int32_t status;
    uint32_t flags;

    uint32_t output_len;
    uint32_t progress_completed_calls;
    uint32_t progress_output_len;
    uint32_t crash_len;

    uint32_t crash_signal;
    uint32_t perf_valid;
    /* Diagnostic /dev/loop candidate mask collected during program execution.
     * Cleanup uses the worker's fixed /dev/loop<procid>; UINT32_MAX means
     * unknown or proc_slot_id >= 32, which cannot fit this ABI. Replaces reserved1
     * (ABI stable: same offset/size). */
    uint32_t loop_devices_used_mask;
    uint32_t proc_id;

    /* [ExecTL] round-1 execution-timeline stamps (guest CLOCK_MONOTONIC us),
     * written unconditionally by the program child (B = setup done, about to
     * arm coverage + walk the program; C = feedback packed into output_pool)
     * and read back by the loop child after reap. Guest-internal like the
     * rest of this page; the host never consumes them. 0 = child died before
     * the stamp. */
    uint64_t tl_b_ts_us;
    uint64_t tl_c_ts_us;
    /* [ExecTL round-2] CPU dimension at the same stamps: process CPU consumed
     * and main-thread runqueue wait (/proc/self/schedstat), both ~0 at fork.
     * Guest-internal; the host never consumes them. */
    uint64_t tl_b_cpu_us;
    uint64_t tl_b_rq_us;
    uint64_t tl_c_cpu_us;
    uint64_t tl_c_rq_us;

    struct ProgramPerfSampleV3 perf;
    uint8_t reserved[PAGE_SIZE - 120 - sizeof(struct ProgramPerfSampleV3)];
} __attribute__((aligned(PAGE_SIZE)));

struct WorkerControlAreaV3 {
    struct WorkerCtrl ctrl;
    struct TaskSlot task;
    struct CompletionSlot completion;
    uint8_t control_reserved[PAGE_SIZE -
                             sizeof(struct WorkerCtrl) -
                             sizeof(struct TaskSlot) -
                             sizeof(struct CompletionSlot)];
} __attribute__((aligned(PAGE_SIZE)));

struct WorkerDataWindowV3 {
    uint8_t input_pool[MAX_INPUT_SIZE];
    uint8_t output_pool[MAX_OUTPUT_SIZE];
    struct ProgramResultPageV3 result_page;
} __attribute__((aligned(PAGE_SIZE)));

struct StepEventRingHeader {
    uint32_t magic;
    uint32_t capacity;
    volatile uint64_t head;
    volatile uint64_t tail;
    uint8_t reserved[40];
} __attribute__((aligned(CACHE_LINE_SIZE)));

struct StepEventSlot {
    volatile uint64_t seq;
    uint32_t worker_id;
    uint32_t actor_id;
    uint64_t executor_id;

    uint32_t op_index;
    uint32_t phase;  /* StepEventPhase */
    uint32_t status; /* CompletionStatus */
    uint32_t reserved0;

    uint64_t ts_us;
    uint8_t reserved[16];
} __attribute__((aligned(CACHE_LINE_SIZE)));

#ifdef __cplusplus
static_assert(sizeof(ShmHeader) == PAGE_SIZE, "ShmHeader must be 4KB");
static_assert(sizeof(WorkerCtrl) == CACHE_LINE_SIZE,
              "WorkerCtrl must fit one cache line");
static_assert(sizeof(TaskSlot) == CACHE_LINE_SIZE,
              "TaskSlot must fit one cache line");
static_assert(sizeof(CompletionSlot) == CACHE_LINE_SIZE,
              "CompletionSlot must fit one cache line");
static_assert(sizeof(WorkerControlAreaV3) == PAGE_SIZE,
              "WorkerControlAreaV3 must be exactly one page");
static_assert(sizeof(ProgramPerfSampleV3) <= 512,
              "ProgramPerfSampleV3 must stay compact");
static_assert(sizeof(ProgramResultPageV3) == PAGE_SIZE,
              "ProgramResultPageV3 must be exactly one page");
static_assert(alignof(ProgramResultPageV3) == PAGE_SIZE,
              "ProgramResultPageV3 must keep PAGE_SIZE alignment");
static_assert(alignof(WorkerDataWindowV3) == PAGE_SIZE,
              "WorkerDataWindowV3 must keep PAGE_SIZE alignment");
static_assert(sizeof(StepEventRingHeader) == CACHE_LINE_SIZE,
              "StepEventRingHeader must fit one cache line");
static_assert(sizeof(StepEventSlot) == CACHE_LINE_SIZE,
              "StepEventSlot must fit one cache line");
#else
_Static_assert(sizeof(struct ShmHeader) == PAGE_SIZE, "ShmHeader must be 4KB");
_Static_assert(sizeof(struct WorkerCtrl) == CACHE_LINE_SIZE,
               "WorkerCtrl must fit one cache line");
_Static_assert(sizeof(struct TaskSlot) == CACHE_LINE_SIZE,
               "TaskSlot must fit one cache line");
_Static_assert(sizeof(struct CompletionSlot) == CACHE_LINE_SIZE,
               "CompletionSlot must fit one cache line");
_Static_assert(sizeof(struct WorkerControlAreaV3) == PAGE_SIZE,
               "WorkerControlAreaV3 must be exactly one page");
_Static_assert(sizeof(struct ProgramPerfSampleV3) <= 512,
               "ProgramPerfSampleV3 must stay compact");
_Static_assert(sizeof(struct ProgramResultPageV3) == PAGE_SIZE,
               "ProgramResultPageV3 must be exactly one page");
_Static_assert(_Alignof(struct ProgramResultPageV3) == PAGE_SIZE,
               "ProgramResultPageV3 must keep PAGE_SIZE alignment");
_Static_assert(_Alignof(struct WorkerDataWindowV3) == PAGE_SIZE,
               "WorkerDataWindowV3 must keep PAGE_SIZE alignment");
_Static_assert(sizeof(struct StepEventRingHeader) == CACHE_LINE_SIZE,
               "StepEventRingHeader must fit one cache line");
_Static_assert(sizeof(struct StepEventSlot) == CACHE_LINE_SIZE,
               "StepEventSlot must fit one cache line");
#endif

// ==================== V3 helpers ====================

static inline int is_power_of_two_u32(uint32_t v) {
    return v != 0 && (v & (v - 1U)) == 0;
}

static inline size_t align_up_size_v3(size_t v, size_t align) {
    return ((v + align - 1U) / align) * align;
}

static inline struct ShmHeader *get_shm_header_v3(void *shm_base) {
    return (struct ShmHeader *)shm_base;
}

static inline const struct ShmHeader *get_shm_header_v3_const(const void *shm_base) {
    return (const struct ShmHeader *)shm_base;
}

static inline size_t get_worker_control_stride_v3(void) {
    return sizeof(struct WorkerControlAreaV3);
}

static inline size_t get_worker_data_stride_v3(void) {
    return sizeof(struct WorkerDataWindowV3);
}

static inline size_t get_control_region_offset_v3(void) {
    return PAGE_SIZE;
}

static inline size_t get_control_region_size_v3(uint32_t n_workers) {
    return (size_t)n_workers * get_worker_control_stride_v3();
}

static inline size_t get_data_region_offset_v3(uint32_t n_workers) {
    return align_up_size_v3(get_control_region_offset_v3() +
                            get_control_region_size_v3(n_workers),
                            PAGE_SIZE);
}

static inline size_t get_data_region_size_v3(uint32_t n_workers) {
    return (size_t)n_workers * get_worker_data_stride_v3();
}

static inline size_t get_step_event_ring_offset_v3(uint32_t n_workers) {
    return align_up_size_v3(get_data_region_offset_v3(n_workers) +
                            get_data_region_size_v3(n_workers),
                            PAGE_SIZE);
}

static inline size_t get_step_event_ring_size_v3(uint32_t capacity) {
    return sizeof(struct StepEventRingHeader) +
           (size_t)capacity * sizeof(struct StepEventSlot);
}

static inline size_t get_total_shm_size_v3(uint32_t n_workers,
                                           uint32_t step_event_capacity) {
    return get_step_event_ring_offset_v3(n_workers) +
           get_step_event_ring_size_v3(step_event_capacity);
}

static inline int shm_header_has_v3_layout(const struct ShmHeader *hdr) {
    return hdr != 0 && hdr->version >= 3 &&
           hdr->control_region_offset != 0 &&
           hdr->data_region_offset != 0 &&
           hdr->step_ring_offset != 0 &&
           hdr->per_worker_control_stride != 0 &&
           hdr->per_worker_data_stride != 0;
}

// V3 layout 是唯一布局：所有 typed-view helper 直接使用 header 内显式 region
// 字段，**不再保留 v2 fallback**。caller 必须保证 ShmHeader.version == 3、
// shm_header_has_v3_layout(hdr) == true。

static inline struct WorkerControlAreaV3 *get_worker_control_area_v3(
    void *shm_base,
    uint32_t worker_id) {
    struct ShmHeader *hdr = get_shm_header_v3(shm_base);
    uintptr_t base = (uintptr_t)shm_base;
    return (struct WorkerControlAreaV3 *)(
        base + (size_t)hdr->control_region_offset +
        (size_t)worker_id * (size_t)hdr->per_worker_control_stride);
}

static inline const struct WorkerControlAreaV3 *get_worker_control_area_v3_const(
    const void *shm_base,
    uint32_t worker_id) {
    const struct ShmHeader *hdr = get_shm_header_v3_const(shm_base);
    uintptr_t base = (uintptr_t)shm_base;
    return (const struct WorkerControlAreaV3 *)(
        base + (size_t)hdr->control_region_offset +
        (size_t)worker_id * (size_t)hdr->per_worker_control_stride);
}

static inline struct WorkerDataWindowV3 *get_worker_data_window_v3(
    void *shm_base,
    uint32_t worker_id) {
    struct ShmHeader *hdr = get_shm_header_v3(shm_base);
    uintptr_t base = (uintptr_t)shm_base;
    return (struct WorkerDataWindowV3 *)(
        base + (size_t)hdr->data_region_offset +
        (size_t)worker_id * (size_t)hdr->per_worker_data_stride);
}

static inline const struct WorkerDataWindowV3 *get_worker_data_window_v3_const(
    const void *shm_base,
    uint32_t worker_id) {
    const struct ShmHeader *hdr = get_shm_header_v3_const(shm_base);
    uintptr_t base = (uintptr_t)shm_base;
    return (const struct WorkerDataWindowV3 *)(
        base + (size_t)hdr->data_region_offset +
        (size_t)worker_id * (size_t)hdr->per_worker_data_stride);
}

static inline size_t get_worker_data_offset_v3(const struct ShmHeader *hdr,
                                               uint32_t worker_id) {
    return (size_t)hdr->data_region_offset +
           (size_t)worker_id * (size_t)hdr->per_worker_data_stride;
}

static inline struct ProgramResultPageV3 *get_worker_result_page_v3(
    void *shm_base,
    uint32_t worker_id) {
    struct WorkerDataWindowV3 *data = get_worker_data_window_v3(shm_base, worker_id);
    return &data->result_page;
}

static inline const struct ProgramResultPageV3 *get_worker_result_page_v3_const(
    const void *shm_base,
    uint32_t worker_id) {
    const struct WorkerDataWindowV3 *data = get_worker_data_window_v3_const(shm_base, worker_id);
    return &data->result_page;
}

static inline struct StepEventRingHeader *get_step_event_ring_header_v3(void *shm_base) {
    struct ShmHeader *hdr = get_shm_header_v3(shm_base);
    return (struct StepEventRingHeader *)(
        (uintptr_t)shm_base + (size_t)hdr->step_ring_offset);
}

static inline const struct StepEventRingHeader *get_step_event_ring_header_v3_const(
    const void *shm_base) {
    const struct ShmHeader *hdr = get_shm_header_v3_const(shm_base);
    return (const struct StepEventRingHeader *)(
        (uintptr_t)shm_base + (size_t)hdr->step_ring_offset);
}

static inline struct StepEventSlot *get_step_event_slots_v3(void *shm_base) {
    struct StepEventRingHeader *hdr = get_step_event_ring_header_v3(shm_base);
    return (struct StepEventSlot *)((uintptr_t)hdr + sizeof(struct StepEventRingHeader));
}

static inline const struct StepEventSlot *get_step_event_slots_v3_const(const void *shm_base) {
    const struct StepEventRingHeader *hdr = get_step_event_ring_header_v3_const(shm_base);
    return (const struct StepEventSlot *)((uintptr_t)hdr + sizeof(struct StepEventRingHeader));
}

static inline struct StepEventSlot *get_step_event_slot_by_pos_v3(void *shm_base,
                                                                   uint64_t pos,
                                                                   uint32_t capacity) {
    struct StepEventSlot *slots = get_step_event_slots_v3(shm_base);
    return &slots[(uint32_t)(pos & (uint64_t)(capacity - 1U))];
}

static inline const struct StepEventSlot *get_step_event_slot_by_pos_v3_const(
    const void *shm_base,
    uint64_t pos,
    uint32_t capacity) {
    const struct StepEventSlot *slots = get_step_event_slots_v3_const(shm_base);
    return &slots[(uint32_t)(pos & (uint64_t)(capacity - 1U))];
}

// Backward-compatible helper name; default StepEventRing capacity.
static inline size_t get_total_shm_size(uint32_t n_workers) {
    return get_total_shm_size_v3(n_workers, STEPEVENT_RING_DEFAULT_CAPACITY);
}

// --- acquire/release helpers ---
static inline uint32_t load_host_ready_v3(const struct ShmHeader *hdr) {
    return __atomic_load_n(&hdr->host_ready, __ATOMIC_ACQUIRE);
}

static inline void store_host_ready_v3(struct ShmHeader *hdr, uint32_t v) {
    __atomic_store_n(&hdr->host_ready, v, __ATOMIC_RELEASE);
}

static inline uint32_t load_corpus_triaged_v3(const struct ShmHeader *hdr) {
    return __atomic_load_n(&hdr->corpus_triaged, __ATOMIC_ACQUIRE);
}

static inline void store_corpus_triaged_v3(struct ShmHeader *hdr, uint32_t v) {
    __atomic_store_n(&hdr->corpus_triaged, v, __ATOMIC_RELEASE);
}

// [machine-check C4.6] env_features publish (worker-0) / read (host).
static inline uint32_t load_env_features_ready_v3(const struct ShmHeader *hdr) {
    return __atomic_load_n(&hdr->env_features_ready, __ATOMIC_ACQUIRE);
}

// Worker-0: write the probed env facts, THEN publish the ready flag with a
// release store so a host acquire-load of the flag observes the full struct.
static inline void publish_env_features_v3(struct ShmHeader *hdr,
                                           const struct EnvFeatures *ef) {
    hdr->env_features = *ef;
    __atomic_store_n(&hdr->env_features_ready, 1u, __ATOMIC_RELEASE);
}

static inline uint32_t task_slot_load_state_v3(const struct TaskSlot *slot) {
    return __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
}

static inline void task_slot_store_state_v3(struct TaskSlot *slot, uint32_t v) {
    __atomic_store_n(&slot->state, v, __ATOMIC_RELEASE);
}

static inline uint32_t completion_slot_load_state_v3(const struct CompletionSlot *slot) {
    return __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
}

static inline void completion_slot_store_state_v3(struct CompletionSlot *slot, uint32_t v) {
    __atomic_store_n(&slot->state, v, __ATOMIC_RELEASE);
}

static inline uint32_t program_result_load_state_v3(
    const struct ProgramResultPageV3 *page) {
    return __atomic_load_n(&page->state, __ATOMIC_ACQUIRE);
}

static inline void program_result_store_state_v3(struct ProgramResultPageV3 *page,
                                                 uint32_t v) {
    __atomic_store_n(&page->state, v, __ATOMIC_RELEASE);
}

static inline uint64_t program_result_load_commit_seq_v3(
    const struct ProgramResultPageV3 *page) {
    return __atomic_load_n(&page->commit_seq, __ATOMIC_ACQUIRE);
}

static inline void program_result_store_commit_seq_v3(struct ProgramResultPageV3 *page,
                                                      uint64_t v) {
    __atomic_store_n(&page->commit_seq, v, __ATOMIC_RELEASE);
}

static inline uint64_t step_event_head_fetch_add_v3(struct StepEventRingHeader *hdr,
                                                     uint64_t delta) {
    return __atomic_fetch_add(&hdr->head, delta, __ATOMIC_ACQ_REL);
}

static inline uint64_t step_event_head_load_v3(const struct StepEventRingHeader *hdr) {
    return __atomic_load_n(&hdr->head, __ATOMIC_ACQUIRE);
}

static inline uint64_t step_event_tail_load_v3(const struct StepEventRingHeader *hdr) {
    return __atomic_load_n(&hdr->tail, __ATOMIC_ACQUIRE);
}

static inline void step_event_tail_store_v3(struct StepEventRingHeader *hdr, uint64_t v) {
    __atomic_store_n(&hdr->tail, v, __ATOMIC_RELEASE);
}

static inline uint64_t step_event_seq_load_v3(const struct StepEventSlot *slot) {
    return __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
}

static inline void step_event_seq_store_v3(struct StepEventSlot *slot, uint64_t v) {
    __atomic_store_n(&slot->seq, v, __ATOMIC_RELEASE);
}

static inline uint64_t now_us() {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    timespec_get(&ts, TIME_UTC);
#endif
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

#endif // IVSHMEM_PROTOCOL_H
