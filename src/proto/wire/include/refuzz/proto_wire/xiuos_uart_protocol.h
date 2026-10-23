#ifndef XIUOS_UART_PROTOCOL_H
#define XIUOS_UART_PROTOCOL_H

/* XiUOS reFuzz worker UART wire protocol — host/guest shared constants.
 *
 * Canonical spec: docs/xiuos-refuzz/030_worker_abi.md §"Phase 1 worker
 * enforcement". Guest reference impl: kernel/refuzz/refuzz_worker.c in the
 * XiUOS fork. Any change here MUST be co-signed with that doc and the
 * guest-side impl, and MUST bump XIUOS_PROTOCOL_VERSION if the wire bytes
 * change.
 *
 * All multi-byte fields on the wire are big-endian. The XiUOS worker runs
 * on little-endian RV32, so both sides must byte-swap explicitly; this file
 * provides inline helpers (XiuosReadU16Be / XiuosPutU32Be / ...) for that.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== Constants ==================== */

#define XIUOS_MAGIC_0          0x52u  /* 'R' */
#define XIUOS_MAGIC_1          0x46u  /* 'F' */
#define XIUOS_PROTOCOL_VERSION 0x01u

#define XIUOS_HEADER_SIZE      8u
#define XIUOS_MIN_FRAME_SIZE   (XIUOS_HEADER_SIZE + 2u) /* +CRC16 */

#define XIUOS_CRC_INIT         0xFFFFu
#define XIUOS_CRC_POLY         0x1021u

#define XIUOS_PROGRAM_VERSION  0x01u
#define XIUOS_RESULT_VERSION   0x03u  /* v3: real-kcov sparse coverage = u16 n_hit + n_hit*(u16 idx,u8 cnt) then 32B state; see docs/plans/xiuos-real-kcov.md */
#define XIUOS_CALL_RECORD_SIZE 20u
#define XIUOS_RESULT_HEADER_SIZE 16u
#define XIUOS_COVERAGE_SIZE    256u
/* [State coverage] v2 appends XIUOS_STATE_SIZE raw per-program peak state-feature
 * bytes AFTER the coverage bitmap (one feedback region; coverage_size field on the
 * wire = XIUOS_COVERAGE_SIZE + XIUOS_STATE_SIZE). Host bucketizes + joint-hashes the
 * deterministic live-object-count features for a second coverage dimension that has
 * gradient when PC coverage is saturated. See docs/plans/xiuos-state-coverage-exploration.md. */
#define XIUOS_STATE_SIZE       32u
#define XIUOS_MAX_PAYLOAD      512u

/* [real-kcov v3 截断修复 2026-05-31] 出站 RESULT 帧(稀疏覆盖)的传输层上限,与入站
 * PROGRAM 帧的 XIUOS_MAX_PAYLOAD 解耦。实测 avg≈123 边/程序、15.5% 撞旧 512B 上限(=154
 * 边)被截断;family 结构边总数 ~844,2+844*3+32=2566B 即够,取 3072 留余量 → 单程序最多
 * (3072-32-2)/3≈1012 边 ≥ 结构上限,稀疏帧不再截断。sparse 帧实际字节 ∝ n_hit,典型程序仍
 * ~400B,不影响带宽。PROGRAM 侧 max-calls/channel cfg 仍用 XIUOS_MAX_PAYLOAD=512 不变;
 * codec 的 build/decode 帧上限 + worker result buffer 用此常量。 */
#define XIUOS_RESULT_MAX_PAYLOAD 3072u

/* [real-kcov v3] AFL 边覆盖位图桶数。worker(kernel/refuzz/refuzz_worker.c)累加 +
 * 稀疏上线;host XiuosCoverageSignal.seen_ 同尺寸。worker 端本地 #define 必须同值 4096。
 * v3 覆盖区 = u16 n_hit + n_hit*(u16 idx<4096, u8 cnt),其后接 XIUOS_STATE_SIZE。*/
#define XIUOS_COV_MAP_BITS     12u
#define XIUOS_COV_MAP_SIZE     (1u << XIUOS_COV_MAP_BITS)  /* 4096 */

/* Worker enforces these counts; host mutator must agree. */
#define XIUOS_SEM_SLOTS        4u
#define XIUOS_MUTEX_SLOTS      4u
#define XIUOS_MSGQ_SLOTS       4u
#define XIUOS_EVENT_SLOTS      4u
#define XIUOS_TIMER_SLOTS      4u
#define XIUOS_TASK_SLOTS       4u
#define XIUOS_WQ_SLOTS         4u
#define XIUOS_DQ_SLOTS         4u
#define XIUOS_WAITQ_SLOTS      4u
#define XIUOS_MALLOC_SLOTS     4u
#define XIUOS_GB_SLOTS         4u
#define XIUOS_GB_BLOCK_SLOTS   4u
#define XIUOS_CA_SLOTS         4u
#define XIUOS_AVL_SLOTS        4u
#define XIUOS_CAP_SLOTS        4u

/* ==================== Frame types ==================== */

typedef enum {
    XIUOS_FRAME_READY   = 0x01,
    XIUOS_FRAME_PING    = 0x02,
    XIUOS_FRAME_PONG    = 0x03,
    XIUOS_FRAME_ACK     = 0x04,
    XIUOS_FRAME_PROGRAM = 0x10,
    XIUOS_FRAME_RESULT  = 0x11,
    XIUOS_FRAME_RESET   = 0x12,
    XIUOS_FRAME_NACK    = 0x7F,
} XiuosFrameType;

/* ==================== Suite + API ==================== */

typedef enum {
    XIUOS_SUITE_COMMON_KERNEL = 0x00,
} XiuosSuiteId;

typedef enum {
    XIUOS_API_SEM_CREATE    = 0x01,
    XIUOS_API_SEM_DELETE    = 0x02,
    XIUOS_API_SEM_OBTAIN    = 0x03,
    XIUOS_API_SEM_ABANDON   = 0x04,
    XIUOS_API_SEM_SET_VALUE = 0x05,

    XIUOS_API_MUTEX_CREATE  = 0x10,
    XIUOS_API_MUTEX_DELETE  = 0x11,
    XIUOS_API_MUTEX_OBTAIN  = 0x12,
    XIUOS_API_MUTEX_ABANDON = 0x13,

    /* KMsgQueue family. Wire convention:
     *   MSGQ_CREATE(slot, msg_size_idx, max_msgs_idx)  argc=3
     *   MSGQ_DELETE(slot)                              argc=1
     *   MSGQ_SEND(slot, byte_pattern_idx)              argc=2  (non-blocking)
     *   MSGQ_RECV(slot, timeout_idx)                   argc=2
     *   MSGQ_URGENT_SEND(slot, byte_pattern_idx)       argc=2
     *   MSGQ_REINIT(slot)                              argc=1
     *
     * Worker folds each *_idx arg with raw & 0x03, then maps the index
     * through bounded tables: msg_size_idx -> {4, 8, 16, 16};
     * max_msgs_idx -> {1, 2, 4, 8}; byte_pattern_idx indexes a fixed
     * 4-pattern table. This keeps mutated programs small and deterministic
     * on the wire while still letting invalid-injection values such as
     * 0xffffffff probe table edges. */
    XIUOS_API_MSGQ_CREATE       = 0x20,
    XIUOS_API_MSGQ_DELETE       = 0x21,
    XIUOS_API_MSGQ_SEND         = 0x22,
    XIUOS_API_MSGQ_RECV         = 0x23,
    XIUOS_API_MSGQ_URGENT_SEND  = 0x24,
    XIUOS_API_MSGQ_REINIT       = 0x25,

    /* KEvent family. Wire convention:
     *   EVENT_CREATE(slot, options_idx)              argc=2
     *   EVENT_DELETE(slot)                           argc=1
     *   EVENT_TRIGGER(slot, events_pattern_idx)      argc=2
     *   EVENT_PROCESS(slot, events_pattern_idx,
     *                       timeout_idx, process_options_idx)   argc=4
     *
     * Worker folds each *_idx with raw & 0x03 and maps through bounded
     * tables: (create) options_idx -> {0, EVENT_OR, EVENT_AND,
     * EVENT_OR|EVENT_AUTOCLEAN}; events_pattern_idx indexes a fixed 4-pattern
     * table over the 29-bit EVENT_EVENTS_MASK. EVENT_PROCESS's
     * process_options_idx -> {EVENT_OR|EVENT_AUTOCLEAN (idx0, old default),
     * EVENT_AND, EVENT_OR, 0 (idx3)}; idx3 (neither AND nor OR) reaches the
     * KEventProcess `else { CHECK(0); }` spin. A legacy argc==3 call keeps the
     * idx0 default. */
    XIUOS_API_EVENT_CREATE      = 0x30,
    XIUOS_API_EVENT_DELETE      = 0x31,
    XIUOS_API_EVENT_TRIGGER     = 0x32,
    XIUOS_API_EVENT_PROCESS     = 0x33,

    /* KTimer family — 3-state lifecycle (EMPTY / CREATED / RUNNING).
     *
     *   TIMER_CREATE(slot, ticks_idx, mode_idx)  argc=3
     *   TIMER_DELETE(slot)                       argc=1
     *   TIMER_START_RUN(slot)                    argc=1
     *   TIMER_QUIT_RUN(slot)                     argc=1
     *   TIMER_MODIFY(slot, ticks_idx)            argc=2
     *
     * Worker folds each *_idx with raw & 0x03 and maps through bounded
     * tables: ticks_idx -> {10, 20, 50, 100}; mode_idx ->
     * {TIMER_TRIGGER_ONCE, TIMER_TRIGGER_PERIODIC, ONCE, PERIODIC}.
     *
     * KCreateTimer requires a callback fn pointer; worker provides a
     * fixed noop callback (RefuzzTimerNoopCallback) so the wire stays
     * data-only. The worker makes DELETE safe for RUNNING timers by
     * calling KTimerQuitRun before KDeleteTimer, so the FSM's DELETE
     * transition fires from CREATED *and* RUNNING. */
    XIUOS_API_TIMER_CREATE      = 0x40,
    XIUOS_API_TIMER_DELETE      = 0x41,
    XIUOS_API_TIMER_START_RUN   = 0x42,
    XIUOS_API_TIMER_QUIT_RUN    = 0x43,
    XIUOS_API_TIMER_MODIFY      = 0x44,
    /* TIMER_ASSIGN_MEMBER_RUN(slot, assign_ticks_idx) argc=2 — oracle-only.
     * KTimerAssignMemberRun(id, ticks) sets timer->origin_timeslice = ticks
     * (a raw x_ticks_t, unlike CREATE's uint8 table) then calls _StartRun.
     * assign_ticks_idx -> {100, 0, 0x7FFFFFFF, 0xFFFFFFFF}: idx1=0 hits the
     * function's own `ticks==0 -> -EINVALED` guard (graceful, unlike _StartRun's
     * CHECK); idx2/idx3 (>= TICK_SIZE_MAX/2) make _StartRun's
     * `CHECK(origin_timeslice < TICK_SIZE_MAX/2)` (softtimer.c:84) fail and spin
     * — the latent timer CHECK-spin (SP-1) that CREATE's uint8 ticks could not
     * reach. Re-running _StartRun on a started timer is also the Class A2
     * double-insert path. */
    XIUOS_API_TIMER_ASSIGN_MEMBER_RUN = 0x45,

    /* KTask (auxiliary victim tasks) family — 2-state lifecycle
     * (EMPTY / BLOCKED). Each op spawns a kernel task (KTaskCreate +
     * StartupKTask) whose body blocks on a target resource owned by the
     * main worker task. This exposes multi-waiter scenarios (sem broadcast
     * on SetValue, KEventDelete with pending waiters, KDeleteMsgQueue with
     * pending recv) that the single-task fuzz surface cannot reach.
     *
     *   TASK_SPAWN_BLOCK_SEM(task_slot, sem_slot)        argc=2
     *   TASK_SPAWN_BLOCK_EVENT(task_slot, event_slot)    argc=2
     *   TASK_SPAWN_BLOCK_MSGQ_RECV(task_slot, mq_slot)   argc=2
     *   TASK_TERMINATE(task_slot)                        argc=1
     *
     * Wire semantics:
     *  - target resource must exist (worker bails with -ERROR if not).
     *  - victim runs at REFUZZ_VICTIM_PRIORITY = worker+1 (numerically HIGHER
     *    = higher priority; XiUOS uses KTASK_LOWEST_PRIORITY=0). It therefore
     *    preempts the worker on spawn, runs its body immediately, and blocks on
     *    the resource right away (WAITING_FOREVER) -- yielding the CPU back to
     *    the worker. Net effect: victim ends up pending, worker resumes.
     *  - victim's blocking call uses WAITING_FOREVER; the only way out is
     *    the main task signaling the resource OR TASK_TERMINATE.
     *  - TERMINATE calls KTaskDelete; victim's pend_list entry needs to be
     *    cleaned by the kernel (LinklistResumeAll on Delete paths). */
    XIUOS_API_TASK_SPAWN_BLOCK_SEM        = 0x50,
    XIUOS_API_TASK_SPAWN_BLOCK_EVENT      = 0x51,
    XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_RECV  = 0x52,
    XIUOS_API_TASK_TERMINATE              = 0x53,
    /* TASK_PRIO_SET(task_slot, prio_idx)  argc=2
     * Calls KTaskPrioSet(victim_id, prio_table[idx]). XiUOS kernel
     * (kernel/thread/mutex.c:116) explicitly documents this API as
     * "bugged" but uses it anyway behind a commented-out call. Wiring it
     * lets reFuzz reach the priority-inheritance / scheduler-interaction
     * paths we've never probed. */
    XIUOS_API_TASK_PRIO_SET               = 0x54,
    /* TASK_SPAWN_SELF_SUSPEND(task_slot)  argc=1
     * Spawns a victim that calls SuspendKTask(self) immediately, then
     * (post-wakeup) enters RefuzzVictimSleepForever(). The task is in
     * kernel SUSPEND state until TASK_WAKEUP is dispatched.
     *
     * TASK_WAKEUP(task_slot)              argc=1
     * Main task calls KTaskWakeup(g_task_slots[slot]). Worker filters
     * empty slots (returns -ERROR) so we don't NULL-deref the kernel.
     * Spec: _KTaskWakeup requires SUSPEND state — wake-from-BLOCKED /
     * DELAYED returns -ERROR per kernel.
     *
     * TASK_SPAWN_SELF_DELAY(task_slot, ms_idx)  argc=2
     * Spawns a victim that calls MdelayKTask(_ms_table[ms_idx]) then
     * RefuzzVictimSleepForever(). _ms_table = {0, 10, 50, 200}; idx
     * folded via & 0x03. */
    XIUOS_API_TASK_SPAWN_SELF_SUSPEND     = 0x55,
    XIUOS_API_TASK_WAKEUP                 = 0x56,
    XIUOS_API_TASK_SPAWN_SELF_DELAY       = 0x57,
    /* TASK_SPAWN_BLOCK_SEM_TIMEOUT(task_slot, sem_slot, timeout_idx) argc=3
     * Oracle-only (NOT wired into the mutator/descriptor): spawns a victim
     * that calls KSemaphoreObtain(sem_id, _to_table[timeout_idx]) with a
     * FINITE timeout, then RefuzzVictimSleepForever(). The finite timeout
     * makes _SemaphoreObtain register KTaskSetDelay AFTER LinklistSuspend,
     * so a victim deleted while blocked leaves a dangling node in
     * xiaoshan_delay_head (Class F). _to_table = {50,100,200,500} ms; idx
     * folded via & 0x03. Used by the delay-list watermark oracle to prove
     * the Class F cleanup gap is not specific to MdelayKTask but common to
     * all suspend->KTaskSetDelay blockers. */
    XIUOS_API_TASK_SPAWN_BLOCK_SEM_TIMEOUT = 0x58,
    /* TASK_SPAWN_BLOCK_EVENT_TIMEOUT(task_slot, event_slot, timeout_idx) argc=3
     * TASK_SPAWN_BLOCK_MSGQ_RECV_TIMEOUT(task_slot, mq_slot, timeout_idx) argc=3
     * Oracle-only siblings of SEM_TIMEOUT: victim blocks in
     * KEventProcess / KMsgQueueRecv with a FINITE timeout (LinklistSuspend
     * then KTaskSetDelay last → delay node stays). Lateral coverage proving
     * the Class F delay-node leak is common to all suspend→KTaskSetDelay
     * blockers, not just MdelayKTask/sem. _to_table = {50,100,200,500} ms. */
    XIUOS_API_TASK_SPAWN_BLOCK_EVENT_TIMEOUT     = 0x59,
    XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_RECV_TIMEOUT = 0x5a,
    /* TASK_SPAWN_BLOCK_MUTEX_TIMEOUT(task_slot, mutex_slot, timeout_idx) argc=3
     * Oracle-only. Mutex needs a HOLDER first (the main worker obtains the
     * mutex via MUTEX_OBTAIN before spawning), else the victim acquires it
     * uncontended and never blocks. With the worker holding it, the victim's
     * finite-timeout KMutexObtain suspends + KTaskSetDelay-last → delay node
     * stays; deleting the blocked victim leaks it. Completes the finite-
     * timeout blocker matrix (sem/event/msgq/mutex + MdelayKTask). */
    XIUOS_API_TASK_SPAWN_BLOCK_MUTEX_TIMEOUT     = 0x5b,
    /* TASK_SPAWN_BLOCK_GB_ALLOC(task_slot, gb_slot, timeout_idx) argc=3
     * Oracle-only. Victim calls AllocBlockMemGather(g_gb_slots[gb_slot],
     * finite_timeout) on an EXHAUSTED pool → blocks on the pool's wait_task
     * list (via task->...sched_link) + KTaskSetDelay. Deleting the blocked
     * victim makes _DeleteKTask reuse that same sched_link for the zombie
     * list → corrupts wait_task. Probes whether the task-delete cleanup gap
     * (Class F family) extends to gatherblock's wait_task. */
    XIUOS_API_TASK_SPAWN_BLOCK_GB_ALLOC          = 0x5c,
    /* TASK_SPAWN_BLOCK_MSGQ_SEND_TIMEOUT(task_slot, mq_slot, timeout_idx) argc=3
     * Oracle-only. Send-side analog of MSGQ_RECV_TIMEOUT: victim calls
     * KMsgQueueSendwait(mq, buf, size, timeout) on a FULL queue (the oracle
     * pre-fills it with the worker's non-blocking MSGQ_SEND), so it blocks on
     * mq->send_pend_list. timeout_idx via the shared _to_table; idx3 =
     * WAITING_FOREVER. Unlike RECV, the SEND path special-cases WAITING_FOREVER
     * before CalculateTickFromTimeMs (msgqueue.c:104), so a WAITING_FOREVER
     * sender suspends with NO KTaskSetDelay (delay node stays 0) — the runtime
     * confirmation of TC-1's "send guarded, recv not". A FINITE-timeout sender
     * does register a delay node (KTaskSetDelay), so deleting it leaks the node
     * (Class F, send-side). */
    XIUOS_API_TASK_SPAWN_BLOCK_MSGQ_SEND_TIMEOUT = 0x5d,
    /* TASK_GET_PRIO(slot) argc=1 — oracle-only scheduler observable. Returns
     * the cur_prio of victim task `slot` (g_task_slots[slot]); slot >=
     * XIUOS_TASK_SLOTS returns the worker's OWN cur_prio. Used to observe
     * priority-inheritance / KTaskPrioSet effects. NOTE the XiUOS direction:
     * HIGHER numeric = HIGHER priority (KTASK_LOWEST_PRIORITY=0; the scheduler
     * keeps the task with the larger cur_prio running). Worker = 5. */
    XIUOS_API_TASK_GET_PRIO                      = 0x5e,
    /* TASK_SPAWN_BLOCK_MUTEX_HIGH(task_slot, mutex_slot) argc=2 — oracle-only.
     * Spawns a victim at a priority ABOVE the worker (numerically larger) that
     * KMutexObtain(mutex, WAITING_FOREVER)s a mutex the worker already holds, so
     * the higher-priority victim blocks on a lower-priority holder — the setup
     * for priority inheritance. A PI mutex would boost the holder (worker) up to
     * the blocked victim's priority; XiUOS's boost code is commented out
     * (mutex.c:114-120, "dont use KTaskPrioSet, for it's bugged"), so
     * TASK_GET_PRIO(self) shows the holder is NOT boosted — priority inversion
     * (a scheduler/QoS finding, not memory-safety). */
    XIUOS_API_TASK_SPAWN_BLOCK_MUTEX_HIGH        = 0x5f,

    /* KWorkQueue family (kernel/thread/workqueue.c).
     *
     *   WQ_CREATE(slot, prio_idx)               argc=2
     *   WQ_DEINIT(slot)                         argc=1
     *   WQ_SUBMIT(slot)                         argc=1  (immediate, noop work)
     *   WQ_SUBMIT_DELAYED(slot, time_idx)       argc=2  (schedules timer)
     *
     * Wire semantics:
     *  - prio_idx folds with & 0x03; worker maps via {6, 7, 8, 10} (all
     *    lower priority than worker so the WQ task can't preempt main).
     *  - SUBMIT uses a per-slot pre-init'd `struct Work` with a noop
     *    cb_func; data-only wire keeps mutator deterministic.
     *  - SUBMIT_DELAYED with time_idx -> {10, 20, 50, 100} ticks triggers
     *    the kernel's WorkSubmit() path that internally KCreateTimer +
     *    KTimerStartRun's (potentially exercises Class A/A2 indirectly).
     *  - DEINIT calls DeInitWorkQueue (non-static in workqueue.c but
     *    absent from xs_workqueue.h — we extern it). */
    XIUOS_API_WQ_CREATE                   = 0x60,
    XIUOS_API_WQ_DEINIT                   = 0x61,
    XIUOS_API_WQ_SUBMIT                   = 0x62,
    XIUOS_API_WQ_SUBMIT_DELAYED           = 0x63,

    /* Dataqueue family (kernel/thread/data_queue.c).
     *
     *   DQ_INIT(slot, node_count_idx)            argc=2
     *   DQ_DEINIT(slot)                          argc=1
     *   DQ_PUSH(slot, size_idx, timeout_idx)     argc=3
     *   DQ_POP(slot, timeout_idx)                argc=2
     *   DQ_PEEK(slot)                            argc=1
     *
     * Wire semantics:
     *  - node_count_idx folds via & 0x03 -> {0, 2, 4, 8}. 0 is included
     *    to probe the (rear+1) % 0 div-by-zero / sem_blank uint8
     *    underflow path explicitly.
     *  - size_idx folds via & 0x03 -> {1, 4, 16, 32}; worker owns the
     *    backing buffer (no caller-supplied pointers).
     *  - timeout_idx folds via & 0x03 -> {WAITING_FOREVER, 0, 50, 200}.
     *    50 / 200 ms exercise the finite-timeout branch in
     *    PushDataqueue that is missing from the do-while(0) cascade.
     *  - Push stores worker-owned pointers; Pop / Peek discard returned
     *    pointers (host doesn't read into worker buffer space). */
    XIUOS_API_DQ_INIT                     = 0x70,
    XIUOS_API_DQ_DEINIT                   = 0x71,
    XIUOS_API_DQ_PUSH                     = 0x72,
    XIUOS_API_DQ_POP                      = 0x73,
    XIUOS_API_DQ_PEEK                     = 0x74,

    /* Waitqueue family (kernel/thread/waitqueue.c).
     *
     *   WAITQ_INIT(slot)                          argc=1
     *   WAITQ_SPAWN_WAIT(task_slot, queue_slot,
     *                    timeout_idx)             argc=3
     *   WAITQ_WAKE(slot)                          argc=1
     *
     * Wire semantics:
     *  - Worker owns static `WaitQueueType g_waitq_slots[4]` (caller
     *    storage) and per-victim `WaitqueueNode g_waitq_victim_node[4]`
     *    (worker-owned node memory). InitWqueue is idempotent in kernel
     *    semantics — just inits the list head.
     *  - WAITQ_SPAWN_WAIT spawns a victim task that calls
     *    WqueueWait(g_waitq_slots[queue_slot], tick_table[timeout_idx]).
     *    timeout_idx via _ticks table {10,20,50,100} so the victim
     *    eventually returns (-ETIMEOUT) if not woken.
     *  - WAITQ_WAKE calls WakeupWqueue(slot, NULL). Wakes all waiters.
     *  - Direct hypothesis: KTaskDelete on a victim in block_threads_list
     *    may leave a dangling node — same pattern as Class F. */
    XIUOS_API_WAITQ_INIT                  = 0x80,
    XIUOS_API_WAITQ_SPAWN_WAIT            = 0x81,
    XIUOS_API_WAITQ_WAKE                  = 0x82,

    /* Oracle-only resource introspection.
     *
     *   RESOURCE_SNAPSHOT()                      argc=0
     *
     * This op is intentionally not a mutator/corpus family. It is a
     * read-only diagnostic endpoint for call-level oracle cases that need
     * to assert "resources returned to baseline" without wedging the
     * worker. v2 aux encoding:
     *
     *   bits  0..7   waitqueue pending-node count across initialized queues
     *   bits  8..15  live victim task slots
     *   bits 16..23  active delay-list nodes in xiaoshan_delay_head
     *
     * Expected value for a fully cleaned-up oracle program is 0. */
    XIUOS_API_RESOURCE_SNAPSHOT           = 0x90,

    /* Oracle-only heap watermark.
     *
     *   HEAP_SNAPSHOT()                          argc=0
     *
     * Returns (current heap used bytes - per-program baseline) as a signed
     * int32 delta. The baseline is captured at program start, after
     * RefuzzCleanupSlots + RefuzzResetSlots leave a clean state. A program
     * that creates AND destroys every object it touches should net delta 0;
     * a positive delta after the destroy path ran witnesses un-reclaimed
     * heap (a lifetime / cleanup leak). Read via MemoryInfo(); turns heap
     * lifetime bugs from NO_WEDGE silence into call-level findings, the same
     * upgrade RESOURCE_SNAPSHOT gave waitqueue. */
    XIUOS_API_HEAP_SNAPSHOT               = 0x91,

    /* Oracle-only tick-conversion contract probes (kernel/thread/tick.c).
     *
     *   TICK_MS_TO_TICK(ms_raw)    argc=1  -> CalculateTickFromTimeMs(ms_raw)
     *   TICK_TO_MS(ticks_raw)      argc=1  -> CalculateTimeMsFromTick(ticks_raw)
     *
     * Unlike every other op, args[0] is NOT a slot — it is the literal scalar
     * fed straight into the conversion. Oracle-only (not a mutator/corpus
     * family); the case table passes exact boundary values and asserts the
     * returned tick/ms count in aux. These pin down three tick.c contract
     * oddities that surfaced from the gatherblock source audit:
     *
     *  - ms==0 does NOT yield 0 ticks: CalculateTickFromTimeMs clamps 0 to
     *    MIN_TICKS(1), so a "nonblocking" timeout becomes a ~1-tick wait. The
     *    `if (wait_time == 0) return NONE;` guard in AllocBlockMemGather is
     *    therefore dead code.
     *  - ms==WAITING_FOREVER(-1, 0xFFFFFFFF) does NOT stay infinite: the
     *    `(uint64)(ms * TICK_PER_SECOND)` cast is applied AFTER a uint32
     *    multiply, so ms*100 overflows mod 2^32 to 0xFFFFFF9C and divides to a
     *    finite 4294967 ticks. Callers that special-case WAITING_FOREVER before
     *    converting are safe; gatherblock (which does not) gets a bounded
     *    garbage timeout instead of blocking forever.
     *  - the `tmp >= 5 && tmp <= 9` sub-tick rounding branch is unreachable at
     *    TICK_PER_SECOND=100: ms*100 mod 1000 is always a multiple of 100, so
     *    the remainder never lands in [5,9]. Pure dead code on this board. */
    XIUOS_API_TICK_MS_TO_TICK             = 0x92,
    XIUOS_API_TICK_TO_MS                  = 0x93,

    /* Oracle-observable heap self-check (kernel/memory/byte_manage.c
     * CheckDynamicMemoryIntegrity). Walks the buddy heap by boundary tags and
     * returns the first violated structural invariant in aux (0 = consistent).
     * Detector-upgrade op: lets an oracle case prove the heap state is corrupt
     * AFTER a sequence that has NOT yet faulted (e.g. the Class B undersized-
     * block overwrite manifests only when the clobbered neighbor is later
     * freed). argc=0; not a mutator/corpus family. */
    XIUOS_API_HEAP_INTEGRITY              = 0x94,

    /* Direct allocator family (kernel/memory/byte_manage.c). A real
     * mutator/corpus family (unlike the oracle-only ops above) — drives the
     * byte heap directly instead of indirectly through object lifecycles.
     * Exercises paths object-lifecycle fuzzing never reaches: x_realloc
     * (grow/shrink/coalesce-metadata), zero-size malloc, large-size, and
     * tighter Class B (BigMemFree coalesce) reproducers.
     *
     *   MALLOC(slot, size_idx)            argc=2
     *   FREE(slot)                        argc=1
     *   REALLOC(slot, size_idx)           argc=2
     *   CALLOC(slot, count_idx, size_idx) argc=3
     *
     * Wire semantics:
     *  - worker owns void* g_malloc_slots[XIUOS_MALLOC_SLOTS]; pointers
     *    never escape worker memory and are not dereferenced (data-only).
     *  - size_idx folds & 0x03 -> {0, 16, 64, 256} bytes (0 probes
     *    zero-size). count_idx folds & 0x03 -> {0, 1, 4, 16}.
     *  - MALLOC/CALLOC on an occupied slot free the old block first.
     *  - REALLOC on an empty slot behaves as malloc (x_realloc(NULL,...)).
     *  - end-of-program cleanup frees every live slot. */
    XIUOS_API_MALLOC                      = 0xA0,
    XIUOS_API_FREE                        = 0xA1,
    XIUOS_API_REALLOC                     = 0xA2,
    XIUOS_API_CALLOC                      = 0xA3,

    /* Gatherblock fixed-size pool allocator (kernel/memory/gatherblock.c).
     * Requires CONFIG_KERNEL_MEMBLOCK=y — this is a CONFIG-EXPANDED family,
     * not part of the baseline full-init config; campaigns using it must be
     * recorded separately. Independent allocator/lifecycle from byte_manage;
     * upstream recently fixed 2 lifecycle bugs here (Init pool-too-small OOB,
     * Delete-with-allocated-blocks UAF), so the module is known-fragile.
     *
     *   GB_CREATE(slot, block_size_idx, block_count_idx) argc=3
     *   GB_DELETE(slot)                                  argc=1
     *   GB_ALLOC(slot, block_slot, timeout_idx)          argc=3
     *   GB_FREE(slot, block_slot)                        argc=2
     *
     * Wire semantics:
     *  - worker owns GatherMemType g_gb_slots[4] (pool handles, like WQ) and
     *    void* g_gb_blocks[4][4] (per-pool allocated block ptrs); pointers
     *    never escape worker memory and are not dereferenced.
     *  - block_size_idx & 0x03 -> {0, 8, 32, 128} (0 probes the pool-too-
     *    small path). block_count_idx & 0x03 -> {0, 1, 4, 16}.
     *  - GB_ALLOC stores the block ptr in g_gb_blocks[slot][block_slot];
     *    GB_FREE frees that slot. block_slot lets the mutator express
     *    double-free (free same block_slot twice) and free-after-delete.
     *  - timeout_idx & 0x03 -> {0, 50, 200, WAITING_FOREVER} ms; the finite
     *    values exercise the alloc-waiter path (a victim blocked in
     *    AllocBlockMemGather, then externally deleted — probes whether the
     *    task-delete delay-list cleanup gap (Class F family) extends here). */
    XIUOS_API_GB_CREATE                   = 0xB0,
    XIUOS_API_GB_DELETE                   = 0xB1,
    XIUOS_API_GB_ALLOC                    = 0xB2,
    XIUOS_API_GB_FREE                     = 0xB3,

    /* Circular-area byte ring buffer (kernel/thread/circular_area.c). Requires
     * CONFIG_KERNEL_CIRCULAR_AREA=y — a CONFIG-EXPANDED family, not part of the
     * baseline full-init config; campaigns using it must be recorded
     * separately. Pure data structure (no task/blocking semantics): a single
     * heap-backed ring with read/write indices.
     *
     *   CA_INIT(slot, length_idx)           argc=2
     *   CA_RELEASE(slot)                    argc=1
     *   CA_RESET(slot)                      argc=1
     *   CA_WRITE(slot, xfer_idx, force)     argc=3
     *   CA_READ(slot, xfer_idx)             argc=2
     *   CA_GET_DATA_LENGTH(slot)            argc=1  -> CircularAreaGetDataLength
     *
     * Wire semantics:
     *  - worker owns CircularAreaType g_ca_slots[XIUOS_CA_SLOTS]; the handle
     *    never escapes worker memory.
     *  - length_idx & 0x03 -> {0, 64, 256, 512} bytes (post ALIGN_MEN_DOWN/4).
     *    0 probes the CHECK(len>0) / zero-length path; 256 is the uint8 index
     *    boundary; 512 exceeds it.
     *  - xfer_idx & 0x03 -> {1, 64, 300, 500} bytes copied from/to a worker
     *    pattern buffer (data-only; pointers never escape). force = arg&1.
     *  - CA_WRITE/READ on an empty (released or never-init) slot return -ERROR;
     *    CA_RELEASE on an empty slot is a no-op error (guards double-free /
     *    use-after-release — those are API-misuse, not kernel bugs).
     *  - end-of-program cleanup releases every live slot.
     *
     * Source-audit target: readidx/writeidx are uint8 but area_length is
     * uint32, so for length > 256 the `idx = (idx + n) % area_length`
     * assignment truncates mod 256 — a length>256 ring silently corrupts its
     * data-length accounting. CA_GET_DATA_LENGTH makes that observable. */
    XIUOS_API_CA_INIT                     = 0xC0,
    XIUOS_API_CA_RELEASE                  = 0xC1,
    XIUOS_API_CA_RESET                    = 0xC2,
    XIUOS_API_CA_WRITE                    = 0xC3,
    XIUOS_API_CA_READ                     = 0xC4,
    XIUOS_API_CA_GET_DATA_LENGTH          = 0xC5,

    /* AVL tree (kernel/thread/avl_tree.c). Requires CONFIG_KERNEL_AVL_TREE=y —
     * a CONFIG-EXPANDED family, not part of the baseline full-init config;
     * campaigns using it must be recorded separately. Pure data structure: a
     * per-slot root pointer (AvlNodeType); the recursive API returns a new
     * root each mutation. Nodes are x_malloc'd internally and the node struct
     * (data/height/left/right) is exposed, so the worker walks the tree to
     * compute oracle observables.
     *
     *   AVL_INSERT(slot, data_idx)         argc=2  -> root = AvlTreeInsertNode
     *   AVL_DELETE(slot, data_idx)         argc=2  -> root = AvlTreeDeleteNode
     *   AVL_MODIFY(slot, src_idx, dst_idx) argc=3  -> root = AvlNodeModifyNode
     *   AVL_SEARCH(slot, data_idx)         argc=2  -> aux 1 if found else 0
     *   AVL_COUNT(slot)                    argc=1  -> aux node count (tree walk)
     *   AVL_CHECK(slot)                    argc=1  -> aux invariant-violation
     *                                                bitmask (0 = all hold)
     *
     * Wire semantics:
     *  - data_idx & 0x0F -> kRefuzzAvlData[16] = {1..16}. The 16-value table
     *    gives enough distinct keys to build height-3 trees (needed to drive
     *    the delete-rebalance path).
     *  - AVL_CHECK bitmask: bit0 = BST order (in-order not strictly
     *    increasing), bit1 = AVL balance (some |BF| > 1), bit2 = cached height
     *    inconsistent with recomputed height.
     *  - end-of-program cleanup post-order-frees each slot's reachable tree.
     *    Nodes orphaned by a buggy rebalance (see below) are unreachable from
     *    the root and therefore leak — a faithful consequence of the bug.
     *
     * Source-audit target: AvlTreeBalance initializes new_node = NONE and only
     * rebalances for BF(heavy_child) strictly > 0 or < 0; when a node reaches
     * |BF| = 2 with its heavy child at BF == 0 (reachable via delete, not
     * insert), all four branches miss and it returns NONE, silently dropping
     * the whole subtree. AVL_COUNT / AVL_SEARCH make that observable. */
    XIUOS_API_AVL_INSERT                  = 0xD0,
    XIUOS_API_AVL_DELETE                  = 0xD1,
    XIUOS_API_AVL_MODIFY                  = 0xD2,
    XIUOS_API_AVL_SEARCH                  = 0xD3,
    XIUOS_API_AVL_COUNT                   = 0xD4,
    XIUOS_API_AVL_CHECK                   = 0xD5,

    /* Task capability map (kernel/thread/capability.c, new 2024 code). Requires
     * CONFIG_KERNEL_CAPABILITY=y — CONFIG-EXPANDED, recorded separately from
     * baseline. Two layers: a flag bitset (xs_capability) and a global pid->cap
     * linked-list map. The worker owns xs_capability flag buffers; the map is
     * keyed by an arbitrary int32 pid (no real task needed) EXCEPT that
     * Set/ClearTaskCapability use the *worker's own* pid as the privileged
     * "current" caller.
     *
     *   CAP_FLAG_SET(slot, type_idx)       argc=2  SetCapability(&buf, type)
     *   CAP_FLAG_CHECK(slot, type_idx)     argc=2  -> aux nonzero if set
     *   CAP_ADD_TASK(pid_idx, slot)        argc=2  AddTaskCapability(pid, &buf)
     *   CAP_ADD_ROOT(pid_idx)              argc=1  AddRootTaskCapability(pid)
     *   CAP_ADD_ROOT_SELF()                argc=0  AddRootTaskCapability(self)
     *   CAP_REMOVE_TASK(pid_idx)           argc=1  RemoveTaskCapability(pid)
     *   CAP_CHECK_TASK(pid_idx, type_idx)  argc=2  -> aux 1 if task has cap
     *   CAP_SET_TASK(pid_idx, type_idx)    argc=2  SetTaskCapability(pid, type)
     *
     * Wire semantics:
     *  - slot indexes g_cap_slots[XIUOS_CAP_SLOTS] flag buffers.
     *  - pid_idx & 0x03 -> kRefuzzCapPids[4] = {100,200,300,400} (arbitrary
     *    keys, never real task ids). type_idx & 0x03 -> {ROOT,TASK,MEM,
     *    RESOURCES} (all in-range; the flags[1]-byte OOB for type>=8 is a
     *    separate source-audit lead, not wired).
     *  - the global pid->cap list is process-global; the worker drains it per
     *    program at cleanup (no clear-all API) over the pid table + worker pid.
     *
     * Source-audit targets: (CAP-1) Set/ClearTaskCapability look up the caller
     * via FindTaskCapability(current) and call CheckCapability(cap,...) with no
     * NULL guard, so an unregistered caller NULL-derefs; (CAP-2)
     * AddRootTaskCapability x_mallocs a cap, copies it into the node, and never
     * frees it -> heap leak per call. */
    XIUOS_API_CAP_FLAG_SET                = 0xE0,
    XIUOS_API_CAP_FLAG_CHECK              = 0xE1,
    XIUOS_API_CAP_ADD_TASK                = 0xE2,
    XIUOS_API_CAP_ADD_ROOT                = 0xE3,
    XIUOS_API_CAP_ADD_ROOT_SELF           = 0xE4,
    XIUOS_API_CAP_REMOVE_TASK             = 0xE5,
    XIUOS_API_CAP_CHECK_TASK              = 0xE6,
    XIUOS_API_CAP_SET_TASK                = 0xE7,
} XiuosApiId;

/* ==================== RESULT status ==================== */

typedef enum {
    XIUOS_STATUS_OK               = 0x00,
    XIUOS_STATUS_PROGRAM_REJECTED = 0x01,
    XIUOS_STATUS_UNSUPPORTED_API  = 0x02,
    XIUOS_STATUS_WORKER_ERROR     = 0x03,
    /* A per-call heap/state invariant check failed AFTER a call but before the
     * worker faulted (silent corruption). The worker skips its normal cleanup
     * (freeing the corrupted heap would trap), reports this status with the
     * invariant code in aux, and leaves its heap unsafe — the host must reset
     * the worker before the next program. */
    XIUOS_STATUS_STATE_VIOLATION  = 0x04,
    /* A per-call SEMANTIC CONTRACT was violated: an operation whose precondition
     * the worker verified (valid live slot, in-range args) and whose spec mandates
     * success returned a non-EOK value (e.g. WorkSubmit's success path missing
     * `return EOK`). NOT a crash/leak — the worker is healthy and cleanup is safe.
     * Soft finding: trap_or_pc = (api_id<<8 | call_index), aux = the wrong return. */
    XIUOS_STATUS_CONTRACT_VIOLATION = 0x05,
    /* A priority-inheritance invariant was violated: a held mutex has a blocked
     * waiter MORE urgent than the holder's effective priority (the holder was not
     * boosted). NOT a crash/leak — worker healthy. Soft finding: trap_or_pc =
     * (holder_prio<<8 | waiter_prio), aux = mutex slot. */
    XIUOS_STATUS_PRIORITY_INVERSION = 0x06,
    /* A task's stack high-water came within a safety margin of its allotted depth.
     * On virt-rv32 KERNEL_STACK_OVERFLOW_CHECK is off so this is otherwise silent.
     * Worker healthy. Soft: trap_or_pc = (task_slot<<16 | depth), aux = used. */
    XIUOS_STATUS_STACK_OVERFLOW   = 0x07,
    XIUOS_STATUS_TRAP             = 0x80,
} XiuosResultStatus;

/* ==================== Wire byte layout (descriptive) ====================
 *
 * Frame:
 *   offset  size  field
 *   0       1     magic0 (0x52 'R')
 *   1       1     magic1 (0x46 'F')
 *   2       1     version (0x01)
 *   3       1     type (XiuosFrameType)
 *   4       2     seq (BE)
 *   6       2     len (BE)
 *   8       len   payload
 *   8+len   2     crc16 (BE), covers header+payload, CRC-16/CCITT-FALSE
 *
 * PROGRAM payload:
 *   offset  size  field
 *   0       1     program_version (0x01)
 *   1       1     suite_id
 *   2       1     call_count
 *   3       1     flags
 *   4       ...   call records (20 bytes each)
 *
 * Call record (20 bytes):
 *   offset  size  field
 *   0       1     api_id
 *   1       1     argc (0..4)
 *   2       2     call_flags (BE)
 *   4       4     arg0 (BE)
 *   8       4     arg1 (BE)
 *   12      4     arg2 (BE)
 *   16      4     arg3 (BE)
 *
 * RESULT payload:
 *   offset  size  field
 *   0       1     result_version (0x01)
 *   1       1     status (XiuosResultStatus)
 *   2       2     flags (BE)
 *   4       2     calls_executed (BE)
 *   6       2     coverage_size (BE, currently 256)
 *   8       4     trap_or_pc (BE)
 *   12      4     aux (BE, treated signed by host)
 *   16      N     coverage bitmap (N = coverage_size)
 */

/* ==================== Big-endian inline helpers ==================== */

static inline uint16_t XiuosReadU16Be(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t XiuosReadU32Be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
            (uint32_t)p[3];
}

static inline void XiuosPutU16Be(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static inline void XiuosPutU32Be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >>  8) & 0xFFu);
    p[3] = (uint8_t)(v & 0xFFu);
}

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflect, no xorout. */
static inline uint16_t XiuosCrc16Update(uint16_t crc, uint8_t byte) {
    crc = (uint16_t)(crc ^ ((uint16_t)byte << 8));
    for (int i = 0; i < 8; ++i) {
        if (crc & 0x8000u) {
            crc = (uint16_t)((crc << 1) ^ XIUOS_CRC_POLY);
        } else {
            crc = (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static inline uint16_t XiuosCrc16(const uint8_t* buf, size_t len) {
    uint16_t crc = XIUOS_CRC_INIT;
    for (size_t i = 0; i < len; ++i) {
        crc = XiuosCrc16Update(crc, buf[i]);
    }
    return crc;
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* XIUOS_UART_PROTOCOL_H */
