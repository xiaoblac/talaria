#pragma once

// [v3 Phase 1.B] IDataPlane — 数据面抽象（Submit / Poll / 生命周期 / 就地盘点）
//
// 设计来源：docs/channel-redesign/v3/30_data_plane.md
// 职责：
//   - Submit：把一次 dispatch 送进 wire；返回 SubmitOutcome
//   - Poll：拉取已完成任务，翻译成语义级 DispatchOutcome（消除 wire 语义泄漏）
//   - Pause/Resume：编排恢复期间的读写门控
//   - Reset：recovery 执行层使用的"就地清零"接口（整板 / 单 worker）
//   - SnapshotInflight：RecoveryExe 决定哪些 executor_id 需要发 abnormal
//
// 非职责：
//   - 不决策 recovery；不做 heartbeat；不读 console；不做 session 管理

#include "refuzz/channel/result.hpp"
#include "refuzz/core/channel_contract.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

namespace refuzz::channel::data {

// SubmitOutcome — TrySend 的同步结果（不含完成信息）
enum class SubmitOutcome : uint8_t {
    kSent = 0,        // 成功排入 wire / 已写 slot
    kBusy,            // slot 满 / worker 忙（可重试 / 入 deferred_）
    kWorkerDown,      // worker 不在 Sendability 集合 / 已被 Revoke
    kPaused,          // data plane 处于 Pause 状态
    kInvalid,         // 入参不合法（payload 过大 / worker_id 越界）
};

// DispatchOutcomeKind — 单次 dispatch 的语义级完成码
//
// 注意：不再携带任何 ivshmem wire 状态枚举（如 COMP_STATUS_*）。
// IvshmemDataPlane 在 Poll 内部把 wire 状态翻译成这些语义值，Channel 的 Translate
// 只读这里。

enum class DispatchOutcomeKind : uint8_t {
    kOk = 0,
    kPartial,         // 程序自己提前结束（exit_group(任意码)/无 handler 的信号）；output 是有效前缀
    kNoResult,        // 真的没有任何产出（零 progress）→ 下游直接不消费，不需再判 output_len
    kTimeout,         // program watchdog 超时（error_code=ERR_TIMEOUT，数据有效，
                      // 走 Completion 侧）。**不再**承载 daemon task hang。
    kHang,            // worker 显式判定的 task hang / 执行阶段结果丢失
                      // （COMP_STATUS_HUNG + ERR_DOMAIN_WATCHDOG_TIMEOUT /
                      // 执行阶段恢复失败的 ERR_DOMAIN_*）。host 见到即进永久
                      // hang 池。防御性兼容旧 TIMEOUT+ERR_DOMAIN_WATCHDOG_TIMEOUT。
    kCancelled,       // 被 Control 取消旗确认
    kWorkerSignaled,  // worker/kernel 报告异常（oops / watchdog 等；等价 v2 kWorkerSignaled）
    kChildAborted,    // child 被 program 行为终止（crash 信号），worker daemon 健在
    kHarnessFatal,    // execution domain could not be rebuilt; worker exits
    kHarnessRecovered,// 域重建成功（仅 infra 类原始原因 6/7/10/13；
                      // hang-evidence 8/9/12 重建成功也保持 kHang 进池）
    kInfraFault,      // 基础设施故障，**程序无罪**。error_code 细分：ERR_EXECUTOR_ERROR
                      // = worker 运行时故障；ERR_INVALID_INPUT = 配置/协议错（确定性，
                      // 重试无意义）
    kUnknown,         // 兜底：未知 wire status / 不该走到的分支。出现即 bug 信号
};

// DispatchOutcome — Poll 返回的单次完成
struct DispatchOutcome {
    uint32_t              worker_id = 0;
    uint32_t              proc_id = UINT32_MAX;
    uint64_t              executor_id = 0;
    uint32_t              dispatch_gen = 0;   // 用于与 Channel::generation_ 对比丢弃跨代
    DispatchOutcomeKind   kind = DispatchOutcomeKind::kOk;
    uint32_t              vendor_status = 0;  // wire 原始码（debug / telemetry，仅透传）
    uint32_t              vendor_flags = 0;   // wire RESULT flags（XiUOS: 每-program leak delta，透传）
    // [XiUOS leak 一等公民化 Phase 5] resource residue auto-measured by the worker
    // after each program's own cleanup, packed as
    // waitq_pending | (live_victim<<8) | (delay_nodes<<16) into the OK-status
    // RESULT trap_or_pc field. Parallel carrier to vendor_flags (heap delta);
    // 0 for non-XiUOS backends / old ELF. See docs/plans/xiuos-leak-componentization.md.
    uint32_t              vendor_resource_residue = 0;
    // [v3 Phase 4.4] worker-side diagnostics（Abnormal 通路透传）：
    //   - error_code：ErrorCode 枚举（ERR_OK / ERR_TIMEOUT / ERR_EXECUTOR_ERROR /
    //                 ERR_WORKER_CRASHED / ERR_PROGRAM_CHILD_CRASHED /
    //                 ERR_TASK_CANCELLED）
    //   - crash_signal：信号号（0=正常退出；>0 为 SIGxxx 原值）
    uint32_t              error_code = 0;
    uint32_t              crash_signal = 0;
    // [v3 call-level oracle v1] worker 侧 per-program 诊断:XiUOS 用作
    // last call 的 kernel return code(aux 字段),production wedge-only
    // 路径不读它,但 XiuosFuzzSession::RunOracleSelfTest 会消费用于
    // catch wedge-invisible 的 semantic bug(如 WorkSubmit_immediate
    // 漏 return 返垃圾值)。其他 backend 默认 0,无副作用。
    int32_t               vendor_aux = 0;
    uint64_t              worker_start_ts_us = 0;
    uint64_t              worker_done_ts_us = 0;
    // [RTT] host-clock instant the host observed the worker START this task,
    // stamped when the host drains the guest's start-ping marker
    // (TaskSlot.worker_started_executor_id). Carried up from the data plane and
    // copied into TaskTrace.worker_start_ack_host_ts_us by the channel (mirrors
    // worker_start_ts_us at channel.cpp:706). 0 = not sampled / not observed.
    uint64_t              worker_start_ack_host_ts_us = 0;
    // Host-side internal RTT split points. The ivshmem data plane stamps these
    // only for sampled tasks after validating the completion identity.
    uint64_t              completion_observed_host_ts_us = 0;
    uint64_t              output_copied_host_ts_us = 0;
    // True when worker_start/done_ts_us are read from the worker's own
    // monotonic clock (ivshmem guest); false when they are a host-side
    // NowMicros() approximation (XiUOS-UART). Propagated into
    // TaskTrace.worker_clock_is_guest_monotonic by the caller. Defaults true
    // to match the common ivshmem backend; XiUOS-UART sets this false.
    bool                   worker_clock_is_guest_monotonic = true;
    std::vector<uint8_t>  output;             // worker 侧写回的数据（payload 独立于 kind）
};

// InflightEntry — SnapshotInflight 单条记录
struct InflightEntry {
    uint32_t worker_id = 0;
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    bool     cancel_requested = false;
    uint64_t cancel_observed_seq = 0;
    // [crash-terminal] true = worker was actively EXECUTING this task at snapshot
    // time (TASK_TAKEN); false = task was placed in the slot but the worker had not
    // picked it up yet (TASK_READY) — it never ran. On a crash reclaim, running ones
    // are crash-suspects (→ kWorkerCrashed, terminal), not-yet-started ones are
    // innocent (→ kCancelled, re-run). Mirrors syzkaller runner.go executing[id] →
    // Crashed vs pending → Restarted. Default true so data planes that don't
    // distinguish keep the legacy "all → crashed" behavior.
    bool     was_running = true;
};

// IDataPlane — 数据面抽象
class IDataPlane {
public:
    virtual ~IDataPlane() = default;

    // ───── 生命周期 ─────
    //
    // 启动顺序契约（v3.G / doorbell 修复）：
    //   1. StartServer()  → 可能启动 host 端服务端点（如 ivshmem-doorbell 的 DoorbellServer）。
    //                        必须在 Substrate.StartVM() 之前调用；QEMU 启动时会立即尝试连。
    //                        对 plain / 不需要 server 的实现为 no-op，默认实现即 Ok。
    //   2. （外部）Substrate.StartVM()  → QEMU 作为 peer 0 连上 server。
    //   3. Prepare()       → host 作为 peer 1 反向连回 server，完成握手、建 mmap/eventfd/epoll。
    //
    // 对于 plain / 无 server 语义的实现，把全部逻辑放在 Prepare() 即可。
    virtual Result<void> StartServer() { return Result<void>::Ok(); }
    virtual Result<void> Prepare() = 0;   // 建立 wire / mmap / 监听 doorbell
    virtual void         Close() = 0;

    // ───── 暂停 / 恢复（recovery 期间由 Channel 编排） ─────
    virtual void Pause() = 0;
    virtual void Resume() = 0;

    // ───── Submit ─────
    struct SubmitInput {
        uint32_t                     worker_id = 0;
        uint32_t                     proc_id = UINT32_MAX;
        uint64_t                     executor_id = 0;
        uint32_t                     dispatch_gen = 0;
        std::chrono::microseconds    wait_for_slot{0};
        const uint8_t*               payload_data = nullptr;
        size_t                       payload_size = 0;
        // [v2 Epic 5 PR-5-B] TaskSlot.flags wire encoding (TASK_FLAG_*).
        // IvshmemDataPlane::Submit writes this verbatim into TaskSlot.flags.
        uint32_t                     exec_flags = 0;
    };

    virtual SubmitOutcome Submit(const SubmitInput& req) = 0;

    // ───── Poll ─────
    //
    // Poll：把 wire 上已完成的 dispatch 拉出来；返回语义级 DispatchOutcome 列表。
    // timeout=0 表示"非阻塞尽可能多拿"；timeout>0 表示"阻塞最多 N us，任何一条完成即返回"。
    // Poll 必须是 transport-neutral 的 blocking poll：
    //   - doorbell transport 应阻塞在 completion doorbell fd + host wake fd 上；
    //   - plain transport 没有 fd，也必须用短 sleep / cv / wake flag 给出有界延迟；
    //   - WakePoller() 必须能让正在阻塞的 Poll() 尽快返回，即使没有 completion。
    virtual void Poll(std::vector<DispatchOutcome>& out,
                      std::chrono::microseconds timeout) = 0;

    // WakePoller：host 侧事件（input 入队、health fault、close/recovery signal 等）用于
    // 打断正在阻塞的 Poll()。实现必须允许跨线程调用；没有阻塞 Poll 时可记一位 wake，
    // 让下一次 blocking Poll 立即返回。
    virtual void WakePoller() noexcept = 0;

    // ───── Reset（Recovery 执行层专用） ─────
    //
    // ResetWorker：清本 worker 所有 inflight 状态；不取消 wire level session
    //             （session 级 reset 由 IControlPlane 做）
    // ResetAll：清所有 worker 的 inflight
    virtual void ResetWorker(uint32_t worker_id) = 0;
    virtual void ResetAll() = 0;

    // ───── Inflight 盘点 ─────
    virtual std::vector<InflightEntry> SnapshotInflight() const = 0;

    // ───── 状态查询（Phase B 升级到接口） ─────
    virtual bool     IsPaused() const noexcept = 0;
    virtual bool     IsClosed() const noexcept = 0;
    virtual uint32_t MaxWorkerSlots() const noexcept = 0;

    // ───── 单点/总量可发查询（Phase B 升级到接口） ─────
    //
    // IsWorkerSendable(wid)：此刻向 wid 发是否会被 DP 接受。
    // CountSendableWorkers：默认实现循环 IsWorkerSendable，子类可重载做 O(1) 优化。
    virtual bool     IsWorkerSendable(uint32_t worker_id) const = 0;
    virtual uint32_t CountSendableWorkers() const {
        uint32_t cnt = 0;
        const uint32_t slots = MaxWorkerSlots();
        for (uint32_t w = 0; w < slots; ++w) {
            if (IsWorkerSendable(w)) ++cnt;
        }
        return cnt;
    }
};

} // namespace refuzz::channel::data
