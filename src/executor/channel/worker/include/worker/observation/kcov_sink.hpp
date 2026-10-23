// Copyright 2026 reFuzz project author -------youngkk.
//
// KcovSink: 把已有的 KcovCollector 包装成 IObservationSink。
//
// R2 引入：替换 ChildExecuteTask 里硬编码的 ICoverageCollector 直拨。
// KcovCollector 仍是 Init/Begin/End/SnapshotFeedback 的实际承载者；
// sink 只是按事件驱动它。
//
// 行为:
//   - kTaskStart : 若 kcov 已 Enabled() 且 task 是 serial mode,Begin()
//                  (threaded mode 跳过——KCOV 是 per-thread 的,worker
//                   thread 未 open kcov fd)
//   - kSessionEnd: 若上一阶段 collecting_ 被置位,End() / EndAsCmp() 收尾
//   - PackFeedback : 只 emit CMP session records;普通 PC coverage 由
//                    KernelWireDriver 的 per-call SyzExecResult tail 返回
//   - SnapshotForCrash : 直接调 KcovCollector::SnapshotFeedback
//                        (async-signal-safe; 不分配)
//
// 普通 PC mode 不 emit task-end program-level KCOV packet,避免与 per-call
// coverage tail 重复。

#pragma once

#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/coverage/kcov_drain_sink.hpp"
#include "worker/coverage/remote_kcov_buffer.hpp"
#include "worker/observation/extra_kcov_control.hpp"
#include "worker/observation/observation_bus.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::worker {

// Match upstream syzkaller's delayed-KCOV mmap model: the executor may keep a
// small KCOV pool opened up front (kCoverOptimizedCount in executor.cc) and
// mmap only part of it before execution. That upstream limit is not permission
// to run coverage-required worker threads without KCOV: if a newly-created
// thread needs coverage but has no opened kcov fd, syzkaller exits with "out of
// opened kcov threads".
// [当前版本 kcov-pool-config] 这两个常量改成 *默认值*;profile/config 可覆盖,
// 让 ops 在低内存 VM (kcov_collector_count<8) 或 cold-VM 调优 (调大 premap)
// 时不重编 worker。
inline constexpr int kDefaultThreadedKcovCollectorCount = 8;
inline constexpr int kDefaultThreadedKcovPremapCount = 3;

// [v2 Epic 7 PR-1/PR-4] KcovSink 同时实现三个 pure-virtual interface:
//   - IObservationSink         : bus 上的 sink 契约 (OnEvent/PackFeedback/...)
//   - IKcovCollectorProvider   : driver 借 collector 做 per-call slicing
//   - IKcovDrainSink (Step 4)  : threaded path 下 driver 把 worker thread 的
//                                  drained CMP records 推回来供 PackFeedback emit
// 三接口都是 pure virtual,多继承 = interface composition,无菱形。
class KcovSink final : public IObservationSink,
                       public IKcovCollectorProvider,
                       public IKcovDrainSink,
                       public IExtraKcovControl {
public:

    // [v2 Epic 7 PR-4] thread_count 决定可用 threaded 基础设施。默认 1 时
    // 行为与 Step 1 完全一致(serial-only)。thread_count > 1 时 collector
    // pool 建到 min(thread_count, collector_count),且 threaded path 只预 mmap
    // 前 premap_count 个 collector,避免 N × 4 MiB KCOV mmap 进入 fork 模板。
    // KernelWireDriver 的 scheduler 只会把 coverage-required call 派给
    // 有 opened KCOV fd 的 slot;超过 collector_count 的并发需求按 syzkaller
    // 语义 fail,不会静默无 coverage 执行。
    // [当前版本 kcov-pool-config] collector_count / premap_count 默认 8 / 3
    // (跟 syzkaller upstream 一致),profile 可覆盖。collector_count==0 等价
    // "用默认 8";<=0 的值都被钳到默认,避免静默关掉 KCOV。
    // [remote-kcov S1] extra_instance is the per-(worker/proc) unique instance
    // used to build the COMMON handle for the extra remote KCOV buffer
    // (kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, extra_instance)). Mirrors
    // syzkaller's `procid + 1`. The extra buffer is only constructed when
    // threaded (thread_count > 1), matching the collector-pool setup — remote
    // coverage only matters once the program-child forks the pool threads that
    // inherit kcov_handle.
    explicit KcovSink(int thread_count = 1,
                      std::size_t kcov_entries = kDefaultKcovEntries,
                      int collector_count = kDefaultThreadedKcovCollectorCount,
                      int premap_count    = kDefaultThreadedKcovPremapCount,
                      uint32_t extra_instance = 1,
                      KcovChildMode child_mode =
                          KcovChildMode::kFreshPerProgram);

    bool Init() override;

    void ConfigureProcId(uint32_t proc_id) override;

    void OnEvent(ObservationEvent ev, const ObservationContext& ctx) override;

    void PackFeedback(uint8_t* out, uint32_t out_cap,
                      uint32_t* inout_len) override;

    uint32_t SnapshotForCrash(uint8_t* out, uint32_t out_cap) const override;

    size_t BufferBytes() const override;

    bool RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds) override;

    const char* Name() const override { return "kcov"; }
    RuntimeFailure RuntimeFailureState() const override {
        return runtime_failure_;
    }
    bool UsesAtForkReset() const { return atfork_registered_; }

    // 暴露给 main 用于诊断日志 (是否成功打开 /dev/kcov)。
    // [v2 Epic 7 PR-1] 改成读 collectors_[0] (Step 1 唯一 collector)。
    bool Enabled() const;
    refuzz::proto::FeedbackKind Kind() const;

    // [v2 Epic 7 PR-1] provider() 替换 mutable_collector():driver 改成依赖
    // IKcovCollectorProvider 小接口,sink 实现该接口并暴露 self 指针。模块
    // 边界:driver 仅看到 coverage/,不依赖 observation/ 具体类。
    IKcovCollectorProvider* provider() { return this; }

    // IKcovCollectorProvider 实现。Step 1: ThreadCount()==1, GetCollector(0)
    // 返 collectors_[0].get();其它 tid 返 nullptr。Threaded path:
    // ThreadCount() 是实际 KCOV 槽位数 min(thread_count, collector_count);
    // 可以小于 logical worker thread_count。
    KcovCollector* GetCollector(int tid) override;
    int ThreadCount() const override;

    // IKcovDrainSink 实现。serial path 不调用三个 method;threaded path 由
    // driver 在 task start (StartThreadedSession) + task end (per-thread
    // AppendThreadDrained) 调用。PC mode 的 per-call coverage 不通过这里 emit;
    // CurrentMode 返回 last_mode_(OnEvent 已设)。
    KcovMode CurrentMode() const override { return last_mode_; }
    void StartThreadedSession(KcovMode mode) override;
    void AppendThreadDrained(std::vector<uint64_t> entries) override;

    // [v2 Epic 7 PR-4] sink-side drain entry 给 driver borrow。镜像 provider()。
    IKcovDrainSink* drain_sink() { return this; }

    // [remote-kcov S2] IExtraKcovControl 实现。loop_runtime 通过
    // bus.FindExtraKcovControl() 拿到本 sink (作为 IExtraKcovControl*),在每条
    // program 边界(program-child fork 前)reset 第 2 个 (extra/remote) KCOV
    // buffer 的写游标。collect+emit 由 PackFeedback 在 program-child 完成。
    // extra_ 为 null (serial / coverage-off / Init 失败) 时 no-op。
    void ResetExtraProgram() override;

    // [remote-kcov R2] See IExtraKcovControl::SetProgramUsesRemoteCover. Set by
    // the program loop (framework) when the program contains a remote_cover
    // call; consumed by PackFeedback to force the async settle/re-drain loop.
    // Reset to false per program by ResetExtraProgram().
    void SetProgramUsesRemoteCover(bool uses) override {
        program_uses_remote_cover_ = uses;
    }

    // [remote-kcov S1] non-RTTI seam: expose self as IExtraKcovControl* so
    // ObservationBus::FindExtraKcovControl() can locate this sink.
    IExtraKcovControl* AsExtraKcovControl() override { return this; }

    // Legacy fresh mode resets collector mappings from a pthread_atfork child
    // handler. Production inherited mode does not register that handler.
    void OnChildPostFork();

    // Fresh mode deregisters from the atfork registry; inherited mode does not
    // touch the registry mutex.
    ~KcovSink() override;

private:
    // [v2 Epic 7 PR-1] vectorized collector pool。size=1 in serial;threaded
    // 下最多 collector_count(默认 8),且仅前 premap_count(默认 3) 预 mmap,
    // 与 syzkaller delayed-KCOV mmap 策略对齐。thread_count > collector_count
    // 时 driver 调度层负责拒绝超过 coverage slot 的执行需求。
    // unique_ptr 是因为
    // KcovCollector 非 copy/non-move (持 fd/mmap),裸值放 vector 会编译失败,
    // vector grow 时也要求 movable。unique_ptr 让对象地址稳定 — driver
    // 借的 raw ptr 在 sink 生命周期内一直有效。
    std::vector<std::unique_ptr<KcovCollector>> collectors_;

    // [remote-kcov S1] second /dev/kcov buffer enabled via KCOV_REMOTE_ENABLE
    // with a COMMON handle. Captures async/softirq/kthread coverage that the
    // per-task local collectors miss. Only constructed when threaded (its
    // value is otherwise null and every forward is a no-op). Enabled in Init()
    // (= loop_child, before program-child fork) so the whole forked tree
    // inherits the kcov_handle. Reset/collected per program by loop_runtime via
    // IExtraKcovControl.
    std::unique_ptr<RemoteKcovBuffer> extra_;
    uint32_t extra_instance_ = 1;
    bool threaded_ = false;
    KcovChildMode child_mode_ = KcovChildMode::kFreshPerProgram;
    RuntimeFailure runtime_failure_ = RuntimeFailure::kNone;
    bool atfork_registered_ = false;

    // [remote-kcov R2] Per-program: does the current program contain a
    // remote_cover call (async coverage that lands after the syscall returns)?
    // Set via SetProgramUsesRemoteCover, cleared per program by
    // ResetExtraProgram, read by PackFeedback to force the settle/re-drain loop
    // even when the first drain is empty. Default false = legacy dynamic gate.
    bool program_uses_remote_cover_ = false;

    std::vector<uint64_t> last_session_entries_;
    bool collecting_ = false;
    // [v2 Epic 5 PR-5-B] mode chosen at kTaskStart; consumed by kSessionEnd
    // (End vs EndAsCmp) and PackFeedback (CMP only). Default kPc matches v1
    // task-start behavior;PC output is per-call, not program-level.
    // [v2 Epic 7 PR-4] threaded path 通过 StartThreadedSession 写 last_mode_,
    // 同时 last_session_entries_ 由 AppendThreadDrained 累积。CMP 路径共享
    // 同一 packet emission 出口 (PackFeedback)。
    KcovMode last_mode_ = KcovMode::kPc;
};

} // namespace refuzz::worker
