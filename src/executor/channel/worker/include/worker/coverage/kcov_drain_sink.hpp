// Copyright 2026 reFuzz project author -------youngkk.
//
// IKcovDrainSink: coverage-layer sink-side interface for the threaded
// KCOV path. driver 在 task end 把每个 worker thread 的 drained CMP records
// 推给 sink,sink 合并并在 PackFeedback 时 emit 一个 CMP packet。PC coverage
// 走 per-call SyzExecResult tail,不再由 sink emit program-level packet。
//
// 为什么需要这个接口(对偶于 IKcovCollectorProvider):
//   - serial path (Step 1): sink 主动调 collector.End/EndAsCmp;CMP records
//     存在 sink 自身 last_session_entries_,PackFeedback emit。
//   - threaded path (Step 4): KCOV lifecycle (Begin/Reset/Collect/End)
//     必须在 KCOV_ENABLE 它的 worker thread 上下文调用(Linux kernel 把
//     KCOV 绑在 current task)。所以 worker thread 自己 End → drained 缓存
//     在 thread struct;main thread 在 task end 把每 thread drained 推给
//     sink。CMP mode 下 sink 仍然是 packet emission 的 owner;PC mode 下
//     End() 只负责 disable,per-call coverage 已经在 syscall 完成后返回。
//
// 模块边界(per memory feedback "适配架构三层"):
//   - driver/ (KernelThreadPool, KernelWireDriver) 持 IKcovDrainSink* borrow
//   - observation/ (KcovSink) 实现 IKcovDrainSink
//   - 两侧通过本接口握手,不互相 #include 具体类。
//
// 调用契约:
//   driver task start (threaded only):
//     drain_sink->StartThreadedSession(mode);   // 锁定 mode,清空累积器
//   driver task end (threaded only,for each used thread):
//     drain_sink->AppendThreadDrained(std::move(thread_drained));
//   sink::PackFeedback:
//     CMP mode iterate last_session_entries_(同 serial path 路径)emit packet;
//     PC mode no-op。
//
// 线程安全:所有 method 仅在 main thread 调用(driver Execute 是 single-
// threaded entry,worker thread 通过 thread pool 中转,不直接 call sink)。
// 实现可以无锁。

#pragma once

#include "worker/coverage/kcov_collector.hpp"  // KcovMode

#include <cstdint>
#include <vector>

namespace refuzz::worker {

class IKcovDrainSink {
public:
    virtual ~IKcovDrainSink() = default;

    // 当前 task 的 KCOV mode。sink 在 OnEvent(kTaskStart) 已根据
    // ctx.collect_comps 设好(serial / threaded 都通过同一路径);driver 在
    // Execute(threaded path)需要读它来选择 pool->StartTask(mode) 和
    // worker thread Begin(mode)。
    virtual KcovMode CurrentMode() const = 0;

    // 开启一个 threaded-mode session;reset 内部累积器,锁定 mode (PC vs CMP)。
    // PackFeedback 只对 CMP mode append records;PC mode coverage 已由
    // per-call tail 承载。
    // 同一 task 只能 call 一次;serial path 不调用此接口。
    virtual void StartThreadedSession(KcovMode mode) = 0;

    // 把一个 worker thread 的 drained payload 追加到累积器。`entries` 按 mode
    // 的 layout:
    //   PC : 每个 uint64 是一个 PC
    //   CMP: 4 × uint64 / record (type, arg1, arg2, pc)
    // 当前语义:PC entries 不会被 PackFeedback emit;CMP records 合并成单
    // packet(host 端 dedup 自然处理)。若后续需要 per-thread 区分(eg.
    // attribution),再扩接口加 tid 参数。
    virtual void AppendThreadDrained(std::vector<uint64_t> entries) = 0;

    // [remote-kcov R2 pass-through] The threaded driver calls this when the
    // program contains a call with the syz `remote_cover` attribute (USB
    // connect/enumeration, 80211 inject, usbip) — i.e. a call whose coverage
    // lands ASYNC in a kthread/softirq (khubd hub_event, RX softirq) AFTER the
    // syscall returns. The extra-remote-KCOV settle loop only runs when this is
    // set (or the first drain already shows remote PCs), so without this the
    // async USB enumeration / class-driver coverage is silently lost (first
    // drain is empty → loop skipped). Default no-op: sinks without an extra
    // remote-KCOV buffer ignore it. KcovSink forwards to its
    // IExtraKcovControl::SetProgramUsesRemoteCover (same signature → one
    // override satisfies both interfaces).
    virtual void SetProgramUsesRemoteCover(bool /*uses*/) {}
};

}  // namespace refuzz::worker
