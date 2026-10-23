// Copyright 2026 reFuzz project author -------youngkk.
//
// IObservationBus + IObservationSink: 多 sink 总线。
//
// 引入位置 (R2)：替换原本"单 ICoverageCollector"的硬编码 + step_event_writer
// 全局函数,统一为"驱动发事件,sink 自行决策" 的总线模型。
//
// 适用范围：
//   - kernel family 当前两 sink: KcovSink, IvshmemStepEventSink
//   - 未来 family 直接挂新 sink: AflBitmapSink / LibfuzzerCovSink /
//     NumericDiffSink / StderrCaptureSink ...
//   - 不需要 cov 的 family 不挂 KcovSink → 完全消失,不付代价。
//
// 线程安全：
//   - Bus.Publish 在 child 主线程 (serial) 或 worker thread (threaded) 触发。
//     Bus 本身不持锁；具体 sink 必须自负责线程安全 (例如
//     IvshmemStepEventSink 仅在 ctor/Init 改全局指针,Publish 阶段不写
//     全局,实际 ring 写入由 step_event_writer.cpp 的 atomic 路径承担)。
//   - PackAllFeedback / SnapshotAllForCrash 仅在主线程或信号 handler 调用。
//
// Crash 路径：SnapshotAllForCrash 必须 async-signal-safe——不分配、不
// 取锁、不调 stdio。每个 sink 的实现要自己保证。

#pragma once

#include "worker/exec_mode.hpp"
#include "worker/runtime_failure.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::worker {

// [remote-kcov S1] forward decl — the per-program control seam for the extra
// remote KCOV buffer. Defined in observation/extra_kcov_control.hpp; the bus
// only needs the pointer type to expose FindExtraKcovControl().
class IExtraKcovControl;

enum class ObservationEvent : uint8_t {
    kTaskStart    = 0,   // child 收到一个新 task,准备执行
    kActionBefore = 1,   // 一条 syscall/action 即将执行 (R2 暂未使用 — 由全局 step writer 处理)
    kActionAfter  = 2,   // 一条 syscall/action 执行完毕 (R2 暂未使用)
    kSessionEnd   = 3,   // 一个 task 的所有 action 执行完毕
};

struct ObservationContext {
    uint32_t worker_id = 0;
    uint64_t executor_id = 0;
    uint32_t call_index = 0;          // for ActionBefore/After
    uint32_t completion_status = 0;   // for ActionAfter
    ExecMode exec_mode = {};          // task-level mode hint (KCOV uses this to skip threaded)
    // [v2 Epic 5 PR-5-B] task-level CollectComps flag (extracted from
    // TaskSlot.flags & TASK_FLAG_COLLECT_COMPS). KcovSink reads this on
    // kTaskStart and switches KCOV mode to KCOV_TRACE_CMP.
    bool     collect_comps = false;
};

class IObservationSink {
public:
    virtual ~IObservationSink() = default;

    virtual void ConfigureProcId(uint32_t /*proc_id*/) {}

    // Init 在 child fork 之后调用 (在 sandbox apply 之前)。
    // 返回 false 不致命：sink 自动降级为禁用。
    virtual bool Init() { return true; }

    // 事件分发：sink 可选地处理某些事件,其它事件忽略即可。
    virtual void OnEvent(ObservationEvent ev, const ObservationContext& ctx) = 0;

    // 任务结束后,把本 sink 收集的 feedback 帧追加到 out (offset=*inout_len)；
    // 更新 *inout_len。空间不足应 silently 丢弃 (打 log,不报错)。
    virtual void PackFeedback(uint8_t* out, uint32_t out_cap,
                              uint32_t* inout_len) = 0;

    // 崩溃信号 handler 调用：必须 async-signal-safe (不可分配/取锁/调 libc)。
    // 把当前可观测状态写到 out (从 offset 0 开始),返回总字节数。
    // 多个 sink 时由 Bus 协调 offset。
    virtual uint32_t SnapshotForCrash(uint8_t* out, uint32_t out_cap) const {
        (void)out;
        (void)out_cap;
        return 0;
    }

    // sink 在 child VA 里持有的 mmap 字节数 (RLIMIT_AS 计算输入)。
    virtual size_t BufferBytes() const { return 0; }

    // Child fd-table hygiene hook. Sinks that own child-internal fds move them
    // to >= *next_fd and append their final fd numbers to preserved_fds.
    // Non-fd sinks keep the default no-op.
    virtual bool RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds) {
        (void)next_fd;
        (void)preserved_fds;
        return true;
    }

    // [remote-kcov S1] Non-RTTI seam: a sink that owns an extra remote KCOV
    // buffer returns itself as IExtraKcovControl*; everyone else keeps the
    // default nullptr. ObservationBus::FindExtraKcovControl() scans for the
    // first non-null so loop_runtime can drive per-program reset/collect
    // without depending on the concrete KcovSink type (matches the codebase's
    // no-dynamic_cast convention).
    virtual IExtraKcovControl* AsExtraKcovControl() { return nullptr; }

    virtual RuntimeFailure RuntimeFailureState() const {
        return RuntimeFailure::kNone;
    }

    virtual const char* Name() const = 0;
};

class IObservationBus {
public:
    virtual ~IObservationBus() = default;

    virtual void ConfigureProcId(uint32_t /*proc_id*/) {}

    virtual void AddSink(std::unique_ptr<IObservationSink> sink) = 0;
    virtual bool InitAll() = 0;

    virtual void Publish(ObservationEvent ev, const ObservationContext& ctx) = 0;

    virtual void PackAllFeedback(uint8_t* out, uint32_t out_cap,
                                 uint32_t* inout_len) = 0;

    virtual uint32_t SnapshotAllForCrash(uint8_t* out, uint32_t out_cap) const = 0;

    virtual size_t TotalBufferBytes() const = 0;

    virtual bool RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds) = 0;

    virtual size_t SinkCount() const = 0;

    // [remote-kcov S1] First sink exposing an extra remote KCOV control, or
    // nullptr if none (serial / coverage-off / no KcovSink). loop_runtime uses
    // it to reset/collect the extra buffer at program boundaries.
    virtual IExtraKcovControl* FindExtraKcovControl() = 0;
    virtual RuntimeFailure RuntimeFailureState() const = 0;
};

// 默认实现：vector<unique_ptr<sink>> + 顺序广播。
class ObservationBus final : public IObservationBus {
public:
    void ConfigureProcId(uint32_t proc_id) override;
    void AddSink(std::unique_ptr<IObservationSink> sink) override;
    bool InitAll() override;
    void Publish(ObservationEvent ev, const ObservationContext& ctx) override;
    void PackAllFeedback(uint8_t* out, uint32_t out_cap, uint32_t* inout_len) override;
    uint32_t SnapshotAllForCrash(uint8_t* out, uint32_t out_cap) const override;
    size_t TotalBufferBytes() const override;
    bool RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds) override;
    size_t SinkCount() const override;
    IExtraKcovControl* FindExtraKcovControl() override;
    RuntimeFailure RuntimeFailureState() const override;

private:
    std::vector<std::unique_ptr<IObservationSink>> sinks_;
};

} // namespace refuzz::worker
