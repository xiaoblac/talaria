#pragma once
// JobDeps —— job/loop 长寿命依赖聚合(迁自退役的 stage framework StageDeps)。
//
// FuzzerLoop 在 ctor 期组出 deps_,以引用传给 job 侧的共享面
// (AdmitMinimizedSeed / DispatchElaboration)。**不能长期持有 JobDeps&**,只能
// 在被调函数参数作用域内使用。
//
// 字段规则:engine 字段一律 const EngineHandle<T>&(保 policy 切换契约);
// next_executor_id / next_seed_id 为 uint64_t&(单线程顺序,非 atomic)。
//
// 相较旧 StageDeps 已去掉的死字段:feedback_handle / crash_pipeline / dispatcher /
// rng / high_watermark / next_job_id / pseudo_dispatch_telemetry / job_core_path
// (stage framework 退役后无 reader;loop 走自己的成员)。

#include <cstdint>
#include <functional>
#include <string>

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/control/job/job_context.hpp"
#include "refuzz/logging/host_logger.hpp"

// ── Forward declarations(避免拉入大量依赖;实际类型由消费者按需 include)──
namespace refuzz::fuzzer {
class IMutatorEngine;
class ISchedulerEngine;
class IStabilityOracle;
class IRetryPolicy;
class IPriorityCalculator;
class ISaturationFilter;
class ICorpusStore;
class CorpusManager;
class IFeedbackStore;
template <class T> class MutexInbox;
struct Seed;
}

namespace refuzz::queue {
class InMemoryTaskQueue;
}

namespace refuzz::fuzzer::metrics {
struct FuzzerMetrics;
}

namespace refuzz::control {

struct JobDeps {
    // ── Engine handles(必须走 handle,消费者在作用域内实时 .Get())──
    const refuzz::core::EngineHandle<refuzz::fuzzer::IMutatorEngine>&    mutator_handle;
    const refuzz::core::EngineHandle<refuzz::fuzzer::ISchedulerEngine>&  scheduler_handle;

    // ── Non-engine components(装配期固定)──
    refuzz::fuzzer::ICorpusStore&        corpus;
    refuzz::queue::InMemoryTaskQueue&    task_queue;
    refuzz::fuzzer::MutexInbox<refuzz::fuzzer::Seed>&  corpus_inbox;
    uint64_t&                                          next_seed_id;

    // ── Observability ──
    refuzz::logging::HostLogger&                logger;
    refuzz::fuzzer::metrics::FuzzerMetrics&     metrics;

    // ── Long-lived scalars / config ──
    uint64_t             exec_timeout_ms = 0;
    // corpus persistence root dir(empty=disable persist)。
    std::string          corpus_persist_dir = {};
    // profile-level capability(镜像 ProfileCapabilities.accept_bytes_only_fallback)。
    bool                 accept_bytes_only_fallback = false;
    // [seed-value signals shadow] gate shadow-only compute(off → 零开销)。
    bool                 seed_value_shadow_enabled = false;

    // ── 单调计数器(单线程顺序,无需 atomic)──
    uint64_t&            next_executor_id;

    // ── corpus 准入入口(nullptr = 未注入;真实 loop 注入 &corpus_manager_)──
    refuzz::fuzzer::CorpusManager*       corpus_admit        = nullptr;

    // ── Framework primitives(raw ptr,所有权在 AssembledBundle;nullptr = 未注入)──
    refuzz::fuzzer::IStabilityOracle*    stability_oracle    = nullptr;
    refuzz::fuzzer::IRetryPolicy*        retry_policy        = nullptr;
    // priority_calculator / saturation_filter / corpus_cover_store:当前经
    // SignalTraits::BuildContext 直接注入消费,此处保 canon 一致性(future 消费者)。
    refuzz::fuzzer::IPriorityCalculator* priority_calculator = nullptr;
    refuzz::fuzzer::ISaturationFilter*   saturation_filter   = nullptr;
    refuzz::fuzzer::IFeedbackStore*      corpus_cover_store  = nullptr;

    // ── 共享 job spawn seam + 运行时档位(loop ctor 恒开)──
    // FuzzerLoop owns the job runtime; JobScheduler is only the request-window
    // submit pump. Jobs/elaboration ask the loop to spawn more jobs through
    // this callback so scheduler internals do not leak into business logic.
    std::function<bool(job::JobFn)> spawn_job;
    bool                            job_elaborate = false;
    bool                            job_arbiter   = false;
};

} // namespace refuzz::control
