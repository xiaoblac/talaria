// Job-loop 重设计 Step 4a —— fault-inject job body 实现。见 fault_job.hpp。

#include "refuzz/control/job/fault_job.hpp"

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/mutator/linux/syz_v2/fault_inject/fault_inject_variant.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <typeinfo>
#include <utility>
#include <vector>

namespace refuzz::control {

namespace fi_alg = ::refuzz::mutator::linux::syz_v2::fault_inject;

namespace {

// RAII:任何退出路径(取消/停链/cap)都把 inflight-seeds gauge -1,与链入口 +1 配平。
struct GaugeGuard {
    refuzz::core::metrics::Gauge* g = nullptr;
    ~GaugeGuard() { if (g != nullptr) g->Add(-1); }
};

// base seed 的 typed Prog(artifact-first)。null → 无 typed IR,无法 mutate CallProps。
std::shared_ptr<const refuzz::program::syz::Prog>
ResolveBaseProg(const refuzz::fuzzer::Seed& seed)
{
    if (!seed.artifact || !seed.artifact->valid()) {
        return nullptr;
    }
    return seed.artifact->As<refuzz::program::syz::Prog>();
}

// (variant, base_seed) → job::Request(artifact-first + 序列化 payload)。等价
// fault_injection_stage.cpp::BuildFaultInjectTask,只是产出 job::Request(submit 边界
// 再把 artifact/payload/opts 拷进 HostFuzzTask)。返回 nullopt = variant 空 / 序列化失败 /
// artifact 构建失败(caller 停链)。variant 携带的 typed Prog 成为 artifact 的 typed_view →
// channeldispatcher 注册 inflight artifact(fault-induced crash 的 §3.10 反查靠它)。
std::optional<job::Request>
BuildFaultRequest(std::unique_ptr<refuzz::program::syz::Prog> variant_owner,
                  const refuzz::fuzzer::Seed&                 base_seed,
                  std::uint32_t                               timeout_ms)
{
    if (variant_owner == nullptr) {
        return std::nullopt;
    }
    if (!base_seed.artifact || !base_seed.artifact->valid()) {
        return std::nullopt;   // base 必须 artifact-first,variant 才能继承 format/target
    }

    auto bytes_or = refuzz::program::syz::serialize_for_exec(*variant_owner);
    if (!bytes_or.has_value() || bytes_or->empty()) {
        return std::nullopt;
    }

    auto canonical_bytes =
        std::make_shared<const std::vector<std::uint8_t>>(std::move(*bytes_or));
    std::shared_ptr<const refuzz::program::syz::Prog> typed_view = std::move(variant_owner);
    refuzz::program::ProgramArtifact variant_artifact =
        refuzz::program::ProgramArtifact::Build(
            base_seed.artifact->format(),
            base_seed.artifact->target(),
            std::shared_ptr<const void>(typed_view, typed_view.get()),
            typeid(refuzz::program::syz::Prog),
            canonical_bytes,
            nullptr);
    if (!variant_artifact.valid()) {
        return std::nullopt;
    }

    job::Request req;
    req.artifact = std::make_shared<const refuzz::program::ProgramArtifact>(
        std::move(variant_artifact));
    // artifact 与 payload 都填:artifact 进 inflight_artifacts_(§3.10 反查),payload 让
    // submit 边界跳过 re-materialize(与 artifact 的 canonical_bytes 共享底层存储)。
    req.payload         = *canonical_bytes;
    req.opts.timeout_ms = timeout_ms;
    req.opts.flags      = 0;   // 无 collect-comps,PC coverage 默认模式(同 BuildFaultInjectTask)
    req.tier            = refuzz::queue::TaskTier::Smash;   // [Step 5] enrich → syz smashQueue(④)
    req.completion_triage_policy =
        job::CompletionTriagePolicy::kSuppressCatchAllTriage;
    return req;
}

struct FaultRunState {
    std::shared_ptr<const refuzz::fuzzer::Seed> seed;
    FaultJobConfig                              config;

    void LogStop(const char* reason,
                 int         call_index,
                 int         nth,
                 std::size_t per_call_count = 0) const
    {
        refuzz::logging::HostLogger::Instance().Log(
            "control.fault_job",
            "fault_job_stop",
            {refuzz::logging::Field("reason", reason),
             refuzz::logging::Field("seed_id", seed ? seed->seed_id : 0),
             refuzz::logging::Field("call_index", call_index),
             refuzz::logging::Field("nth", nth),
             refuzz::logging::Field("per_call_count",
                                    static_cast<std::uint64_t>(per_call_count))});
    }

    void Run(job::JobContext& ctx)
    {
        const auto& m = config.metrics;

        if (m.fault_job != nullptr) m.fault_job->Add(1);
        GaugeGuard fault_inflight_guard{m.fault_job};

        auto base_prog = ResolveBaseProg(*seed);
        if (!base_prog || base_prog->calls().empty()) {
            LogStop("missing_typed_prog", config.call_index, 0);
            return;   // 无 typed prog / 空程序 → 空转退(不计 task/completed)
        }

        int call_index = config.call_index;
        if (call_index < 0 ||
            static_cast<std::size_t>(call_index) >= base_prog->calls().size()) {
            LogStop("invalid_call_index", call_index, 0, base_prog->calls().size());
            return;
        }

        const int max_nth = config.max_nth > 0 ? config.max_nth : 1;

        // 建 nth=1(同 producer):建不出 → 不开链、不计 task/completed(与 producer 早退一致)。
        std::optional<job::Request> req = BuildFaultRequest(
            fi_alg::MakeFaultInjectVariant(*base_prog, call_index, 1),
            *seed, config.timeout_ms);
        if (!req.has_value()) {
            LogStop("build_request_failed", call_index, 1);
            return;
        }

        for (int nth = 1; ; ++nth) {
            // reexec 计数由 loop build_task 按 tier 记(fault continuation→Smash→reexec_tasks)。
            job::ExecResult r = ctx.exec(std::move(*req));   // ← 挂起点
            if (r.cancelled) {
                return;   // 取消 unwind:guard 扣 gauge;**不**计 chain_completed(链被中止,非完成)
            }
            if (m.fault_task_completed != nullptr) m.fault_task_completed->Inc();

            if (r.hard_stop) {
                break;   // worker/channel 层面已拿不到结果(timeout/worker-crash/...)→ 停链
            }

            // 终止规则:
            //   有 per-call 观测 & call_index 位 fault_injected==0 → 注入点耗尽 → 停链;
            //   置位 → triggered++、继续;短/无观测 → log 后停链。
            if (static_cast<std::size_t>(call_index) < r.per_call.size()) {
                if (r.per_call[static_cast<std::size_t>(call_index)].fault_injected) {
                    // 注入点仍触发 → 继续 nth+1
                } else {
                    break;   // 耗尽 → 停链
                }
            } else {
                LogStop("missing_per_call_observation", call_index, nth, r.per_call.size());
                break;
            }

            if (nth >= max_nth) {
                break;   // cap(跑满 max_nth)→ 停链(同 consumer next_nth>kFaultInjectMaxNth)
            }

            // 建下一发 nth+1(同 consumer);建不出 → 停链(defensive:call_index 已验证)。
            req = BuildFaultRequest(
                fi_alg::MakeFaultInjectVariant(*base_prog, call_index, nth + 1),
                *seed, config.timeout_ms);
            if (!req.has_value()) {
                LogStop("build_request_failed", call_index, nth + 1);
                break;
            }
        }

    }
};

} // namespace

job::JobFn MakeFaultJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    FaultJobConfig                              config)
{
    auto st    = std::make_shared<FaultRunState>();
    st->seed   = std::move(seed);
    st->config = config;
    return [st](job::JobContext& ctx) { st->Run(ctx); };
}

} // namespace refuzz::control
