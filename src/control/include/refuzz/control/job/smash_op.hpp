#pragma once
// Job-loop 重设计 Step 4c —— smash 无栈定向 op(**不是** job)。
//
// `000 §5`:smash = ~N 个**独立**单次变体(互不依赖),塞进一条 job 栈 = "假串行",吃吞吐。
// 所以 smash 迁成 **无栈 op**:在触发点(4d:admit)直接 burst submit N 个变体 task,
// fire-and-forget,结果回 catch-all MutationalConsumer(**无 job、无结果路由**)。
//
// 与旧 SmashProducerStage 的差异:旧版跨 tick 每 tick 投 1 个(受 max_concurrent_seeds /
// skip_nth / producer-chain 公平限流);那套限流是 **producer-chain 产物**,job-loop 里
// producer chain 正在退休 → 直接 burst。变体生成 + task 构建逐字段不变(经 mutate 注入)。
//
// StageDeps-free:mutate / submit 经 seam 注入(同 fault/hints job 的 DI),可隔离单测。
// 触发点 4d 绑:mutate_fn = MutateTyped(+profile-gated bytes-only path + 严格 profile skip),
// submit_fn = 分配 exec_id + task_queue.Push(unrouted → TryClaim 落空 → catch-all)。

#include "refuzz/control/job/job_context.hpp"   // [Step 5] job::JobFn / JobContext / Request
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/queue/host_fuzz_task.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace refuzz::core::metrics { class Counter; class Gauge; }

namespace refuzz::control {

// 一个 smash 变体:typed artifact(artifact.valid())**或** raw payload bytes(profile-gated
// bytes-only path)二选一。mutate seam 产出;SubmitSmashVariants 据此填 task。
struct SmashVariant {
    refuzz::program::ProgramArtifact artifact;   // valid() ⟺ typed 路径
    std::vector<std::uint8_t>        payload;     // 非空 ⟺ profile-gated bytes-only path
};

// 产一个变体(= 旧 stage 的 MutateTyped / profile-gated bytes path / 严格 skip 决策,4d 绑)。
// nullopt = 本轮没产出有效变体(消耗一轮预算,同旧 stage 的 skip 路径)。
using SmashMutateFn = std::function<std::optional<SmashVariant>(const refuzz::fuzzer::Seed&)>;

// 投递一个已建好的变体 task(fire-and-forget → catch-all)。绑定期分配 exec_id + task_queue.Push。
// 返回 false = 队列 backpressure → 中断本 burst(不再投后续变体)。
using SmashSubmitTaskFn = std::function<bool(refuzz::queue::HostFuzzTask&&)>;

// Smash job/op 自己记录变体 completion、burst 完成和在飞 seed 数。
struct SmashOpMetrics {
    refuzz::core::metrics::Counter* smash_completed      = nullptr;  // 一个 seed 的 burst 正常跑完一次
    refuzz::core::metrics::Gauge*   smash_job            = nullptr;  // 当前 inflight smash job 数
    // 每个变体的 ctx.exec() completion 回来(非取消)+1 —— per-task 粒度,跟 smash_completed
    // (要等 N 轮全部正常跑完才 +1)分母不同,不能直接相除当命中率看。
    refuzz::core::metrics::Counter* smash_task_completed = nullptr;
};

struct SmashOpConfig {
    int             iterations = 25;   // 变体数(= 旧 SmashProducerStage::Config::iterations)
    std::uint32_t   timeout_ms = 0;
    SmashOpMetrics  metrics;
};

// burst submit 一个 seed 的 N 个 smash 变体。同步(无栈、无挂起);调用方(4d)在 admit 点
// (控制线程)调它。skip(mutate 返 nullopt)仍消耗一轮预算;submit 返 false → 中断 burst
// (不再投后续变体)。
void SubmitSmashVariants(const refuzz::fuzzer::Seed& seed,
                         std::uint64_t               seed_id,
                         const SmashMutateFn&        mutate,
                         const SmashSubmitTaskFn&    submit,
                         SmashOpConfig               config);

// [Step 5] arbiter 模型:smash 作为一条 job,镜像 syz smashJob.run() —— 每变体一次 `ctx.exec`
// (阻塞到真实 completion 回来才继续下一变体,不批量 emit)。取消 → unwind;abnormal completion
// → 停本 job 剩余轮次。变体生成(mutate seam)/ metrics 与 SubmitSmashVariants 同一份。非
// arbiter 仍走 SubmitSmashVariants 无栈 burst。
job::JobFn MakeSmashJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    std::uint64_t                               seed_id,
    SmashMutateFn                               mutate,
    SmashOpConfig                               config);

} // namespace refuzz::control
