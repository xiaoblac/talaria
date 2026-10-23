#pragma once
// Job-loop 重设计 Step 3 Slice C3 —— core-path job body。
//
// 把 triage(deflake + decide)与 minimize 融成**一条 job 栈**:
//   1. deflake:收集 min_runs 个总样本(若有 discovery，则它占 sample 0)，收 per-run
//      观测 + program signal；自适应扩展到 max_runs(未稳 & 上次是 completion 才再投，
//      镜像旧 triage consumer)，total_runs 是最终硬上限；
//   2. decide:extract_stable(= oracle k-of-n)判 stable;stable →
//      deflake::DecideAndStampStableSeed 盖章 + 出 per-call 候选;flaky → 直接 return;
//   3. minimize:逐候选 driver->RunInline(**不起 worker**,test_fn 内 ctx.exec)→ 收敛;
//   4. admit:ctx.retain 在 control 线程 AdmitMinimizedSeed(单一所有者;取消不执行)。
//
// MinimizeDriver 只走 RunInline(C1)→ **1 线程/job**,没有内部 worker。重逻辑
// 复用 deflake:: / AdmitMinimizedSeed, minimize 输入构造收在本 job 实现内。
// 见 docs/job-loop-redesign/040_step3_triage_migration.md。

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/control/stage/triage_deflake.hpp"    // deflake:: (analysis + decide)
#include "refuzz/control/stages/minimize_driver.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace refuzz::core::metrics { class Counter; class Gauge; }

namespace refuzz::control {

using PerCallCandidate = refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate;
using MinimizeAdmitFn =
    std::function<void(MinimizeDriver::StepVerdict&&, std::optional<PerCallCandidate>)>;
using StableAdmitFn =
    std::function<void(const refuzz::fuzzer::Seed&, bool /*dispatch_elaboration*/)>;

// Core-path job runtime copy of syzkaller triageJob.calls. This is deliberately
// job-local state, not seed/corpus metadata and not DiscoveryNewSignalMetadata.
struct CorePathChasedCall {
    int                          call_index = -1;
    std::vector<std::uint64_t>   new_signal_hashes;
    std::vector<std::uint8_t>    new_signal_prios;
    std::optional<std::int32_t>  errno_value;
    std::optional<std::uint32_t> syscall_id;
    bool                         signal_hashes_are_edges = false;
    std::size_t                  first_run_index = 0;
};

struct CorePathDiscoverySample {
    std::vector<std::uint64_t> signal_hashes;
    deflake::RunObservation    observation;
};

enum class DeflakeMode : std::uint8_t {
    kFuzz = 0,
    kBootCorpus,
};

// [Step 3 Slice D — 指标补全] core-path job 替代 triage+minimize 两 stage,因此必须自己
// 发那两个 stage 的全部计数(否则 flag-on 下这些指标恒 0 → 观测盲区)。指针取自
// deps.metrics(D3 填),job 线程直接 Inc/Add(Counter/Gauge 都是 lock-free atomic)。
//   triage 侧:每 deflake re-exec(task_completed)、判定完成(completed)、stable admit
//     (admit_stable +admitted_units)、flaky/空 drop(drop_flaky)、inflight gauge(+1/-1);
//   minimize 侧:每 minimize re-exec(task_completed)、inflight gauge(+1/-1)。
//   minimize_completed 由 AdmitMinimizedSeed 在 control 线程(retain)发,不在此重复。
struct CorePathMetrics {
    refuzz::core::metrics::Counter* triage_task_completed   = nullptr;
    refuzz::core::metrics::Counter* triage_completed        = nullptr;
    refuzz::core::metrics::Counter* triage_admit_stable     = nullptr;
    refuzz::core::metrics::Counter* triage_drop_flaky       = nullptr;
    refuzz::core::metrics::Gauge*   triage_job   = nullptr;
    refuzz::core::metrics::Counter* minimize_task_completed = nullptr;
    refuzz::core::metrics::Gauge*   minimize_job = nullptr;
};

// oracle 的 k-of-n stable 抽取(= IStabilityOracle::ExtractStable):program-level
// per_run_hashes(每 run 的 new_signal_hashes)+ k → stable hashes。生产:绑
// deps.stability_oracle;测试:注入简单 k-of-n lambda(不必造真 oracle)。
using ExtractStableFn = std::function<std::vector<std::uint64_t>(
    const std::vector<std::vector<std::uint64_t>>&, int /*min_votes*/)>;

struct CorePathJobConfig {
    int                          min_runs   = 3;   // minimum total samples, discovery included
    int                          max_runs   = 5;   // normal/boot no-growth total limit
    int                          total_runs = 5;   // hard total-sample limit (boot=20)
    int                          min_votes  = 3;   // k-of-n 的 k
    int                          attempts   = 3;   // minimize attempts
    refuzz::crash::MinimizeMode  mode       = refuzz::crash::MinimizeMode::kCallsOnly;
    std::uint32_t                timeout_ms = 0;
    bool                         seed_value_shadow_enabled = false;
    DeflakeMode                  deflake_mode = DeflakeMode::kFuzz;
    std::optional<CorePathDiscoverySample> discovery_sample;
    // [per-call novelty — syz job.calls seed] discovery-exec per-call newSignal that
    //   seeds the chased-call map; the deflake loop grows it per re-exec (= syz
    //   deflake→triageProgCall). Built by the catch-all from the discovery
    //   EngineOutput's per-call observation. Empty is logged by the runtime and
    //   dropped after deflake; there is no whole-program guilty-call fallback.
    std::vector<CorePathChasedCall> initial_calls;
    // syzkaller boot-corpus candidates carry ProgMinimized|ProgSmashed: after
    // deflake they enter corpus directly, without minimize and without enrich.
    bool                         skip_minimize       = false;
    bool                         dispatch_elaboration = true;
    StableAdmitFn                stable_admit;
    std::function<void()>        on_terminal;
    // [Step 5] 本 job continuation 打档:CandidateTriage(boot 语料 ①)/ Triage(现场 ③)。
    // spawn 点按 SeedSource::kBootCorpus 设。
    ::refuzz::queue::TaskTier    tier = ::refuzz::queue::TaskTier::Triage;
    // [Step 3 Slice D] stage-parity 计数句柄(D3 从 deps.metrics 填;测试可留空)。
    CorePathMetrics              metrics;
    // [Step 5b] 并发 fan-out:per-call minimize 每候选一个独立 child minimize job(= syz
    // triageJob 的 wg.Go(handleCall))。生产 wiring 必须提供 spawn_child;空值只给单测
    // 走 parent 串行 seam,不是 runtime 错误恢复路径。
    std::function<bool(job::JobFn)> spawn_child;
    // child 的 MinimizeDriver 工厂(每 child 独立 driver → 并发安全)。空 ⇒ 默认构造
    // (生产:真 driver,同 parent);测试注入 mock。
    std::function<std::shared_ptr<MinimizeDriver>()> make_child_driver;
};

// 造一条 core-path job(返回 JobFn 交给 JobScheduler::TrySpawn)。
//   - seed **共享可变**(shared_ptr<Seed>):job 会盖 triage 元数据(CorpusCoverage/
//     SeedStability/TriageStableSignal…),而 admit_fn 绑的 AdmitMinimizedSeed 读**同一份**
//     original_seed(继承 source/lineage/cover)—— 必须共享,否则 admit 看不到 job 的盖章。
//     job 线程盖章与 control 线程 admit 由 strict-alternation 隔开(不重叠 → 无 data race)。
//   - driver 只经 RunInline 在 job 线程跑;工厂/mock 注入。
//   - extract_stable 绑 oracle->ExtractStable;admit_fn 绑 AdmitMinimizedSeed
//     (捕获持久 deps + 同一 seed_sp)或测试 recorder → job body 不依赖 JobDeps。
job::JobFn MakeCorePathJob(
    std::shared_ptr<refuzz::fuzzer::Seed>  seed,
    std::shared_ptr<MinimizeDriver>        driver,
    ExtractStableFn                        extract_stable,
    MinimizeAdmitFn                        admit_fn,
    CorePathJobConfig                      config);

CorePathDiscoverySample MakeCorePathDiscoverySample(const job::ExecResult& result);

// [Step 5b] fan-out child:对 `candidates` 里的每个 per-call 候选做 minimize(自持独立
// driver + minimize_job gauge + 逐候选 retain-admit)。复用与 parent 串行段同一份
// MinimizeOneCandidate(不漂移)。fan-out 时每 child 收一个候选;传多个则串行处理。
job::JobFn MakeCorePathMinimizeJob(
    std::shared_ptr<refuzz::fuzzer::Seed> seed,
    MinimizeAdmitFn                       admit_fn,
    std::vector<PerCallCandidate>         candidates,
    CorePathJobConfig                     config);

} // namespace refuzz::control
