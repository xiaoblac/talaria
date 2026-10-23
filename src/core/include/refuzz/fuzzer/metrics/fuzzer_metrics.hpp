#pragma once

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"

namespace refuzz::core::metrics {
class MetricRegistry;
}

namespace refuzz::fuzzer::metrics {

// FuzzerLoop / dispatcher / CorpusManager 共用的 metric 句柄缓存。
//
// 契约:
//   - Bind(registry) 由 FuzzerLoop 构造期调用一次,所有指针在 registry 生命周期内稳定。
//   - 发布方只持有 FuzzerMetrics*,允许为 nullptr(v1→v2 迁移期 stats/metrics 独立判空)。
//   - 一个 FuzzerMetrics 实例对应一个 fuzzer 实例的全量 series,见 docs 020 §2.1。
//
// 命名取自 docs/telemetry-redesign/020_naming_catalog.md §2.1,新增 series 必须先改 020。
struct FuzzerMetrics {
    // fuzzer.generated_tasks
    refuzz::core::metrics::Counter* generated_tasks = nullptr;
    // fuzzer.reexec_tasks — 已有 seed 的重跑执行(deflake / minimize / smash /
    // fault chain 等)。
    // run_summary 用作 invariant `terminal <= generated + reexec`(否则 reexec
    // task 让 terminal 永远超出 generated)。
    refuzz::core::metrics::Counter* reexec_tasks = nullptr;

    // [collide 变换层] fuzzer.exec_collide —— collide_producer 每把一个 gen/mut 新程序
    // task 变换成 async 并发变体就 +1（对齐 syzkaller statExecCollide）。纯诊断:不改
    // produced_kind 记账（collide 变体仍归它来源的 gen/mut slot），只反映 collide 触发量。
    refuzz::core::metrics::Counter* exec_collide = nullptr;

    // [speed-compare arm D] fuzzer.calls.executed — actually-executed syscalls
    // (kCallFlagExecuted), summed per completion/abnormal result. Symmetric with
    // the B/C replayer's executed_syz_calls and syz's syz_exec_calls_total, so the
    // full fuzz loop can report REAL executed-syscalls/sec (panel exec_calls=),
    // not a programs×mean_calls estimate.
    refuzz::core::metrics::Counter* calls_executed = nullptr;

    // fuzzer.results{kind=...} — result counters,对齐 LoopStats 各 *_results 字段
    refuzz::core::metrics::Counter* results_completion = nullptr;
    refuzz::core::metrics::Counter* results_partial_completion = nullptr;
    // [两层语义] program watchdog 判的超时(CompletionKind::kTimeout)。这是
    // **Completion 侧**的终态:程序被 per-program 看门狗 SIGKILL,但已发布的 progress
    // 数据完整可信,覆盖照常计入。与下面的 results_timeout(= task hang)是两回事:
    //   results_program_timeout — 程序自己跑太久,worker 健在,数据有效
    //   results_timeout         — daemon watchdog 判的 task hang,拿不到结果
    refuzz::core::metrics::Counter* results_program_timeout = nullptr;
    refuzz::core::metrics::Counter* results_abnormal = nullptr;
    refuzz::core::metrics::Counter* results_fault = nullptr;
    refuzz::core::metrics::Counter* results_interesting = nullptr;
    refuzz::core::metrics::Counter* results_crash = nullptr;
    // task hang(daemon watchdog / host 判 worker 死)。见 results_program_timeout。
    refuzz::core::metrics::Counter* results_timeout = nullptr;
    refuzz::core::metrics::Counter* results_exec_error = nullptr;
    refuzz::core::metrics::Counter* results_harness_fatal = nullptr;
    refuzz::core::metrics::Counter* results_raw_timeout = nullptr;
    refuzz::core::metrics::Counter* results_worker_crash_error = nullptr;
    refuzz::core::metrics::Counter* results_invalid_input_error = nullptr;
    refuzz::core::metrics::Counter* results_output_too_large_error = nullptr;
    refuzz::core::metrics::Counter* results_raw_executor_error = nullptr;
    refuzz::core::metrics::Counter* results_coverage_empty = nullptr;
    refuzz::core::metrics::Counter* results_malformed_feedback = nullptr;

    // fuzzer.cov.*
    refuzz::core::metrics::Counter* cov_new_total = nullptr;
    refuzz::core::metrics::Gauge* cov_unique = nullptr;
    // Measurement-only distinct-set cardinalities. These do not replace the
    // max-signal gain metrics above: priority upgrades change cov_new_total but
    // never change these gauges.
    refuzz::core::metrics::Gauge* cov_all_pc = nullptr;
    refuzz::core::metrics::Gauge* cov_corpus_pc = nullptr;
    refuzz::core::metrics::Gauge* cov_all_edge = nullptr;
    refuzz::core::metrics::Gauge* cov_corpus_edge = nullptr;
    // [v2 Epic 5 PR-5-B] fuzzer.cov.cmp.* — KCOV_CMP comparison-record dedupe
    // counters. Mirror of fuzzer.cov.{new_total,unique} but on cmp truth-store.
    // Pre-reserved by PR-K-D in docs/telemetry-redesign/020_naming_catalog.md;
    // PR-5-B activates the publishers. Telemetry projector kcov_cmp series
    // binding (set in PR-K-D) auto-fills once these increment.
    refuzz::core::metrics::Counter* cov_cmp_new_total = nullptr;
    refuzz::core::metrics::Gauge*   cov_cmp_unique    = nullptr;
    // [Task A] fuzzer.cov.corpus.* — distinct PCs of programs ADMITTED to
    // the corpus (post triage+minimize). reFuzz analog of syz_corpus_cover.
    // Fed only at corpus admission, not on every execution like cov.unique.
    refuzz::core::metrics::Counter* cov_corpus_new_total = nullptr;
    refuzz::core::metrics::Gauge*   cov_corpus_unique    = nullptr;
    // [edge-over-time] fuzzer.cov.corpus.signal_unique — distinct EDGES (signal)
    // in the corpus union (cover_edges mode). reFuzz analog of syz bench
    // "signal" = len(corpus.signal). Fed from corpus_edge_feedback_store at admit.
    refuzz::core::metrics::Gauge*   cov_corpus_signal_unique = nullptr;

    // fuzzer.corpus.*
    refuzz::core::metrics::Counter* corpus_growth = nullptr;
    refuzz::core::metrics::Gauge* corpus_size = nullptr;
    // fuzzer.corpus.owned_edges — distinct stable edges the corpus collectively
    // covers (= the SignalOwnershipIndex size). The corpus's intrinsic size bound:
    // one best owner per edge, so corpus_size tracks this, not a fixed capacity.
    refuzz::core::metrics::Gauge* corpus_owned_edges = nullptr;
    // [v2 PR-K-E2 — 当前版本] corpus 内存占用估算(只算当前 seed.payload bytes,
    // 暂不计入 ProgramArtifact)。用于诊断 RSS 大头是否来自 corpus。
    // CorpusManager 从 boot-loaded store 同步一次,之后 admit/drop 增量维护;
    // minimize/eviction 后可下降,与 corpus_size 同步反映真实 corpus。
    refuzz::core::metrics::Gauge* corpus_bytes = nullptr;

    // fuzzer.policy_switch{kind=...}
    refuzz::core::metrics::Counter* policy_switch_mutation = nullptr;
    refuzz::core::metrics::Counter* policy_switch_schedule = nullptr;
    refuzz::core::metrics::Counter* policy_switch_corpus = nullptr;

    // fuzzer.inbox_drop{queue=...}
    refuzz::core::metrics::Counter* inbox_drop_result = nullptr;

    // Triage/core-path job 度量：
    //   - triage_admit_stable: deflake N 次后交集非空 → 进入 minimize/admit；
    //   - triage_drop_flaky:   deflake N 次后交集为空 → 丢弃 pending seed；
    //   - triage_completed:    triage job 最终 stable / flaky 判定完成 → +1；
    //   - triage_job: 当前 inflight triage job 数（Gauge —— 进出 +1/-1）。
    refuzz::core::metrics::Counter* triage_admit_stable = nullptr;
    refuzz::core::metrics::Counter* triage_drop_flaky = nullptr;
    refuzz::core::metrics::Counter* triage_completed = nullptr;
    refuzz::core::metrics::Gauge*   triage_job = nullptr;

    // Minimize job 度量：
    //   - minimize_completed: minimize verdict.done 一次 +1（含立即 minimal 跳过路径）；
    //   - minimize_job: 当前 inflight minimize job 数（Gauge —— 进出 +1/-1）。
    refuzz::core::metrics::Counter* minimize_completed         = nullptr;
    refuzz::core::metrics::Gauge*   minimize_job    = nullptr;

    // Smash job/op 度量：
    //   - smash_completed:      每个 seed 跑完 N 轮 +1。
    //   - smash_job:            当前 inflight smash job 数（Gauge —— 进出 +1/-1）。
    refuzz::core::metrics::Counter* smash_completed      = nullptr;
    refuzz::core::metrics::Gauge*   smash_job            = nullptr;

    // Hints job 度量：
    //   - hints_completed: hints job 前缀+尾部正常结束 +1；
    //   - hints_job:       当前 inflight hints job 数（Gauge —— 进出 +1/-1）。
    refuzz::core::metrics::Counter* hints_completed = nullptr;
    refuzz::core::metrics::Gauge*   hints_job       = nullptr;

    // Fault job 度量：
    //   - fault_job: 当前 inflight fault-injection job 数（Gauge —— 进出 +1/-1）。
    refuzz::core::metrics::Gauge*   fault_job       = nullptr;

    // [per-job task-completed] 统一口径:job 每收到一个属于自己的 task 结果(非取消)+1
    // (= 完成一个 executor 执行,per-TASK,不是 per-job/chain)。smash_task_completed 现在也
    // 遵循同一口径(逐变体 ctx.exec() completion +1,不再是提交成功时按变体数一次性 +N)。
    // fuzzer_stats_sink 按时间 dump。
    refuzz::core::metrics::Counter* triage_task_completed        = nullptr;
    refuzz::core::metrics::Counter* minimize_task_completed      = nullptr;
    refuzz::core::metrics::Counter* hints_task_completed         = nullptr;
    refuzz::core::metrics::Counter* fault_task_completed         = nullptr;
    refuzz::core::metrics::Counter* smash_task_completed         = nullptr;

    // [job-loop] fuzzer.job_aborted —— job 主体抛出未捕获异常、被 libaco 协程边界兜住
    // (fail-soft)的次数(control/src/job/job.cpp RunBody)。>0 = 有 job 逻辑 bug 被吞掉,
    // 需排查(异常被吞掉后 fuzz loop 继续,但可能留下半写共享状态)。
    refuzz::core::metrics::Counter* job_aborted = nullptr;

    // [v2 exectime split] fuzzer.fuzz_phase_started_us
    //   FuzzerLoop 第一次 producer 成功投出 task 时,一次性 Set 为
    //   (steady_clock::now() - session_start) 的微秒数。0 = 还未开始 fuzz phase。
    //   run_summary 用它派生 elapsed_fuzz_ms / exec_fuzz_s,
    //   把 Build/Start/QEMU 等启动开销从 exectime 里剥离。
    refuzz::core::metrics::Gauge*   fuzz_phase_started_us = nullptr;

    // 一次性绑定。重复调用会在 registry 内部返回相同引用,指针保持稳定。
    void Bind(refuzz::core::metrics::MetricRegistry& registry);
};

} // namespace refuzz::fuzzer::metrics
