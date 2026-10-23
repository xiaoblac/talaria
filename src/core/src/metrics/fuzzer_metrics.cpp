#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"

namespace refuzz::fuzzer::metrics {

namespace {

refuzz::core::metrics::Labels KindLabel(const char* kind)
{
    return {{"kind", kind}};
}

refuzz::core::metrics::Labels QueueLabel(const char* queue)
{
    return {{"queue", queue}};
}

} // namespace

void FuzzerMetrics::Bind(refuzz::core::metrics::MetricRegistry& r)
{
    generated_tasks = &r.CounterOf("fuzzer.generated_tasks");
    reexec_tasks    = &r.CounterOf("fuzzer.reexec_tasks");
    exec_collide    = &r.CounterOf("fuzzer.exec_collide");

    // [speed-compare arm D] real executed-syscall counter (see hpp).
    calls_executed                  = &r.CounterOf("fuzzer.calls.executed");

    results_completion              = &r.CounterOf("fuzzer.results", KindLabel("completion"));
    results_partial_completion      = &r.CounterOf("fuzzer.results", KindLabel("partial_completion"));
    results_program_timeout         = &r.CounterOf("fuzzer.results", KindLabel("program_timeout"));
    results_abnormal                = &r.CounterOf("fuzzer.results", KindLabel("abnormal"));
    results_fault                   = &r.CounterOf("fuzzer.results", KindLabel("fault"));
    results_interesting             = &r.CounterOf("fuzzer.results", KindLabel("interesting"));
    results_crash                   = &r.CounterOf("fuzzer.results", KindLabel("crash"));
    results_timeout                 = &r.CounterOf("fuzzer.results", KindLabel("timeout"));
    results_exec_error              = &r.CounterOf("fuzzer.results", KindLabel("exec_error"));
    results_harness_fatal           = &r.CounterOf("fuzzer.results", KindLabel("harness_fatal"));
    results_raw_timeout             = &r.CounterOf("fuzzer.results", KindLabel("raw_timeout"));
    results_worker_crash_error      = &r.CounterOf("fuzzer.results", KindLabel("worker_crash_error"));
    results_invalid_input_error     = &r.CounterOf("fuzzer.results", KindLabel("invalid_input_error"));
    results_output_too_large_error  = &r.CounterOf("fuzzer.results", KindLabel("output_too_large_error"));
    results_raw_executor_error      = &r.CounterOf("fuzzer.results", KindLabel("raw_executor_error"));
    results_coverage_empty          = &r.CounterOf("fuzzer.results", KindLabel("coverage_empty"));
    results_malformed_feedback      = &r.CounterOf("fuzzer.results", KindLabel("malformed_feedback"));

    cov_new_total = &r.CounterOf("fuzzer.cov.new_total");
    cov_unique    = &r.GaugeOf("fuzzer.cov.unique");
    cov_all_pc     = &r.GaugeOf("fuzzer.cov.all_pc");
    cov_corpus_pc  = &r.GaugeOf("fuzzer.cov.corpus_pc");
    cov_all_edge   = &r.GaugeOf("fuzzer.cov.all_edge");
    cov_corpus_edge = &r.GaugeOf("fuzzer.cov.corpus_edge");
    // [v2 Epic 5 PR-5-B] cmp dedupe counters — pre-reserved by PR-K-D, now active.
    cov_cmp_new_total = &r.CounterOf("fuzzer.cov.cmp.new_total");
    cov_cmp_unique    = &r.GaugeOf("fuzzer.cov.cmp.unique");
    // [Task A] corpus-admitted coverage counters (syz_corpus_cover analog).
    cov_corpus_new_total = &r.CounterOf("fuzzer.cov.corpus.new_total");
    cov_corpus_unique    = &r.GaugeOf("fuzzer.cov.corpus.unique");
    // [edge-over-time] corpus SIGNAL (edge) union size — reFuzz analog of syz
    // bench "signal" (len(corpus.signal), merged on admit). Distinct from
    // corpus.unique (PC union = syz "coverage"). Fed from
    // Compatibility alias of the corpus-edge measurement store.
    cov_corpus_signal_unique = &r.GaugeOf("fuzzer.cov.corpus.signal_unique");

    corpus_growth     = &r.CounterOf("fuzzer.corpus.growth");
    corpus_size       = &r.GaugeOf("fuzzer.corpus.size");
    // [coverage-ownership bound] owned-edges.
    corpus_owned_edges = &r.GaugeOf("fuzzer.corpus.owned_edges");
    // [v2 PR-K-E2] corpus 占用估算 Gauge,见 fuzzer_metrics.hpp 字段说明。
    corpus_bytes      = &r.GaugeOf("fuzzer.corpus.bytes");

    policy_switch_mutation = &r.CounterOf("fuzzer.policy_switch", KindLabel("mutation"));
    policy_switch_schedule = &r.CounterOf("fuzzer.policy_switch", KindLabel("schedule"));
    policy_switch_corpus   = &r.CounterOf("fuzzer.policy_switch", KindLabel("corpus"));

    inbox_drop_result = &r.CounterOf("fuzzer.inbox_drop", QueueLabel("result"));

    triage_admit_stable   = &r.CounterOf("fuzzer.triage", KindLabel("admit_stable"));
    triage_drop_flaky     = &r.CounterOf("fuzzer.triage", KindLabel("drop_flaky"));
    triage_completed      = &r.CounterOf("fuzzer.triage", KindLabel("completed"));
    triage_job = &r.GaugeOf("fuzzer.triage_job");

    minimize_completed           = &r.CounterOf("fuzzer.minimize", KindLabel("completed"));
    minimize_job      = &r.GaugeOf("fuzzer.minimize_job");

    smash_completed      = &r.CounterOf("fuzzer.smash", KindLabel("completed"));
    smash_job            = &r.GaugeOf("fuzzer.smash_job");

    hints_completed = &r.CounterOf("fuzzer.hints", KindLabel("completed"));
    hints_job       = &r.GaugeOf("fuzzer.hints_job");
    fault_job       = &r.GaugeOf("fuzzer.fault_job");

    triage_task_completed        = &r.CounterOf("fuzzer.triage",        KindLabel("task_completed"));
    minimize_task_completed      = &r.CounterOf("fuzzer.minimize",      KindLabel("task_completed"));
    hints_task_completed         = &r.CounterOf("fuzzer.hints",         KindLabel("task_completed"));
    fault_task_completed         = &r.CounterOf("fuzzer.fault_inject",  KindLabel("task_completed"));
    smash_task_completed         = &r.CounterOf("fuzzer.smash",         KindLabel("task_completed"));

    // [job-loop] job 异常 fail-soft 计数(见 hpp)。
    job_aborted                  = &r.CounterOf("fuzzer.job_aborted");

    // [v2 exectime split] 0 = fuzz phase 尚未起步;FuzzerLoop 首次 produce 时一次性 Set。
    fuzz_phase_started_us = &r.GaugeOf("fuzzer.fuzz_phase_started_us");
}

} // namespace refuzz::fuzzer::metrics
