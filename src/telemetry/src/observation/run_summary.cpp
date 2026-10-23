#include "refuzz/telemetry/observation/run_summary.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace refuzz::telemetry {

namespace cm = core::metrics;

namespace {

double ElapsedSec(std::chrono::steady_clock::time_point start,
                  std::chrono::steady_clock::time_point now)
{
    return std::chrono::duration<double>(now - start).count();
}

} // namespace

int64_t CounterInSamples(const std::vector<cm::MetricRegistry::Sample>& samples,
                         std::string_view name,
                         const cm::Labels& labels)
{
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return s.value;
        }
    }
    return 0;
}

int64_t LookupComputedInt(
    const std::vector<std::pair<std::string, SummaryValue>>& prior,
    std::string_view key)
{
    for (const auto& [k, v] : prior) {
        if (k == key) return v.kind == SummaryValueKind::kInt ? v.i : static_cast<int64_t>(v.d);
    }
    return 0;
}

double LookupComputedDouble(
    const std::vector<std::pair<std::string, SummaryValue>>& prior,
    std::string_view key)
{
    for (const auto& [k, v] : prior) {
        if (k == key) return v.kind == SummaryValueKind::kDouble ? v.d : static_cast<double>(v.i);
    }
    return 0.0;
}

const char* SummaryRunModeName(SummaryRunMode mode)
{
    switch (mode) {
    case SummaryRunMode::kFuzzing: return "fuzzing";
    case SummaryRunMode::kReplay:  return "replay";
    }
    return "unknown";
}

const char* InvariantStatusName(RunSummaryInvariants::Status s)
{
    switch (s) {
    case RunSummaryInvariants::Status::kPending:  return "pending";
    case RunSummaryInvariants::Status::kOk:       return "ok";
    case RunSummaryInvariants::Status::kViolated: return "violated";
    case RunSummaryInvariants::Status::kDisabled: return "disabled";
    case RunSummaryInvariants::Status::kSkipped:  return "skipped";
    }
    return "unknown";
}

namespace {

using Sample   = cm::MetricRegistry::Sample;
using Samples  = std::vector<Sample>;
using Computed = std::vector<std::pair<std::string, SummaryValue>>;

// 简写器 —— 减少 schema table 里的 lambda 体积。
auto CounterExtract(const char* name) {
    return [name](const Samples& s, const Computed&, auto, auto) {
        return SummaryValue::Int(CounterInSamples(s, name));
    };
}

auto CounterKindExtract(const char* name, const char* kind) {
    return [name, kind](const Samples& s, const Computed&, auto, auto) {
        return SummaryValue::Int(CounterInSamples(s, name, {{"kind", kind}}));
    };
}

auto CounterLabelExtract(const char* name, const char* key, const char* val) {
    return [name, key, val](const Samples& s, const Computed&, auto, auto) {
        return SummaryValue::Int(CounterInSamples(s, name, {{key, val}}));
    };
}

auto CounterLabelsExtract(const char* name, cm::Labels labels) {
    labels = cm::NormalizeLabels(std::move(labels));
    return [name, labels = std::move(labels)](const Samples& s, const Computed&, auto, auto) {
        return SummaryValue::Int(CounterInSamples(s, name, labels));
    };
}

// [harness-fatal 语义修正] channel 终态 one-hot gauge 聚合：任意 channel 处于
// 指定 lifecycle state 即返回 1。用于 run 失败判据 —— 只有 channel 真正进入
// kFailed（recovery 策略预算耗尽裁决 kFailChannel）才算整轮失败；单次任务级
// harness_fatal 只是可恢复的 worker 故障，不再判 run 失败。
auto ChannelLifecycleAnyExtract(const char* state) {
    return [state](const Samples& s, const Computed&, auto, auto) {
        for (const auto& sample : s) {
            if (sample.name != "channel.lifecycle_state" || sample.value <= 0) {
                continue;
            }
            for (const auto& [k, v] : sample.labels) {
                if (k == "state" && v == state) {
                    return SummaryValue::Int(1);
                }
            }
        }
        return SummaryValue::Int(0);
    };
}

} // namespace

const std::vector<SummaryField>& RunSummarySchema()
{
    // Schema 硬编码。顺序 = 计算顺序(派生字段在其依赖之后)。
    // 与 020_naming_catalog.md + 040_run_summary_redesign.md §6.1 逐条对照 review。
    //
    // 速率类字段使用注意(新增 worker/channel 时尤其要看):
    //   - submit_rate_net 扣除 backoff_wait_s,反映的是"dispatcher 串行提交节奏",
    //     对 worker 数不敏感(worker 多 → backoff 少 → 分母自消)。
    //   - per_slot_rate 的 slot = channel,不是 channel 内部 worker。1 channel/N worker
    //     时 per_slot_rate = submit_rate_net。想要"每 worker 速率"需新发布 workers.total。
    //   - 要看并行带来的总吞吐提升,比较 tasks_submitted / exec_s 或 elapsed_ms。
    static const std::vector<SummaryField> kSchema = {
        // --- Fuzzer counters ---
        {"generated",          CounterExtract("fuzzer.generated_tasks")},
        // Existing-seed re-executions. The invariant `terminal <= generated +
        // reexec` uses this because generated only counts gen/mut new programs.
        {"reexec",             CounterExtract("fuzzer.reexec_tasks")},
        {"completion",         CounterKindExtract("fuzzer.results", "completion")},
        {"partial_completion", CounterKindExtract("fuzzer.results", "partial_completion")},
        {"abnormal",           CounterKindExtract("fuzzer.results", "abnormal")},
        {"fault",              CounterKindExtract("fuzzer.results", "fault")},
        {"interesting",        CounterKindExtract("fuzzer.results", "interesting")},
        {"crash",              CounterKindExtract("fuzzer.results", "crash")},
        {"timeout",            CounterKindExtract("fuzzer.results", "timeout")},
        {"exec_error",         CounterKindExtract("fuzzer.results", "exec_error")},
        {"harness_fatal",      CounterKindExtract("fuzzer.results", "harness_fatal")},
        {"channel_failed",     ChannelLifecycleAnyExtract("failed")},
        {"raw_timeout",        CounterKindExtract("fuzzer.results", "raw_timeout")},
        {"worker_crash",       CounterKindExtract("fuzzer.results", "worker_crash_error")},
        {"invalid_input",      CounterKindExtract("fuzzer.results", "invalid_input_error")},
        {"output_too_large",   CounterKindExtract("fuzzer.results", "output_too_large_error")},
        {"raw_executor_error", CounterKindExtract("fuzzer.results", "raw_executor_error")},
        {"coverage_empty",     CounterKindExtract("fuzzer.results", "coverage_empty")},
        {"malformed_feedback", CounterKindExtract("fuzzer.results", "malformed_feedback")},

        // --- Coverage / corpus ---
        {"new_cov",            CounterExtract("fuzzer.cov.new_total")},
        {"cov_unique",         [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Int(CounterInSamples(s, "fuzzer.cov.unique"));
        }},
        {"corpus_growth",      CounterExtract("fuzzer.corpus.growth")},
        {"corpus",             [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Int(CounterInSamples(s, "fuzzer.corpus.size"));
        }},
        // [v2 PR-K-E2] corpus_bytes:Gauge,反映 payload bytes 累积。
        // 用于诊断 RSS 大头是否来自 corpus 增长(配合 corpus_size 看每条平均字节数)。
        {"corpus_bytes",       [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Int(CounterInSamples(s, "fuzzer.corpus.bytes"));
        }},
        {"corpus_save_error",  CounterExtract("fuzzer.corpus.save_error")},
        // [coverage-ownership bound] 语料边界机制可观测量:evicted = 周期边-最小 sweep
        // 抛弃的 subsumed seed 数;owned_edges = 当前 corpus 覆盖的 distinct 稳定边数
        // (语料大小的内生上界)。
        {"corpus_evicted",     CounterExtract("fuzzer.corpus.evicted")},
        {"corpus_merge",       CounterExtract("fuzzer.corpus.merge")},
        {"corpus_owned_edges", [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Int(CounterInSamples(s, "fuzzer.corpus.owned_edges"));
        }},

        // [job 指标归 sink] triage/minimize/smash/hints/fault 等 job-maintained 指标改由
        //   fuzzer_stats_sink(stats.log,60s 周期 key=value)承接,不再进 run_summary。

        // --- Policy switches ---
        {"policy_sw_mut",      CounterLabelExtract("fuzzer.policy_switch", "kind", "mutation")},
        {"policy_sw_sched",    CounterLabelExtract("fuzzer.policy_switch", "kind", "schedule")},
        {"policy_sw_corpus",   CounterLabelExtract("fuzzer.policy_switch", "kind", "corpus")},

        // --- Inbox drops ---
        {"inbox_drop",         CounterLabelExtract("fuzzer.inbox_drop", "queue", "result")},
        {"crash_inbox_drop",   CounterLabelExtract("fuzzer.inbox_drop", "queue", "crash")},

        // --- Executor ---
        // events_forwarded: 从 channel 回传到 fuzzer 的事件总数(completion/abnormal/control 全算)
        {"events_forwarded",   CounterExtract("executor.events_forwarded")},
        // tasks_submitted: dispatcher submit_accepted 成功的累计次数(≠ 完成数,见 terminal)
        {"tasks_submitted",    CounterExtract("executor.tasks_submitted")},
        // backoff_wait_s: dispatcher 因通道 inflight 满而空转等待的累计时长。
        //   worker 越多→通道容量越大→backoff 越少;是判断"是不是被通道反压"的关键。
        {"backoff_wait_s",     [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Double(
                 static_cast<double>(CounterInSamples(s, "executor.dispatch.backoff_wait_us")) / 1'000'000.0);
        }},
        {"backoff_episodes",   CounterExtract("executor.dispatch.backoff_episodes")},
        // slot_count: 读 executor.channels.total gauge = dispatcher 当前注册的 channel 数。
        //   注意:是"channel 数",不是"channel 内部 worker 数"。一个 channel 内部有 N 个
        //   worker 并行时,这里仍然记 1。若需要"每 worker 速率",需另外发布 workers.total gauge。
        {"slot_count",         [](const Samples& s, const Computed&, auto, auto) {
             return SummaryValue::Int(CounterInSamples(s, "executor.channels.total"));
        }},

        // --- Derived (依赖先行字段,顺序不能调) ---
        // terminal: completion + abnormal,即 fuzzer 侧"已落地"的任务总数(含异常)。
        //   用于 coverage_empty_rate / timeout_rate 的分母。
        {"terminal",           [](const Samples&, const Computed& p, auto, auto) {
             return SummaryValue::Int(
                 LookupComputedInt(p, "completion") + LookupComputedInt(p, "abnormal"));
        }},
        // elapsed_ms / exec_s: 从 session_start 到当前 tick 的墙钟时长(steady_clock)。
        //   把它作为分母得到的是"总吞吐",能如实反映增加 worker 带来的速度提升。
        //   注意:elapsed_ms / exec_s 包含 Build 末段 + Start + executor 启动 + 等首个 task
        //        的全部 wall time。要看"纯 fuzz phase"请用 elapsed_fuzz_ms / exec_fuzz_s。
        {"elapsed_ms",         [](const Samples&, const Computed&, auto start, auto now) {
             return SummaryValue::Int(
                 std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count());
        }},
        {"exec_s",             [](const Samples&, const Computed&, auto start, auto now) {
             return SummaryValue::Double(ElapsedSec(start, now));
        }},
        // [v2 exectime split] fuzz_started_us:从 session_start 到 FuzzerLoop 首次
        //   producer 成功投出 task 的微秒偏移。0 = fuzz phase 还未起步(可能是 worker
        //   未就绪 / corpus 尚未 drain / generate stage 暂未触发)。FuzzerLoop 在
        //   首次 produce 成功后一次性 Set,后续不再覆盖。
        {"fuzz_started_us",    CounterExtract("fuzzer.fuzz_phase_started_us")},
        // elapsed_fuzz_ms / exec_fuzz_s: 从"首个 task 投出"到当前 tick 的 wall time。
        //   = elapsed_ms - fuzz_started_us/1000;fuzz_started_us=0 时输出 0。
        //   这是对照 syzkaller exectime 的口径(syzkaller 的 exectime 也只算 fuzz loop)。
        {"elapsed_fuzz_ms",    [](const Samples&, const Computed& p, auto, auto) {
             const int64_t fuzz_us  = LookupComputedInt(p, "fuzz_started_us");
             if (fuzz_us <= 0) return SummaryValue::Int(0);
             const int64_t elapsed  = LookupComputedInt(p, "elapsed_ms");
             const int64_t fuzz_ms  = fuzz_us / 1000;
             return SummaryValue::Int(elapsed > fuzz_ms ? elapsed - fuzz_ms : 0);
        }},
        {"exec_fuzz_s",        [](const Samples&, const Computed& p, auto, auto) {
             const int64_t fuzz_us = LookupComputedInt(p, "fuzz_started_us");
             if (fuzz_us <= 0) return SummaryValue::Double(0.0);
             const double  exec_s = LookupComputedDouble(p, "exec_s");
             const double  fuzz_s = static_cast<double>(fuzz_us) / 1'000'000.0;
             return SummaryValue::Double(exec_s > fuzz_s ? exec_s - fuzz_s : 0.0);
        }},
        // [v1 速率分母 = exec_s — ROLLBACK: 删 v2 块, 取消下面 v1 注释]
        // {"submit_rate_net",    [](const Samples&, const Computed& p, auto, auto) {
        //      const double tasks = static_cast<double>(LookupComputedInt(p, "tasks_submitted"));
        //      const double eff   = std::max(1.0, LookupComputedDouble(p, "exec_s") -
        //                                         LookupComputedDouble(p, "backoff_wait_s"));
        //      return SummaryValue::Double(tasks / eff);
        // }},
        // {"per_slot_rate",      [](const Samples&, const Computed& p, auto, auto) {
        //      const double slots = static_cast<double>(std::max<int64_t>(1, LookupComputedInt(p, "slot_count")));
        //      return SummaryValue::Double(LookupComputedDouble(p, "submit_rate_net") / slots);
        // }},
        // {"execs_per_sec",      [](const Samples&, const Computed& p, auto, auto) {
        //      const double secs = std::max(1.0, LookupComputedDouble(p, "exec_s"));
        //      return SummaryValue::Double(
        //          static_cast<double>(LookupComputedInt(p, "terminal")) / secs);
        // }},
        // {"new_cov_rate",       [](const Samples&, const Computed& p, auto, auto) {
        //      const double secs = std::max(1.0, LookupComputedDouble(p, "exec_s"));
        //      return SummaryValue::Double(
        //          static_cast<double>(LookupComputedInt(p, "new_cov")) / secs);
        // }},
        // [v2 exectime split — 当前版本] 速率分母切到 exec_fuzz_s,只算 fuzz phase。
        //   语义:对照 syzkaller exectime 口径——syzkaller 的速率统计也只算 fuzz loop 内。
        //   fuzz phase 未起步(fuzz_started_us == 0)时 exec_fuzz_s == 0,
        //   max(1, 0) = 1,但分子(terminal/tasks_submitted/new_cov)同时为 0,结果 = 0,符合"还没开始 fuzz"直觉。
        //   注意:backoff_wait_s 仍是 session_start 起的累计 counter;若 startup 期就有 dispatcher backoff
        //   (罕见,startup 期通常无 task 待 submit)会被双重扣除,可接受偏差。
        // submit_rate_net: tasks_submitted / max(1, exec_fuzz_s - backoff_wait_s)
        //   "非 backoff 期间的 submit 节奏",度量 dispatcher 串行提交开销(ivshmem 门铃 + 协议打包)。
        //   警告:对 worker 数基本不敏感——worker 增加→backoff 减少→分母几乎不变→速率看起来恒定。
        //   想看并行收益请对比 tasks_submitted / exec_fuzz_s。
        {"submit_rate_net",    [](const Samples&, const Computed& p, auto, auto) {
             const double tasks = static_cast<double>(LookupComputedInt(p, "tasks_submitted"));
             const double eff   = std::max(1.0, LookupComputedDouble(p, "exec_fuzz_s") -
                                                LookupComputedDouble(p, "backoff_wait_s"));
             return SummaryValue::Double(tasks / eff);
        }},
        // per_slot_rate: submit_rate_net / slot_count(=channel 数,不是 worker 数)。
        //   当前只有 1 个 channel 时 = submit_rate_net,不会除以 channel 内部的 worker 数。
        {"per_slot_rate",      [](const Samples&, const Computed& p, auto, auto) {
             const double slots = static_cast<double>(std::max<int64_t>(1, LookupComputedInt(p, "slot_count")));
             return SummaryValue::Double(LookupComputedDouble(p, "submit_rate_net") / slots);
        }},
        // execs_per_sec: 对齐 LibAFL `ClientStats::execs_per_sec` 的吞吐定义。
        //   分子 = terminal (completion + abnormal),即"已落地"的执行总数,对应
        //   LibAFL 的 executions(无论是否产生 interesting input,每次 exec 都计 1)。
        //   分母 = exec_fuzz_s (fuzz phase 起的墙钟秒数,剥离 startup 开销)。
        //   与 submit_rate_net 区别:submit_rate_net 扣了 backoff_wait_s,度量的是
        //   dispatcher 串行提交节奏,对 worker 数不敏感;execs_per_sec 用真实 fuzz 墙钟,
        //   随 worker 增加而线性上升,是衡量并行吞吐收益的字段。
        {"execs_per_sec",      [](const Samples&, const Computed& p, auto, auto) {
             const double secs = std::max(1.0, LookupComputedDouble(p, "exec_fuzz_s"));
             return SummaryValue::Double(
                 static_cast<double>(LookupComputedInt(p, "terminal")) / secs);
        }},
        {"new_cov_rate",       [](const Samples&, const Computed& p, auto, auto) {
             const double secs = std::max(1.0, LookupComputedDouble(p, "exec_fuzz_s"));
             return SummaryValue::Double(
                 static_cast<double>(LookupComputedInt(p, "new_cov")) / secs);
        }},
        {"coverage_empty_rate",[](const Samples&, const Computed& p, auto, auto) {
             const double denom = static_cast<double>(std::max<int64_t>(1, LookupComputedInt(p, "terminal")));
             return SummaryValue::Double(
                 static_cast<double>(LookupComputedInt(p, "coverage_empty")) / denom);
        }},
        {"timeout_rate",       [](const Samples&, const Computed& p, auto, auto) {
             const double denom = static_cast<double>(std::max<int64_t>(1, LookupComputedInt(p, "terminal")));
             return SummaryValue::Double(
                 static_cast<double>(LookupComputedInt(p, "timeout") +
                                     LookupComputedInt(p, "raw_timeout")) / denom);
        }},
    };
    return kSchema;
}

} // namespace refuzz::telemetry
