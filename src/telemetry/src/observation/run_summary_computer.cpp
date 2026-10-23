#include "refuzz/telemetry/observation/run_summary_computer.hpp"

#include <algorithm>

namespace refuzz::telemetry {

namespace {

// [fixed request stream] Which run modes an invariant is meaningful in. An
// invariant that reads a counter which is STRUCTURALLY zero in some mode is
// not "a check that happens to pass/fail there" -- it is a check that does not
// apply there, and must not be evaluated. Encoding that per invariant keeps
// the decision next to the predicate it belongs to, instead of hiding a
// mode branch inside one predicate's body.
using ModeMask = uint8_t;
constexpr ModeMask kModeFuzzing = 1u << 0;
constexpr ModeMask kModeReplay  = 1u << 1;
constexpr ModeMask kModeAll     = kModeFuzzing | kModeReplay;

constexpr ModeMask MaskOf(SummaryRunMode mode) {
    return mode == SummaryRunMode::kReplay ? kModeReplay : kModeFuzzing;
}

struct Invariant {
    const char* id;
    ModeMask modes;
    // 返回 true 表示满足。入参是算好的 fields(按 schema 顺序);在这里用 LookupComputed* 取值。
    bool (*check)(const std::vector<std::pair<std::string, SummaryValue>>& f);
};

bool InvTerminalLeGenerated(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    // terminal = completion + abnormal,涵盖所有完成的 task 来源。generated 只数
    // gen/mut 新生 program,已有 seed 的重跑由 reexec_tasks 补齐。
    // 两个模式都成立:replay 下 generated 恒 0,右边退化成 reexec,而 replay 的
    // 每个 terminal 结果都来自 stream 里的一条 reexec task,不等式仍然是真约束。
    return LookupComputedInt(f, "terminal") <=
           LookupComputedInt(f, "generated") + LookupComputedInt(f, "reexec");
}

// 「这次 run 到底干活了没有」。两个模式下 work 进入流水线的入口不同,所以是两条
// 不同的表达式,而不是一条表达式加 mode 判断 —— 同名 id,任一模式下只有一条生效。
bool InvProgressNonzeroFuzzing(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    // ExploreJob 产 gen/mut program 是 fuzzing 模式的 work 入口。
    return LookupComputedInt(f, "generated") >= 1 && LookupComputedInt(f, "terminal") >= 1;
}

bool InvProgressNonzeroReplay(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    // replay 模式 orchestrator 置 suppress_default_producer=true,ExploreJob 根本
    // 不启动 → generated 结构性为 0;FixedInputProducerJob 喂进来的 request 记在
    // reexec。拿 generated 判 progress 在这里恒假,是错判不是发现问题。
    return LookupComputedInt(f, "reexec") >= 1 && LookupComputedInt(f, "terminal") >= 1;
}

bool InvBackoffWaitLeExec(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    return LookupComputedDouble(f, "backoff_wait_s") <= LookupComputedDouble(f, "exec_s") + 1.0;
}

bool InvExecRateNonNeg(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    return LookupComputedDouble(f, "submit_rate_net") >= 0.0;
}

bool InvChannelFailedZero(const std::vector<std::pair<std::string, SummaryValue>>& f) {
    // [harness-fatal 语义修正] 整轮失败只由 channel 真正进入 kFailed 判定
    // （recovery 策略预算耗尽后裁决 kFailChannel）。fuzzer.results{kind=harness_fatal}
    // 只是任务级 worker 故障计数，恢复成功后必须不计入 run 失败。
    return LookupComputedInt(f, "channel_failed") == 0;
}

const std::vector<Invariant>& InvariantList() {
    static const std::vector<Invariant> kList = {
        {"terminal_le_generated",   kModeAll,      &InvTerminalLeGenerated},
        {"progress_nonzero",        kModeFuzzing,  &InvProgressNonzeroFuzzing},
        {"progress_nonzero",        kModeReplay,   &InvProgressNonzeroReplay},
        {"backoff_wait_le_exec_s",  kModeAll,      &InvBackoffWaitLeExec},
        {"exec_rate_nonneg",        kModeAll,      &InvExecRateNonNeg},
        {"channel_failed_zero",     kModeAll,      &InvChannelFailedZero},
    };
    return kList;
}

} // namespace

RunSummary ComputeRunSummary(
    const std::vector<core::metrics::MetricRegistry::Sample>& samples,
    std::chrono::steady_clock::time_point session_start,
    std::chrono::steady_clock::time_point now,
    std::chrono::system_clock::time_point session_start_wall,
    std::chrono::system_clock::time_point now_wall,
    bool is_final,
    bool enable_invariants,
    SummaryRunMode run_mode)
{
    RunSummary summary;
    summary.snapshot_ts = now;
    summary.session_start_wall = session_start_wall;
    summary.snapshot_wall = now_wall;
    summary.is_final = is_final;
    summary.run_mode = run_mode;

    const auto& schema = RunSummarySchema();
    summary.fields.reserve(schema.size());
    for (const auto& field : schema) {
        const auto val = field.extract(samples, summary.fields, session_start, now);
        summary.fields.emplace_back(field.out_name, val);
    }

    if (samples.empty()) {
        summary.invariants.status = RunSummaryInvariants::Status::kSkipped;
        return summary;
    }
    if (!is_final) {
        summary.invariants.status = RunSummaryInvariants::Status::kPending;
        return summary;
    }
    if (!enable_invariants) {
        summary.invariants.status = RunSummaryInvariants::Status::kDisabled;
        return summary;
    }

    const ModeMask active_mode = MaskOf(run_mode);
    for (const auto& inv : InvariantList()) {
        if ((inv.modes & active_mode) == 0) {
            continue;   // 该模式下不适用:不评估,也不记 failure
        }
        if (!inv.check(summary.fields)) {
            summary.invariants.failures.emplace_back(inv.id);
        }
    }
    summary.invariants.status = summary.invariants.failures.empty()
        ? RunSummaryInvariants::Status::kOk
        : RunSummaryInvariants::Status::kViolated;
    return summary;
}

} // namespace refuzz::telemetry
