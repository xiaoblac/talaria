#include "refuzz/telemetry/observation/run_state_renderer.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/channel_contract.hpp"  // WorkerSlotState（worker 行渲染）

#include <cstdint>
#include <cstdio>
#include <iomanip>  // [v2 G5 follow-up] std::fixed / std::setprecision for exec/s line
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace refuzz::telemetry {
using refuzz::core::RuntimeEvent;
using refuzz::core::RuntimeSnapshot;
using refuzz::core::metrics::Labels;
using refuzz::core::channel_contract::WorkerSlotState;
using SampleMap = RunStateStore::SampleMap;

namespace {

const char* EventKindName(RuntimeEvent::Kind kind)
{
    switch (kind) {
    case RuntimeEvent::Kind::kFault:
        return "fault";
    case RuntimeEvent::Kind::kRecoveryBegin:
        return "recovery_begin";
    case RuntimeEvent::Kind::kRecoveryComplete:
        return "recovery_complete";
    case RuntimeEvent::Kind::kPolicySwitch:
        return "policy_switch";
    case RuntimeEvent::Kind::kChannelStateChange:
        return "channel_state_change";
    }
    return "unknown";
}

std::string Shorten(std::string_view value, size_t max_len)
{
    if (value.size() <= max_len) {
        return std::string(value);
    }
    if (max_len <= 3) {
        return std::string(value.substr(0, max_len));
    }
    std::string out(value.substr(0, max_len - 3));
    out += "...";
    return out;
}

void AppendEventField(std::ostringstream& out,
                      const char* key,
                      const std::string& value,
                      size_t max_len = 96)
{
    if (value.empty()) {
        return;
    }
    out << ' ' << key << '=' << Shorten(value, max_len);
}

// 从 samples map 查 counter 值;找不到返回 0。
//
// 必须先 NormalizeLabels:注册侧(MetricRegistry::GaugeOf/CounterOf)会把 label 按 key
// 排序后入 key,而这里是精确 find —— 调用方按语义顺序写的 {channel_id, worker_id, state}
// 与存进去的 {channel_id, state, worker_id} 不是同一个 key,会静默查不中返回 0。
// 历史调用方碰巧都是有序的所以没暴露;新增 worker 行时踩中了。
uint64_t CounterValue(const SampleMap& samples,
                      std::string_view name,
                      Labels labels = {})
{
    const auto it = samples.find(
        std::make_pair(std::string(name),
                       refuzz::core::metrics::NormalizeLabels(std::move(labels))));
    if (it == samples.end()) {
        return 0;
    }
    return static_cast<uint64_t>(it->second.value);
}

// 从 samples 里找所有出现过的 channel_id (任一 channel.* series 的 label)。
// 返回 sorted, dedup。
std::vector<uint32_t> GatherChannelIds(const SampleMap& samples)
{
    std::set<uint32_t> ids;
    for (const auto& [key, sample] : samples) {
        const auto& [name, labels] = key;
        if (name.compare(0, 8, "channel.") != 0) continue;
        for (const auto& [k, v] : labels) {
            if (k == "channel_id") {
                try {
                    ids.insert(static_cast<uint32_t>(std::stoul(v)));
                } catch (...) {}
                break;
            }
        }
    }
    return {ids.begin(), ids.end()};  // sorted
}

// 从 one-hot lifecycle_state 反查当前 state name。
// 找不到 value==1 的条目时返回 "unknown"。
std::string LookupLifecycleState(const SampleMap& samples, uint32_t channel_id)
{
    // 7 个状态名，与 channel_metrics.cpp Bind() 里 kLifecycleNames 完全一致
    static const char* kStates[] = {
        "stopped", "booting", "running", "degraded", "recovering", "failed", "closed"
    };
    const std::string cid = std::to_string(channel_id);
    for (const char* state : kStates) {
        const Labels lbl = {{"channel_id", cid}, {"state", state}};
        const auto it = samples.find(std::make_pair(std::string("channel.lifecycle_state"), lbl));
        if (it != samples.end() && it->second.value >= 1) {
            return state;
        }
    }
    return "unknown";
}

// [v2 6b-2 — 当前版本] 从 one-hot fuzzer.current_policy{kind=X, name=Y} 反查当前 policy name。
// kind ∈ {"mutation", "schedule", "corpus"}。未找到返回空字符串 ""。
std::string LookupCurrentPolicy(const SampleMap& samples, std::string_view kind)
{
    const std::string kind_str(kind);
    for (const auto& [key, sample] : samples) {
        const auto& [metric_name, labels] = key;
        if (metric_name != "fuzzer.current_policy") continue;
        std::string_view found_kind;
        std::string_view found_name;
        for (const auto& [k, v] : labels) {
            if (k == "kind") found_kind = v;
            else if (k == "name") found_name = v;
        }
        if (found_kind == kind_str && sample.value >= 1) {
            return std::string(found_name);
        }
    }
    return {};
}

// [v2 PR-K-B] Sparkline ramp: 8 levels from sparse to dense. Index 0 ('.')
// = empty / zero; index 7 ('#') = max-delta in window. Per plan §6.1 D-3.
constexpr const char* kSparkRamp = "._:-=+*#";

// [v2 PR-K-B] Render a sparkline string from a coverage history snapshot
// (oldest-first per CoverageSeriesBuffer::Snapshot contract). All-zero-delta
// window → all level-0 chars; otherwise each delta is mapped linearly to
// 0..7 by max_delta_in_window. Negative deltas (theoretical safety) clamp
// to level 0.
std::string RenderSparkline(const std::vector<CoverageSamplePoint>& history)
{
    if (history.empty()) {
        return {};
    }
    int64_t max_delta = 0;
    for (const auto& p : history) {
        if (p.value_delta > max_delta) {
            max_delta = p.value_delta;
        }
    }
    std::string out;
    out.reserve(history.size());
    for (const auto& p : history) {
        if (max_delta <= 0) {
            out += kSparkRamp[0];
            continue;
        }
        int64_t level = (p.value_delta * 7) / max_delta;
        if (level < 0) level = 0;
        if (level > 7) level = 7;
        out += kSparkRamp[level];
    }
    return out;
}

// 遍历 worker_liveness 样本聚合 alive_count 和 total_workers。
struct WorkerLivenessSummary { uint32_t alive = 0; uint32_t total = 0; };

WorkerLivenessSummary SummarizeWorkerLiveness(const SampleMap& samples,
                                              uint32_t channel_id)
{
    const std::string cid = std::to_string(channel_id);
    std::set<std::string> workers_seen;
    uint32_t alive = 0;
    for (const auto& [key, sample] : samples) {
        const auto& [name, labels] = key;
        if (name != "channel.health.worker_liveness") continue;
        std::string_view found_cid, state, worker_id;
        for (const auto& [k, v] : labels) {
            if (k == "channel_id") found_cid = v;
            else if (k == "state") state = v;
            else if (k == "worker_id") worker_id = v;
        }
        if (found_cid != cid) continue;
        workers_seen.insert(std::string(worker_id));
        if (state == "alive" && sample.value >= 1) ++alive;
    }
    return {alive, static_cast<uint32_t>(workers_seen.size())};
}

// 收集本 channel 上所有 worker 的 id（升序），供逐行渲染。
std::vector<uint32_t> GatherWorkerIds(const SampleMap& samples, uint32_t channel_id)
{
    const std::string cid = std::to_string(channel_id);
    std::set<uint32_t> ids;
    for (const auto& [key, sample] : samples) {
        const auto& [name, labels] = key;
        if (name != "channel.health.worker_liveness") continue;
        std::string_view found_cid, worker_id;
        for (const auto& [k, v] : labels) {
            if (k == "channel_id") found_cid = v;
            else if (k == "worker_id") worker_id = v;
        }
        if (found_cid != cid || worker_id.empty()) continue;
        ids.insert(static_cast<uint32_t>(std::stoul(std::string(worker_id))));
    }
    return {ids.begin(), ids.end()};
}

const char* SlotName(int64_t slot)
{
    // 与 WorkerSlotState 对齐（gauge 里存的是它的整数值）。
    switch (static_cast<WorkerSlotState>(slot)) {
    case WorkerSlotState::kEmpty:      return "empty";
    case WorkerSlotState::kDispatched: return "dispatched";
    case WorkerSlotState::kExecuting:  return "executing";
    case WorkerSlotState::kUnknown:    break;
    }
    return "unknown";
}

// worker 的展示态。**stall 不是状态，是时长** —— 判死要等满 silent_budget_s（300s），
// 只报 alive/dead 的话面板上就是"299s 一直 alive，然后啪一下 dead"，没有过程。
// 这里把连续量翻成一个单调、不跳变的进程：running → stalling(1s) → … → dead。
//
// recovering 单独成态：daemon 只要活着，程序 hang 到点必然去轮换 domain（proc_epoch +1）。
// 所以"静默但 epoch 在涨"= 它活着、正在自救、卡的是**被测程序**（合法，最长 65s）；
// "静默且 epoch 冻着" = 连自救都没做 = 卡的是 **daemon 自己**。两者处置完全不同，
// 没有这个区分，"静默 60s"根本无法解读。
const char* WorkerStateName(bool alive, uint64_t silent_s, bool recovering,
                            int64_t slot)
{
    if (!alive) return "dead";
    if (recovering) return "recovering";
    if (silent_s > 0) return "stalling";
    if (static_cast<WorkerSlotState>(slot) == WorkerSlotState::kEmpty) return "idle";
    return "running";
}

} // namespace

std::string RenderRuntimePanel(const RuntimeSnapshot& snapshot,
                               const SampleMap& metric_samples,
                               const std::vector<RuntimeEvent>& recent_events,
                               std::string_view tag)
{
    std::ostringstream out;
    const std::string prefix = tag.empty() ? std::string() : ("[" + std::string(tag) + "] ");

    if (snapshot.ts_us == 0) {
        out << prefix << "observability_snapshot=unavailable\n";
        return out.str();
    }

    // [6b-3 — 当前版本] RuntimeSnapshot.executor 已删除, channel 数量直接从 metric_samples 读
    out << prefix
        << "snapshot ts_us=" << snapshot.ts_us
        << " policy_phase=" << snapshot.policy_phase
        << " policy_switch_count=" << snapshot.policy_switch_count
        << " channels=" << CounterValue(metric_samples, "executor.channels.total")
        << "\n";

    {
        const uint64_t completion = CounterValue(metric_samples, "fuzzer.results",
                                                 {{"kind", "completion"}});
        const uint64_t abnormal   = CounterValue(metric_samples, "fuzzer.results",
                                                 {{"kind", "abnormal"}});
        const uint64_t terminal   = completion + abnormal;
        out << prefix
            << "fuzzer generated=" << CounterValue(metric_samples, "fuzzer.generated_tasks")
            << " completion=" << completion
            << " partial_completion=" << CounterValue(metric_samples, "fuzzer.results",
                                                       {{"kind", "partial_completion"}})
            << " abnormal=" << abnormal
            << " fault=" << CounterValue(metric_samples, "fuzzer.results",
                                         {{"kind", "fault"}})
            << " terminal=" << terminal
            // [speed-compare arm D] real executed syscalls (kCallFlagExecuted),
            // for executed-syscalls/sec symmetric with syz's syz_exec_calls_total.
            << " exec_calls=" << CounterValue(metric_samples, "fuzzer.calls.executed")
            << " interesting=" << CounterValue(metric_samples, "fuzzer.results",
                                               {{"kind", "interesting"}})
            << " crash=" << CounterValue(metric_samples, "fuzzer.results",
                                         {{"kind", "crash"}})
            << " timeout=" << CounterValue(metric_samples, "fuzzer.results",
                                           {{"kind", "timeout"}})
            << " exec_error=" << CounterValue(metric_samples, "fuzzer.results",
                                              {{"kind", "exec_error"}})
            << " harness_fatal=" << CounterValue(metric_samples, "fuzzer.results",
                                                 {{"kind", "harness_fatal"}})
            // [v1 hardcoded coverage scalar — ROLLBACK: uncomment below]
            // << " new_cov=" << CounterValue(metric_samples, "fuzzer.cov.new_total")
            // << " unique_cov=" << CounterValue(metric_samples, "fuzzer.cov.unique")
            // [v2 PR-K-B — coverage moved to RenderCoverageBlock (descriptor-driven, §1.2 Rule B)]
            << " corpus=" << CounterValue(metric_samples, "fuzzer.corpus.size")
            // [v2 PR-K-E2] corpus_bytes 为 corpus payload 字节累计估算,用于
            // 直观判断 RSS 大头是否来自 corpus(平均 = bytes/size)。
            << " corpus_bytes=" << CounterValue(metric_samples, "fuzzer.corpus.bytes")
            << " corpus_growth=" << CounterValue(metric_samples, "fuzzer.corpus.growth")
            << " inbox_drop=" << CounterValue(metric_samples, "fuzzer.inbox_drop",
                                              {{"queue", "result"}})
            << "\n";
    }

    // [v1 6b-2 policies — ROLLBACK: uncomment below and remove v2]
    // out << prefix
    //     << "policies mutation=" << snapshot.fuzzer.policies.mutation_policy
    //     << " scheduling=" << snapshot.fuzzer.policies.scheduling_policy
    //     << " corpus=" << snapshot.fuzzer.policies.corpus_admission_policy
    //     << "\n";

    // [v2 6b-2 — 当前版本] policies 行从 metric_samples 读取 one-hot fuzzer.current_policy。
    // 渲染 key 名保持向后兼容（"scheduling=" 对应 kind="schedule"）。
    out << prefix
        << "policies mutation=" << LookupCurrentPolicy(metric_samples, "mutation")
        << " scheduling=" << LookupCurrentPolicy(metric_samples, "schedule")
        << " corpus=" << LookupCurrentPolicy(metric_samples, "corpus")
        << "\n";

    out << prefix
        << "executor pending_tasks=" << CounterValue(metric_samples, "executor.dispatch.pending")
        << " total_channels=" << CounterValue(metric_samples, "executor.channels.total")
        << " tasks_submitted=" << CounterValue(metric_samples, "executor.tasks_submitted")
        << " stop_requested=" << CounterValue(metric_samples, "executor.stop_requested")
        << "\n";

    out << prefix
        << "executor_counters events_forwarded=" << CounterValue(metric_samples, "executor.events_forwarded")
        << "\n";

    // [v1 6b-2 exec_channel — ROLLBACK: uncomment below and remove v2]
    // // channel 列表：仅输出 channel_id（v4 无 TargetState 可输出）
    // for (const auto& ch : executor.channels) {
    //     out << prefix
    //         << "exec_channel id=" << ch.channel_id
    //         << "\n";
    // }

    for (uint32_t channel_id : GatherChannelIds(metric_samples)) {
        const Labels id_label = {{"channel_id", std::to_string(channel_id)}};
        const uint64_t gen = CounterValue(metric_samples, "channel.generation", id_label);
        const uint64_t total_slots = CounterValue(metric_samples,
            "channel.runtime.total_slots", id_label);
        const uint64_t free_slots = CounterValue(metric_samples,
            "channel.runtime.free_slots", id_label);
        const uint64_t inflight = CounterValue(metric_samples,
            "channel.runtime.inflight", id_label);
        const uint64_t sampled_ts_us = CounterValue(metric_samples,
            "channel.health.sampled_ts_us", id_label);
        const auto workers = SummarizeWorkerLiveness(metric_samples, channel_id);
        const uint64_t k = CounterValue(metric_samples, "channel.health.crash",
            {{"channel_id", std::to_string(channel_id)}, {"kind", "kernel"}});
        const uint64_t v = CounterValue(metric_samples, "channel.health.crash",
            {{"channel_id", std::to_string(channel_id)}, {"kind", "vm"}});
        const uint64_t w = CounterValue(metric_samples, "channel.health.crash",
            {{"channel_id", std::to_string(channel_id)}, {"kind", "worker"}});
        const uint64_t i = CounterValue(metric_samples, "channel.health.crash",
            {{"channel_id", std::to_string(channel_id)}, {"kind", "internal"}});

        out << prefix
            << "channel_snapshot id=" << channel_id
            << " lifecycle=" << LookupLifecycleState(metric_samples, channel_id)
            << " generation=" << gen
            << " booted=" << (gen != 0 ? 1 : 0)
            << " slots=" << total_slots
            << " free_slots=" << free_slots
            << " inflight=" << inflight
            << " health=workers=" << workers.alive << '/' << workers.total
            << ",k=" << k << ",v=" << v << ",w=" << w << ",i=" << i
            << " sampled_ts_us=" << sampled_ts_us
            << "\n";

        // 一 worker 一行。上面 channel 行的 workers=alive/total 留作概览（channel 多起来
        // 时才有俯瞰），下面这些是详情。
        for (const uint32_t wid : GatherWorkerIds(metric_samples, channel_id)) {
            const Labels wl{{"channel_id", std::to_string(channel_id)},
                            {"worker_id", std::to_string(wid)}};
            const bool alive = CounterValue(metric_samples, "channel.health.worker_liveness",
                {{"channel_id", std::to_string(channel_id)},
                 {"worker_id", std::to_string(wid)},
                 {"state", "alive"}}) >= 1;
            const uint64_t silent_s =
                CounterValue(metric_samples, "channel.health.worker_silent_s", wl);
            const uint64_t budget_s =
                CounterValue(metric_samples, "channel.health.worker_silent_budget_s", wl);
            const uint64_t epoch =
                CounterValue(metric_samples, "channel.health.worker_proc_epoch", wl);
            const bool recovering =
                CounterValue(metric_samples, "channel.health.worker_recovering", wl) >= 1;
            const auto slot =
                static_cast<int64_t>(CounterValue(metric_samples, "channel.health.worker_slot", wl));

            out << prefix
                << "worker channel=" << channel_id
                << " id=" << wid
                << " state=" << WorkerStateName(alive, silent_s, recovering, slot)
                << " slot=" << SlotName(slot)
                << " silent=" << silent_s << "s/" << budget_s << "s"
                << " proc_epoch=" << epoch
                << "\n";
        }
    }

    out << prefix << "recent_events=" << recent_events.size() << "\n";
    for (const auto& event : recent_events) {
        out << prefix
            << "event ts_us=" << event.ts_us
            << " kind=" << EventKindName(event.kind)
            << " channel=" << event.channel_id
            << " incident=" << event.incident_id;
        AppendEventField(out, "subject", event.subject, 48);
        AppendEventField(out, "from", event.from_state, 48);
        AppendEventField(out, "to", event.to_state, 48);
        AppendEventField(out, "detail", event.detail, 500);
        out << "\n";
    }

    return out.str();
}

// Store-based overload:从 store 取 snapshot + samples + events
std::string RenderRuntimePanel(const RunStateStore& store,
                               std::string_view tag,
                               size_t max_events)
{
    // [v2 PR-K-B] Append descriptor-driven coverage block. The lower-level
    // overload (SampleMap-based) is kept untouched for tests that pass a
    // raw SampleMap; coverage rendering only runs when a store is available
    // (i.e., production + projector-aware tests).
    auto rendered = RenderRuntimePanel(store.LatestSnapshot(),
                                       store.MetricSamples(),
                                       store.RecentEvents(max_events),
                                       tag);

    // [v2 G5 follow-up] exec/sec windowed(LibAFL `afl_exec_sec` 等价)+ avg
    // (cumulative)。windowed 是 EWMA 平滑后的 5s 窗口 delta rate;avg 从
    // run_summary 拿(`terminal / exec_fuzz_s` 累计平均)。两条并存反映"当前/末段
    // 速率" vs "全局回顾"。详 docs/telemetry-redesign(LibAFL afl_exec_sec ref)。
    {
        std::ostringstream rate_line;
        const std::string prefix = tag.empty() ? std::string() : ("[" + std::string(tag) + "] ");
        rate_line << prefix
                  << "exec/s windowed=" << std::fixed << std::setprecision(2)
                  << store.WindowedExecsPerSec() << " (5s)";
        if (auto rs = store.LatestRunSummary(); rs.has_value()) {
            for (const auto& f : rs->fields) {
                if (f.first == "execs_per_sec" && f.second.kind == SummaryValueKind::kDouble) {
                    rate_line << " avg=" << std::fixed << std::setprecision(2) << f.second.d;
                    break;
                }
            }
        }
        rate_line << "\n";
        rendered += rate_line.str();
    }

    rendered += RenderCoverageBlock(store);
    rendered += '\n';
    return rendered;
}

// [v2 PR-K-B] Descriptor-driven coverage block — see header for contract.
//
// Atomic snapshot per series: ONE SeriesSnapshot() call provides both
// the sparkline history and the latest scalar (history.back()). Two-call
// patterns (LatestSeriesPoint + SeriesSnapshot under separate locks)
// would let the projector push a new point between them, so the scalar
// could come from tick N while the sparkline included tick N+1. The
// single-snapshot shape is race-free.
std::string RenderCoverageBlock(const RunStateStore& store, size_t spark_width)
{
    std::ostringstream out;
    for (const auto& descriptor : store.RegisteredSeries()) {
        out << "\n  " << descriptor.display_name;
        const auto history = store.SeriesSnapshot(descriptor.id, spark_width);
        if (history.empty()) {
            out << " (no coverage data)";
            continue;
        }
        const auto& latest = history.back();
        out << " total=" << latest.value_total
            << " Δ="     << latest.value_delta
            << ' '       << RenderSparkline(history);
    }
    return out.str();
}

// [v2 run_summary redesign]
std::string RenderRunSummary(const RunStateStore& store, std::string_view tag)
{
    std::ostringstream out;
    const std::string prefix = tag.empty() ? std::string() : ("[" + std::string(tag) + "] ");

    const auto summary_opt = store.LatestRunSummary();
    if (!summary_opt) {
        out << prefix << "run_summary=pending\n";
        return out.str();
    }
    const RunSummary& s = *summary_opt;

    out << prefix
        << "status=" << InvariantStatusName(s.invariants.status)
        << (s.is_final ? " (final)" : " (tick)") << "\n";
    out << prefix;
    for (size_t i = 0; i < s.fields.size(); ++i) {
        if (i > 0) out << ' ';
        out << s.fields[i].first << '=';
        const auto& v = s.fields[i].second;
        if (v.kind == SummaryValueKind::kInt) {
            out << v.i;
        } else {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.3f", v.d);
            out << buf;
        }
    }
    out << "\n";

    if (!s.invariants.failures.empty()) {
        out << prefix << "invariant_failures=";
        for (size_t i = 0; i < s.invariants.failures.size(); ++i) {
            if (i > 0) out << ',';
            out << s.invariants.failures[i];
        }
        out << "\n";
    }
    return out.str();
}

} // namespace refuzz::telemetry
