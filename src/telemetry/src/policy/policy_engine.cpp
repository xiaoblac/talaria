#include "refuzz/telemetry/policy/policy_engine.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <chrono>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_set>

namespace refuzz::telemetry {
using refuzz::core::RuntimeEvent;
using refuzz::core::metrics::Labels;
using refuzz::core::metrics::MetricRegistry;

namespace {

uint64_t NowUs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

// ── registry helper functions (D5: duplicated from run_state_renderer.cpp) ─

// Read a Counter value by (name, labels); returns 0 if not found.
uint64_t CounterValue(const MetricRegistry& registry,
                      std::string_view name,
                      const Labels& labels = {})
{
    const auto samples = registry.CollectPrefix(std::string(name));
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return static_cast<uint64_t>(s.value);
        }
    }
    return 0;
}

// Read a Gauge value by (name, labels); returns 0 if not found.
int64_t GaugeValue(const MetricRegistry& registry,
                   std::string_view name,
                   const Labels& labels = {})
{
    const auto samples = registry.CollectPrefix(std::string(name));
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return s.value;
        }
    }
    return 0;
}

// Scan "channel." prefix samples; extract unique channel_ids (sorted).
std::vector<uint32_t> GatherChannelIds(const MetricRegistry& registry)
{
    std::set<uint32_t> ids;
    const auto samples = registry.CollectPrefix("channel.");
    for (const auto& s : samples) {
        for (const auto& [k, v] : s.labels) {
            if (k == "channel_id") {
                try {
                    ids.insert(static_cast<uint32_t>(std::stoul(v)));
                } catch (...) {}
                break;
            }
        }
    }
    return {ids.begin(), ids.end()}; // sorted
}

// Reverse-lookup lifecycle_state one-hot for a channel.
// Returns "unknown" if no state gauge has value >= 1.
std::string LookupLifecycleState(const MetricRegistry& registry,
                                 uint32_t channel_id)
{
    // 7 state names — must match kLifecycleNames in channel_metrics.cpp
    static const char* kStates[] = {
        "stopped", "booting", "running", "degraded", "recovering", "failed", "closed"
    };
    const std::string cid = std::to_string(channel_id);
    const auto samples = registry.CollectPrefix("channel.lifecycle_state");
    for (const char* state : kStates) {
        const Labels lbl = {{"channel_id", cid}, {"state", state}};
        for (const auto& s : samples) {
            if (s.name == "channel.lifecycle_state" &&
                s.labels == lbl &&
                s.value >= 1) {
                return state;
            }
        }
    }
    return "unknown";
}

// Reverse-lookup current policy name from one-hot fuzzer.current_policy{kind=X}.
// Returns empty string if not found (no Set() called yet).
std::string LookupCurrentPolicy(const MetricRegistry& registry,
                                std::string_view kind)
{
    const auto samples = registry.CollectPrefix("fuzzer.current_policy");
    const std::string kind_str(kind);
    for (const auto& s : samples) {
        if (s.name != "fuzzer.current_policy") {
            continue;
        }
        std::string_view found_kind;
        std::string_view found_name;
        for (const auto& [k, v] : s.labels) {
            if (k == "kind") found_kind = v;
            else if (k == "name") found_name = v;
        }
        if (found_kind == kind_str && s.value >= 1) {
            return std::string(found_name);
        }
    }
    return {};
}

} // namespace

const char* SystemPhaseName(SystemPhase phase)
{
    switch (phase) {
    case SystemPhase::kNormal:
        return "normal";
    case SystemPhase::kDegraded:
        return "degraded";
    case SystemPhase::kRecovering:
        return "recovering";
    case SystemPhase::kStalled:
        return "stalled";
    }
    return "unknown";
}

// [v2 — 当前版本] registry 参数替代旧 RuntimeSnapshot 数据源
PolicyEngine::PolicyEngine(refuzz::core::IPolicyControl& control,
                           RunStateStore* store,
                           const refuzz::core::metrics::MetricRegistry& registry,
                           PolicyEngineConfig config)
    : control_(control)
    , store_(store)
    , registry_(registry)
    , config_(std::move(config))
{}

bool PolicyEngine::CooldownPassed() const
{
    return std::chrono::steady_clock::now() - last_switch_ >= config_.min_dwell;
}

// [v2 — 当前版本] 替代 SnapshotMatchesProfile，从 registry 反查当前策略名。
// 若某种 kind 尚未发布（LookupCurrentPolicy 返回空），视为"不知道"，
// 不触发切换（返回 true），避免启动前 / 测试无数据时误触发 ApplyProfile。
bool PolicyEngine::CurrentPoliciesMatch(const PolicyProfile& profile) const
{
    const auto mutation  = LookupCurrentPolicy(registry_, "mutation");
    const auto schedule  = LookupCurrentPolicy(registry_, "schedule");
    const auto corpus    = LookupCurrentPolicy(registry_, "corpus");

    // If any kind is unknown (not yet published), treat as match to avoid
    // spurious ApplyProfile when no policy state has been registered.
    if (mutation.empty() || schedule.empty() || corpus.empty()) {
        return true;
    }

    return mutation == profile.mutation_policy &&
           schedule == profile.scheduling_policy &&
           corpus   == profile.corpus_policy;
}

void PolicyEngine::ApplyProfile(const PolicyProfile& profile)
{
    control_.SwitchMutationPolicy(profile.mutation_policy);
    control_.SwitchSchedulingPolicy(profile.scheduling_policy);
    control_.SwitchCorpusAdmissionPolicy(profile.corpus_policy);
    last_switch_ = std::chrono::steady_clock::now();
    switch_count_.fetch_add(1, std::memory_order_relaxed);
}

// [v2 — 当前版本] 从 registry 读 fuzzer.results + fuzzer.cov.new_total
void PolicyEngine::UpdateCovBaseline()
{
    const uint64_t completion = CounterValue(registry_, "fuzzer.results",
                                             {{"kind", "completion"}});
    const uint64_t abnormal   = CounterValue(registry_, "fuzzer.results",
                                             {{"kind", "abnormal"}});
    const uint64_t terminal = completion + abnormal;

    double cov_rate = 0.0;
    if (terminal > last_consumed_) {
        const uint64_t cov_total = CounterValue(registry_, "fuzzer.cov.new_total");
        const uint64_t d_cov  = cov_total > last_cov_total_ ? cov_total - last_cov_total_ : 0;
        const uint64_t d_cons = terminal - last_consumed_;
        cov_rate = d_cons > 0
            ? static_cast<double>(d_cov) / static_cast<double>(d_cons)
            : 0.0;
        last_cov_total_ = cov_total;
    }
    last_consumed_ = terminal;

    cov_rate_window_.push_back(cov_rate);
    if (static_cast<int>(cov_rate_window_.size()) > config_.window_size) {
        cov_rate_window_.pop_front();
    }
}

bool PolicyEngine::CheckStalled()
{
    if (static_cast<int>(cov_rate_window_.size()) < config_.window_size) {
        consecutive_stall_windows_ = 0;
        return false;
    }

    double sum = 0.0;
    for (double rate : cov_rate_window_) {
        sum += rate;
    }
    const double avg = sum / static_cast<double>(cov_rate_window_.size());
    if (avg < config_.stall_threshold) {
        ++consecutive_stall_windows_;
    } else {
        consecutive_stall_windows_ = 0;
    }
    return consecutive_stall_windows_ >= config_.required_stall_windows;
}

// [v2 — 当前版本] 从 registry 反查 channel lifecycle_state + executor 指标
SystemPhase PolicyEngine::DeterminePhase()
{
    UpdateCovBaseline();

    bool any_recovery = false;
    std::unordered_set<uint32_t> unhealthy_channels;

    const bool stop_requested = GaugeValue(registry_, "executor.stop_requested") >= 1;
    const auto ids = GatherChannelIds(registry_);

    for (uint32_t id : ids) {
        const auto state = LookupLifecycleState(registry_, id);
        if (state == "booting" || state == "recovering") {
            any_recovery = true;
        } else if (state == "degraded" || state == "failed") {
            unhealthy_channels.insert(id);
        } else if (state == "stopped" || state == "closed") {
            if (!stop_requested) {
                unhealthy_channels.insert(id);
            }
        }
        // "running" or "unknown" → no-op
    }

    if (any_recovery) {
        consecutive_stall_windows_ = 0;
        return SystemPhase::kRecovering;
    }

    // total_channels from executor metric; fall back to ids.size() if zero (D§2.5)
    size_t total = static_cast<size_t>(
        GaugeValue(registry_, "executor.channels.total"));
    if (total == 0) {
        total = ids.size();
    }

    if (total > 0) {
        const double ratio = static_cast<double>(unhealthy_channels.size()) /
                             static_cast<double>(total);
        if (ratio >= config_.degraded_channel_ratio) {
            consecutive_stall_windows_ = 0;
            return SystemPhase::kDegraded;
        }
    }

    if (CheckStalled()) {
        return SystemPhase::kStalled;
    }
    return SystemPhase::kNormal;
}

// [v2 — 当前版本] Evaluate() 无参数，读 registry 代替 RuntimeSnapshot
void PolicyEngine::Evaluate()
{
    const SystemPhase previous = current_phase_.load(std::memory_order_acquire);
    const SystemPhase phase = DeterminePhase();
    current_phase_.store(phase, std::memory_order_release);

    if ((phase == SystemPhase::kRecovering || phase == SystemPhase::kDegraded) &&
        store_ != nullptr && phase != previous) {
        store_->PushEvent(RuntimeEvent{
            .ts_us = NowUs(),
            .kind = RuntimeEvent::Kind::kPolicySwitch,
            .subject = "policy_phase",
            .from_state = SystemPhaseName(previous),
            .to_state = SystemPhaseName(phase),
            .detail = "hold_current_policies",
        });
        return;
    }

    const PolicyProfile* desired = nullptr;
    switch (phase) {
    case SystemPhase::kNormal:
        desired = &config_.normal;
        break;
    case SystemPhase::kStalled:
        desired = &config_.stalled;
        break;
    case SystemPhase::kDegraded:
    case SystemPhase::kRecovering:
        return;
    }

    if (desired == nullptr || CurrentPoliciesMatch(*desired)) {
        return;
    }
    if (!CooldownPassed()) {
        return;
    }

    ApplyProfile(*desired);
    if (store_ != nullptr) {
        std::ostringstream detail;
        detail << "mutation=" << desired->mutation_policy
               << " scheduling=" << desired->scheduling_policy
               << " corpus=" << desired->corpus_policy;
        store_->PushEvent(RuntimeEvent{
            .ts_us = NowUs(),
            .kind = RuntimeEvent::Kind::kPolicySwitch,
            .subject = "policy_phase",
            .from_state = SystemPhaseName(previous),
            .to_state = SystemPhaseName(phase),
            .detail = detail.str(),
        });
    }
}

SystemPhase PolicyEngine::CurrentPhase() const
{
    return current_phase_.load(std::memory_order_acquire);
}

uint64_t PolicyEngine::SwitchCount() const
{
    return switch_count_.load(std::memory_order_acquire);
}

} // namespace refuzz::telemetry
