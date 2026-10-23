// policy_engine_registry_test.cpp
//
// Step 6b-1: PolicyEngine migrated to consume MetricRegistry instead of
// RuntimeSnapshot. Verifies all five cases described in the 6b-1 spec.

#include "refuzz/core/control.hpp"
#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/metrics/policy_state_publisher.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"
#include "refuzz/telemetry/policy/policy_engine.hpp"

#include <cstdio>
#include <cstdint>
#include <string_view>

using refuzz::core::metrics::Counter;
using refuzz::core::metrics::Gauge;
using refuzz::core::metrics::MetricRegistry;
using refuzz::core::metrics::PolicyStatePublisher;
using refuzz::telemetry::PolicyEngine;
using refuzz::telemetry::PolicyEngineConfig;
using refuzz::telemetry::RunStateStore;
using refuzz::telemetry::SystemPhase;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",            \
                         #cond, __LINE__);                                  \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        int rc = fn();                                                      \
        if (rc != 0) {                                                      \
            std::fprintf(stderr, "FAILED: %s\n", #fn);                      \
            return rc;                                                      \
        }                                                                   \
        std::fprintf(stderr, "PASS:   %s\n", #fn);                          \
    } while (0)

// Minimal FakePolicyControl that records last applied policy names.
class FakePolicyControl final : public refuzz::core::IPolicyControl {
public:
    void SwitchMutationPolicy(std::string_view name) override
    {
        mutation_policy = std::string(name);
    }
    void SwitchSchedulingPolicy(std::string_view name) override
    {
        scheduling_policy = std::string(name);
    }
    void SwitchCorpusAdmissionPolicy(std::string_view name) override
    {
        corpus_policy = std::string(name);
    }

    std::string mutation_policy;
    std::string scheduling_policy;
    std::string corpus_policy;
};

// Case 1: Evaluate() with empty registry → kNormal, no policy switch.
static int TestCase1_EmptyRegistry()
{
    MetricRegistry registry;
    FakePolicyControl control;
    RunStateStore store;

    PolicyEngineConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0}; // disable cooldown

    PolicyEngine engine(control, &store, registry, cfg);
    engine.Evaluate();

    CHECK(engine.CurrentPhase() == SystemPhase::kNormal);
    CHECK(engine.SwitchCount() == 0);
    CHECK(control.mutation_policy.empty());
    return 0;
}

// Case 2: Fill stall window via fuzzer counters → kStalled → switch to stalled profile.
static int TestCase2_StallDetection()
{
    MetricRegistry registry;
    FakePolicyControl control;
    RunStateStore store;

    PolicyEngineConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.window_size = 3;
    cfg.required_stall_windows = 1;
    cfg.stall_threshold = 0.5; // rate below 0.5 is stalled

    // Register counter handles. We'll advance them step by step.
    Counter& completion = registry.CounterOf("fuzzer.results", {{"kind", "completion"}});
    Counter& cov_total  = registry.CounterOf("fuzzer.cov.new_total");

    PolicyEngine engine(control, &store, registry, cfg);

    // Publish policy gauges so CurrentPoliciesMatch works:
    // Before window fills, phase should be kNormal and policies match normal config.
    PolicyStatePublisher pub;
    pub.Bind(registry);
    pub.Set("mutation", cfg.normal.mutation_policy);
    pub.Set("schedule", cfg.normal.scheduling_policy);
    pub.Set("corpus",   cfg.normal.corpus_policy);

    // Fill window with zero-coverage completions (rate=0 < 0.5 → stalled).
    for (int i = 0; i < 3; ++i) {
        // Each tick: 10 more completions, 0 new coverage.
        for (int j = 0; j < 10; ++j) completion.Inc();
        engine.Evaluate();
    }

    // Now window is full with rate=0.0; required_stall_windows=1 → kStalled.
    CHECK(engine.CurrentPhase() == SystemPhase::kStalled);
    CHECK(engine.SwitchCount() == 1);
    CHECK(control.mutation_policy == cfg.stalled.mutation_policy);
    CHECK(control.scheduling_policy == cfg.stalled.scheduling_policy);
    CHECK(control.corpus_policy == cfg.stalled.corpus_policy);

    // Suppress unused warning.
    (void)cov_total;
    return 0;
}

// Case 3: Channel degraded via lifecycle_state one-hot → kDegraded.
static int TestCase3_DegradedChannel()
{
    MetricRegistry registry;
    FakePolicyControl control;
    RunStateStore store;

    PolicyEngineConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.degraded_channel_ratio = 0.5;

    // Set executor.channels.total = 1 and stop_requested = 0.
    registry.GaugeOf("executor.channels.total").Set(1);
    registry.GaugeOf("executor.stop_requested").Set(0);

    // Register lifecycle_state for channel_id=42 as degraded (one-hot).
    static const char* kStates[] = {
        "stopped", "booting", "running", "degraded", "recovering", "failed", "closed"
    };
    for (const char* state : kStates) {
        registry.GaugeOf("channel.lifecycle_state",
                          {{"channel_id", "42"}, {"state", state}}).Set(0);
    }
    registry.GaugeOf("channel.lifecycle_state",
                      {{"channel_id", "42"}, {"state", "degraded"}}).Set(1);

    PolicyEngine engine(control, &store, registry, cfg);
    engine.Evaluate();

    // 1 of 1 channel is degraded → ratio=1.0 >= 0.5 → kDegraded.
    CHECK(engine.CurrentPhase() == SystemPhase::kDegraded);
    // kDegraded holds current policies (no switch when phase == kDegraded).
    CHECK(engine.SwitchCount() == 0);
    return 0;
}

// Case 4: CurrentPoliciesMatch — publish via PolicyStatePublisher, verify match.
static int TestCase4_CurrentPoliciesMatch()
{
    MetricRegistry registry;
    FakePolicyControl control;
    RunStateStore store;

    PolicyEngineConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    // Set normal profile to a known set.
    cfg.normal.mutation_policy   = "uniform_random";
    cfg.normal.scheduling_policy = "round_robin";
    cfg.normal.corpus_policy     = "all_filters";

    // Publish the normal policy names so engine sees them as "current".
    PolicyStatePublisher pub;
    pub.Bind(registry);
    pub.Set("mutation", cfg.normal.mutation_policy);
    pub.Set("schedule", cfg.normal.scheduling_policy);
    pub.Set("corpus",   cfg.normal.corpus_policy);

    PolicyEngine engine(control, &store, registry, cfg);
    // With empty channel registry → kNormal phase, and current policies already match
    // normal → no switch.
    engine.Evaluate();

    CHECK(engine.CurrentPhase() == SystemPhase::kNormal);
    CHECK(engine.SwitchCount() == 0);
    // Confirm no switch happened because policies matched.
    CHECK(control.mutation_policy.empty());
    return 0;
}

// Case 5: PolicyStatePublisher.Set — old gauge zeroed, new gauge set to 1.
static int TestCase5_PublisherGaugeFlip()
{
    MetricRegistry registry;
    PolicyStatePublisher pub;
    pub.Bind(registry);

    // First set: mutation = "splice"
    pub.Set("mutation", "splice");

    // Verify splice = 1.
    {
        const auto samples = registry.CollectPrefix("fuzzer.current_policy");
        bool splice_is_1 = false;
        for (const auto& s : samples) {
            if (s.name != "fuzzer.current_policy") continue;
            std::string_view kind_v, name_v;
            for (const auto& [k, v] : s.labels) {
                if (k == "kind") kind_v = v;
                else if (k == "name") name_v = v;
            }
            if (kind_v == "mutation" && name_v == "splice") {
                splice_is_1 = (s.value == 1);
            }
        }
        CHECK(splice_is_1);
    }

    // Switch to: mutation = "havoc"
    pub.Set("mutation", "havoc");

    // Verify splice = 0, havoc = 1.
    {
        const auto samples = registry.CollectPrefix("fuzzer.current_policy");
        int64_t splice_val = -1, havoc_val = -1;
        for (const auto& s : samples) {
            if (s.name != "fuzzer.current_policy") continue;
            std::string_view kind_v, name_v;
            for (const auto& [k, v] : s.labels) {
                if (k == "kind") kind_v = v;
                else if (k == "name") name_v = v;
            }
            if (kind_v == "mutation") {
                if (name_v == "splice") splice_val = s.value;
                else if (name_v == "havoc") havoc_val = s.value;
            }
        }
        CHECK(splice_val == 0);
        CHECK(havoc_val == 1);
    }

    // No-op: set to same name again — havoc should still be 1.
    pub.Set("mutation", "havoc");
    {
        const auto samples = registry.CollectPrefix("fuzzer.current_policy");
        int64_t havoc_val = -1;
        for (const auto& s : samples) {
            if (s.name != "fuzzer.current_policy") continue;
            std::string_view kind_v, name_v;
            for (const auto& [k, v] : s.labels) {
                if (k == "kind") kind_v = v;
                else if (k == "name") name_v = v;
            }
            if (kind_v == "mutation" && name_v == "havoc") {
                havoc_val = s.value;
            }
        }
        CHECK(havoc_val == 1);
    }
    return 0;
}

int main()
{
    RUN_TEST(TestCase1_EmptyRegistry);
    RUN_TEST(TestCase2_StallDetection);
    RUN_TEST(TestCase3_DegradedChannel);
    RUN_TEST(TestCase4_CurrentPoliciesMatch);
    RUN_TEST(TestCase5_PublisherGaugeFlip);
    return 0;
}
