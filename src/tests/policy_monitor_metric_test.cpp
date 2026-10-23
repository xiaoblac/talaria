// policy_monitor_metric_test.cpp
//
// 验证 Step 2:PolicyMonitor::Tick 从 MetricRegistry 读取
// fuzzer.cov.new_total 和 fuzzer.results{kind=completion/abnormal}
// 驱动滑窗停滞判断，TriggerCount 在满足条件时递增。

#include "refuzz/core/control.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/policy/policy_monitor.hpp"

#include <cstdio>
#include <cstdint>
#include <string_view>

using refuzz::core::metrics::MetricRegistry;
using refuzz::telemetry::PolicyMonitor;
using refuzz::telemetry::PolicyMonitorConfig;

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

// 最小 stub:记录调用次数即可，不需要实际切换策略。
class StubPolicyControl final : public refuzz::core::IPolicyControl {
public:
    void SwitchMutationPolicy(std::string_view) override { ++switch_calls; }
    void SwitchSchedulingPolicy(std::string_view) override {}
    void SwitchCorpusAdmissionPolicy(std::string_view) override {}
    int switch_calls = 0;
};

// 向 registry 发布一批 counter 增量，模拟 fuzzer 运行一个 tick 的情况。
static void Publish(MetricRegistry& r, uint64_t cov, uint64_t completion, uint64_t abnormal)
{
    r.CounterOf("fuzzer.cov.new_total").Inc(static_cast<int64_t>(cov));
    r.CounterOf("fuzzer.results", {{"kind", "completion"}}).Inc(static_cast<int64_t>(completion));
    r.CounterOf("fuzzer.results", {{"kind", "abnormal"}}).Inc(static_cast<int64_t>(abnormal));
}

// Tick 不应触发:覆盖率持续增长，不停滞。
static int TestNoTriggerWhenCoverageGrowing()
{
    MetricRegistry r;
    StubPolicyControl ctrl;
    PolicyMonitorConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.window_size = 3;
    cfg.stall_threshold = 0.01;
    cfg.required_windows = 2;

    PolicyMonitor mon(ctrl, cfg);

    // 每个 tick 新增 10 coverage / 100 terminal — 速率 0.1，高于阈值。
    for (int i = 0; i < 6; ++i) {
        Publish(r, 10, 100, 0);
        mon.Tick(r);
    }
    CHECK(mon.TriggerCount() == 0);
    return 0;
}

// Tick 应触发:覆盖率为零，连续 required_windows 个窗口停滞后触发。
static int TestTriggerWhenStalled()
{
    MetricRegistry r;
    StubPolicyControl ctrl;
    PolicyMonitorConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.window_size = 3;
    cfg.stall_threshold = 0.01;
    cfg.required_windows = 2;

    PolicyMonitor mon(ctrl, cfg);

    // 填满窗口:有 terminal 进展但零覆盖 → cov_rate=0 < stall_threshold。
    // 需要 window_size + (required_windows-1) 个 tick 才能连续满足条件。
    for (int i = 0; i < 5; ++i) {
        Publish(r, 0, 50, 0);
        mon.Tick(r);
    }
    CHECK(mon.TriggerCount() == 1);
    return 0;
}

// 若 terminal 不增长则 cov_rate 保持 0，窗口也会积累 0.0 率。
static int TestTerminalFromBothCompletionAndAbnormal()
{
    MetricRegistry r;
    StubPolicyControl ctrl;
    PolicyMonitorConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.window_size = 2;
    cfg.stall_threshold = 0.01;
    cfg.required_windows = 2;

    PolicyMonitor mon(ctrl, cfg);

    // completion=0, abnormal=30 → terminal=30，cov_rate=0/30=0。
    for (int i = 0; i < 4; ++i) {
        Publish(r, 0, 0, 30);
        mon.Tick(r);
    }
    CHECK(mon.TriggerCount() == 1);
    return 0;
}

// 重置后再次停滞应再次触发。
static int TestTriggerCountIncrementsEachStall()
{
    MetricRegistry r;
    StubPolicyControl ctrl;
    PolicyMonitorConfig cfg;
    cfg.min_dwell = std::chrono::seconds{0};
    cfg.window_size = 2;
    cfg.stall_threshold = 0.01;
    cfg.required_windows = 2;

    PolicyMonitor mon(ctrl, cfg);

    // 第一次停滞触发。
    for (int i = 0; i < 4; ++i) {
        Publish(r, 0, 50, 0);
        mon.Tick(r);
    }
    const uint64_t after_first = mon.TriggerCount();
    CHECK(after_first >= 1);

    // 继续停滞应再触发一次(consecutive_stall_windows_ 被重置为 0 后重新积累)。
    for (int i = 0; i < 4; ++i) {
        Publish(r, 0, 50, 0);
        mon.Tick(r);
    }
    CHECK(mon.TriggerCount() > after_first);
    return 0;
}

int main()
{
    RUN_TEST(TestNoTriggerWhenCoverageGrowing);
    RUN_TEST(TestTriggerWhenStalled);
    RUN_TEST(TestTerminalFromBothCompletionAndAbnormal);
    RUN_TEST(TestTriggerCountIncrementsEachStall);
    return 0;
}
