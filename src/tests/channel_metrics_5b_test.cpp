// channel_metrics_5b_test.cpp
//
// Step 5b 源头 Counter Inc 验证:
//   - FaultTracker runtime_restart / vm_reboot Counter 单调递增
//   - CounterMonotonicAcrossWindowExpiry: 窗口过期（reset snapshot 字段）不影响 Counter
//   - HealthMonitor crash counters 四种 kind 各 +1
//   - CrashCounterMonotonicAcrossHealthMonitorRestart: Stop+Start 重置 stat_* 不影响 Counter
//
// 不依赖 QEMU / ivshmem / 实际 VM；FaultTracker / HealthMonitor 可独立实例化。
// 使用裸 CHECK + RUN_TEST 宏（与项目其他测试风格对齐，无 googletest 依赖）。

#include "refuzz/channel/recovery/fault_tracker.hpp"
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/core/metrics/channel_metrics.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace refuzz::channel::recovery;
using namespace refuzz::channel::health;
using namespace refuzz::core::metrics;

namespace cc = refuzz::core::channel_contract;

// ─────────────────────────────────────────────────────────────
// Macros
// ─────────────────────────────────────────────────────────────

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
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                         \
        int rc = fn();                                                      \
        if (rc != 0) {                                                      \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                    \
            return rc;                                                      \
        }                                                                   \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                        \
    } while (0)

// ─────────────────────────────────────────────────────────────
// Minimal IHealthSensor stub — Start/Stop/Poke no-op
// (HealthMonitor::Start() requires at least one sensor)
// ─────────────────────────────────────────────────────────────

class NopSensor final : public IHealthSensor {
public:
    std::string_view Name() const override { return "nop"; }
    refuzz::channel::Result<void> Start(HealthPublisher& /*pub*/) override {
        return refuzz::channel::Result<void>::Ok();
    }
    void Stop() override {}
    void Poke() override {}
};

// ─────────────────────────────────────────────────────────────
// Helper — build a ChannelMetrics Bind'd to a registry
// ─────────────────────────────────────────────────────────────

static void MakeMetrics(MetricRegistry& reg, ChannelMetrics& m)
{
    m.Bind(reg, /*channel_id=*/0);
}

// ─────────────────────────────────────────────────────────────
// Helper — find a counter sample by label value for label key "kind"
// ─────────────────────────────────────────────────────────────

static int64_t FindByKind(const std::vector<MetricRegistry::Sample>& samples,
                          const std::string& kind_value)
{
    for (const auto& s : samples) {
        for (const auto& lv : s.labels) {
            // labels are LabelPair = std::pair<std::string, std::string>
            // .first = key, .second = value
            if (lv.first == "kind" && lv.second == kind_value) {
                return s.value;
            }
        }
    }
    return -1;  // not found
}

// ─────────────────────────────────────────────────────────────
// Helper — build a default FaultContext
// ─────────────────────────────────────────────────────────────

static FaultContext MakeFaultCtx()
{
    FaultContext ctx;
    ctx.source_worker_id = 0;
    ctx.total_workers    = 1;
    ctx.unusable_workers = 1;
    return ctx;
}

// ─────────────────────────────────────────────────────────────
// Helper — build a default CrashFragment with a given kind
// ─────────────────────────────────────────────────────────────

static cc::CrashFragment MakeFragment(cc::CrashKind kind)
{
    cc::CrashFragment f;
    f.kind             = kind;
    f.source_worker_id = 0;
    return f;
}

// ─────────────────────────────────────────────────────────────
// Test 1 — FaultTracker runtime_restart Counter increments
// ─────────────────────────────────────────────────────────────

static int TestFaultTrackerRuntimeRestartIncrementsCounter()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    FaultTracker tracker(FaultTrackerConfig{
        .fault_window_ms         = 60000,
        .healthy_streak_to_reset = 100,  // large — prevent auto-reset
    });
    tracker.SetMetrics(&m);

    // Drive N kRestartAllWorkers faults through TryBeginRecovery + CompleteRecovery.
    // Each TryBeginRecovery call increments runtime_restart_count AND must call Counter Inc.
    constexpr int N = 5;
    for (int i = 0; i < N; ++i) {
        auto obs = tracker.ObserveFault(static_cast<uint64_t>(i + 1), MakeFaultCtx());
        CHECK(obs.can_proceed);

        // TryBeginRecovery — triggers ++state.runtime_restart_count + Counter Inc
        bool bound = tracker.TryBeginRecovery(
            static_cast<uint64_t>(i + 1),
            cc::ChannelFaultReason::kWorkerHeartbeatLost,
            cc::RecoveryAction::kRestartAllWorkers);
        CHECK(bound);

        // CompleteRecovery (success=false avoids resetting counters)
        bool ok = tracker.CompleteRecovery(
            static_cast<uint64_t>(i + 1),
            cc::RecoveryAction::kRestartAllWorkers,
            /*success=*/false);
        CHECK(ok);
    }

    const auto samples = reg.CollectPrefix("channel.recovery.runtime_restart");
    CHECK(samples.size() == 1);
    CHECK(samples[0].value == static_cast<int64_t>(N));

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 2 — FaultTracker vm_reboot Counter increments
// ─────────────────────────────────────────────────────────────

static int TestFaultTrackerVmRebootIncrementsCounter()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    FaultTracker tracker(FaultTrackerConfig{
        .fault_window_ms         = 60000,
        .healthy_streak_to_reset = 100,
    });
    tracker.SetMetrics(&m);

    constexpr int N = 3;
    for (int i = 0; i < N; ++i) {
        auto obs = tracker.ObserveFault(static_cast<uint64_t>(i + 1), MakeFaultCtx());
        CHECK(obs.can_proceed);

        bool bound = tracker.TryBeginRecovery(
            static_cast<uint64_t>(i + 1),
            cc::ChannelFaultReason::kWorkerHeartbeatLost,
            cc::RecoveryAction::kRebootVm);
        CHECK(bound);

        bool ok = tracker.CompleteRecovery(
            static_cast<uint64_t>(i + 1),
            cc::RecoveryAction::kRebootVm,
            /*success=*/false);  // success=false avoids resetting snapshot counts
        CHECK(ok);
    }

    const auto samples = reg.CollectPrefix("channel.recovery.vm_reboot");
    CHECK(samples.size() == 1);
    CHECK(samples[0].value == static_cast<int64_t>(N));

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 3 — Counter monotonic across window expiry
// Window expiry resets state.runtime_restart_count (snapshot),
// but must NOT reset the Counter (Counter is monotonic).
// ─────────────────────────────────────────────────────────────

static int TestCounterMonotonicAcrossWindowExpiry()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    // Very short fault window: 1 ms
    FaultTracker tracker(FaultTrackerConfig{
        .fault_window_ms         = 1,
        .healthy_streak_to_reset = 100,
    });
    tracker.SetMetrics(&m);

    // First fault → TryBeginRecovery → Counter = 1
    {
        auto obs = tracker.ObserveFault(1, MakeFaultCtx());
        CHECK(obs.can_proceed);

        bool bound = tracker.TryBeginRecovery(
            1,
            cc::ChannelFaultReason::kWorkerHeartbeatLost,
            cc::RecoveryAction::kRestartAllWorkers);
        CHECK(bound);

        bool ok = tracker.CompleteRecovery(1, cc::RecoveryAction::kRestartAllWorkers, false);
        CHECK(ok);
    }

    // Verify Counter = 1 after first fault
    {
        auto samples = reg.CollectPrefix("channel.recovery.runtime_restart");
        CHECK(samples.size() == 1);
        CHECK(samples[0].value == 1);
    }

    // Sleep > 1ms to force window expiry.
    // MaybeDecayWindow resets state.runtime_restart_count → 0 (snapshot reset).
    // The next ObserveFault call will trigger MaybeDecayWindow.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Second fault → window has expired (ObserveFault will call MaybeDecayWindow
    // and reset state.runtime_restart_count = 0) → TryBeginRecovery → Counter = 2
    {
        auto obs = tracker.ObserveFault(2, MakeFaultCtx());
        CHECK(obs.can_proceed);

        bool bound = tracker.TryBeginRecovery(
            2,
            cc::ChannelFaultReason::kWorkerHeartbeatLost,
            cc::RecoveryAction::kRestartAllWorkers);
        CHECK(bound);

        bool ok = tracker.CompleteRecovery(2, cc::RecoveryAction::kRestartAllWorkers, false);
        CHECK(ok);
    }

    // Counter MUST be 2 (not 1) — window expiry must not reset it.
    {
        auto samples = reg.CollectPrefix("channel.recovery.runtime_restart");
        CHECK(samples.size() == 1);
        CHECK(samples[0].value == 2);
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 3b — 真 kernel crash 的 reboot 不消耗基础设施 cascade 预算
// kKernelCrash → reboot 成功：保护窗照常打开，但 reboots_in_cascade_window 不 +1；
// 随后 kVmDead（基础设施故障）→ reboot 成功才 +1。否则高频真 bug 会把预算打满，
// 后续基础设施故障被错误熔断（kFailChannel）。
// ─────────────────────────────────────────────────────────────

static int TestKernelCrashRebootDoesNotConsumeCascadeBudget()
{
    FaultTracker tracker(FaultTrackerConfig{
        .fault_window_ms         = 60000,
        .healthy_streak_to_reset = 100,  // large — prevent auto-reset
    });

    // ① 真 kernel crash → reboot 成功：开保护窗，但不计 cascade
    {
        auto obs = tracker.ObserveFault(1, MakeFaultCtx());
        CHECK(obs.can_proceed);

        bool bound = tracker.TryBeginRecovery(
            1,
            cc::ChannelFaultReason::kKernelCrash,
            cc::RecoveryAction::kRebootVm);
        CHECK(bound);

        bool ok = tracker.CompleteRecovery(
            1,
            cc::RecoveryAction::kRebootVm,
            /*success=*/true);
        CHECK(ok);

        auto snap = tracker.GetSnapshot();
        CHECK(snap.reboots_in_cascade_window == 0);
        CHECK(snap.recovery_window_until_us != 0);  // 保护窗仍开
        CHECK(snap.recovery_backoff_level == 0);
    }

    // ② 基础设施故障（qemu 退出 kVmDead）→ reboot 成功：才计 cascade
    {
        auto obs = tracker.ObserveFault(2, MakeFaultCtx());
        CHECK(obs.can_proceed);

        bool bound = tracker.TryBeginRecovery(
            2,
            cc::ChannelFaultReason::kVmDead,
            cc::RecoveryAction::kRebootVm);
        CHECK(bound);

        bool ok = tracker.CompleteRecovery(
            2,
            cc::RecoveryAction::kRebootVm,
            /*success=*/true);
        CHECK(ok);

        auto snap = tracker.GetSnapshot();
        CHECK(snap.reboots_in_cascade_window == 1);
        CHECK(snap.recovery_backoff_level == 1);
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 4 — HealthMonitor crash counters increment (all 5 kinds)
// ─────────────────────────────────────────────────────────────

static int TestHealthMonitorCrashCountersIncrement()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    HealthMonitorConfig cfg;
    cfg.expected_worker_count = 1;
    HealthMonitor hm(HealthMonitorView{}, cfg);
    hm.AddSensor(std::make_unique<NopSensor>());
    hm.SetMetrics(&m);

    auto r = hm.Start();
    CHECK(r.ok());

    // Publish one event per crash kind via PublishCrashEvent
    hm.PublishCrashEvent(CrashEventOrigin::kSerialPattern,
        MakeFragment(cc::CrashKind::kKernelCrash));

    hm.PublishCrashEvent(CrashEventOrigin::kVmLiveness,
        MakeFragment(cc::CrashKind::kVmDead));

    hm.PublishCrashEvent(CrashEventOrigin::kHeartbeat,
        MakeFragment(cc::CrashKind::kWorkerDead));

    hm.PublishCrashEvent(CrashEventOrigin::kHealthInternal,
        MakeFragment(cc::CrashKind::kHealthInternalFault),
        "checker_name", 0);

    hm.PublishCrashEvent(CrashEventOrigin::kVmLiveness,
        MakeFragment(cc::CrashKind::kNoOutput));

    hm.Stop();

    // Assert each counter = 1
    {
        const auto samples = reg.CollectPrefix("channel.health.crash");
        // 5 series: kind=kernel/vm/worker/internal/no_output
        CHECK(samples.size() == 5);

        CHECK(FindByKind(samples, "kernel")   == 1);
        CHECK(FindByKind(samples, "vm")        == 1);
        CHECK(FindByKind(samples, "worker")    == 1);
        CHECK(FindByKind(samples, "internal")  == 1);
        CHECK(FindByKind(samples, "no_output") == 1);
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 5 — Crash counter monotonic across HealthMonitor restart
// The source Counter accumulates across Stop()/Start() (2 after 2 events).
// Counter 语义 = "本 run 内累计发生次数"，HealthMonitor 重启不清零。
// ─────────────────────────────────────────────────────────────

static int TestCrashCounterMonotonicAcrossHealthMonitorRestart()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    HealthMonitorConfig cfg;
    cfg.expected_worker_count = 1;
    HealthMonitor hm(HealthMonitorView{}, cfg);
    hm.AddSensor(std::make_unique<NopSensor>());
    hm.SetMetrics(&m);

    // First run: publish one kernel crash
    {
        auto r = hm.Start();
        CHECK(r.ok());

        hm.PublishCrashEvent(CrashEventOrigin::kSerialPattern,
            MakeFragment(cc::CrashKind::kKernelCrash));

        hm.Stop();
    }

    // Verify Counter = 1 after first run
    {
        const auto samples = reg.CollectPrefix("channel.health.crash");
        CHECK(FindByKind(samples, "kernel") == 1);
    }

    // Second run: restart the HealthMonitor, then publish one more kernel crash.
    {
        auto r = hm.Start();
        CHECK(r.ok());

        hm.PublishCrashEvent(CrashEventOrigin::kSerialPattern,
            MakeFragment(cc::CrashKind::kKernelCrash));

        hm.Stop();
    }

    // Counter MUST be 2 (not 1) — snapshot reset must not affect Counter.
    {
        const auto samples = reg.CollectPrefix("channel.health.crash");
        CHECK(FindByKind(samples, "kernel") == 2);
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
// Test 6 — HealthMonitor Publish() path also increments Counter
// (second publish path: Sensor submits pre-built CrashEvent)
// ─────────────────────────────────────────────────────────────

static int TestHealthMonitorPublishPathIncrementsCounter()
{
    MetricRegistry  reg;
    ChannelMetrics  m{};
    MakeMetrics(reg, m);

    HealthMonitorConfig cfg;
    cfg.expected_worker_count = 1;
    HealthMonitor hm(HealthMonitorView{}, cfg);
    hm.AddSensor(std::make_unique<NopSensor>());
    hm.SetMetrics(&m);

    auto r = hm.Start();
    CHECK(r.ok());

    // Use the Publish() interface (second code path)
    CrashEvent ev;
    ev.fragment = MakeFragment(cc::CrashKind::kVmDead);
    hm.Publish(std::move(ev));

    hm.Stop();

    const auto samples = reg.CollectPrefix("channel.health.crash");
    CHECK(FindByKind(samples, "vm") == 1);

    return 0;
}

// ─────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// §4.6 input_queue series Bind smoke test
// 验证 5 条 series 在 Bind 后指针非空,且 Counter / Gauge kind 正确。
// ─────────────────────────────────────────────────────────────

static int TestChannelInputQueueSeriesBind()
{
    MetricRegistry reg;
    ChannelMetrics m;
    MakeMetrics(reg, m);

    CHECK(m.input_queue_depth          != nullptr);
    CHECK(m.input_queue_capacity       != nullptr);
    CHECK(m.input_queue_full_episodes  != nullptr);
    CHECK(m.input_queue_busy_rejects   != nullptr);
    CHECK(m.input_queue_full_us        != nullptr);

    // Counter 起始 0
    CHECK(m.input_queue_full_episodes->Value() == 0u);
    CHECK(m.input_queue_busy_rejects->Value()  == 0u);
    CHECK(m.input_queue_full_us->Value()       == 0u);

    // Gauge 起始 0
    CHECK(m.input_queue_depth->Value()    == 0);
    CHECK(m.input_queue_capacity->Value() == 0);

    // 重复 Bind 幂等 (同 channel_id)
    ChannelMetrics m2;
    m2.Bind(reg, /*channel_id=*/0);
    CHECK(m2.input_queue_depth          == m.input_queue_depth);
    CHECK(m2.input_queue_capacity       == m.input_queue_capacity);
    CHECK(m2.input_queue_full_episodes  == m.input_queue_full_episodes);
    CHECK(m2.input_queue_busy_rejects   == m.input_queue_busy_rejects);
    CHECK(m2.input_queue_full_us        == m.input_queue_full_us);

    return 0;
}

int main()
{
    std::fprintf(stderr, "=== channel_metrics_5b_test ===\n");

    RUN_TEST(TestFaultTrackerRuntimeRestartIncrementsCounter);
    RUN_TEST(TestFaultTrackerVmRebootIncrementsCounter);
    RUN_TEST(TestCounterMonotonicAcrossWindowExpiry);
    RUN_TEST(TestKernelCrashRebootDoesNotConsumeCascadeBudget);
    RUN_TEST(TestHealthMonitorCrashCountersIncrement);
    RUN_TEST(TestCrashCounterMonotonicAcrossHealthMonitorRestart);
    RUN_TEST(TestHealthMonitorPublishPathIncrementsCounter);
    RUN_TEST(TestChannelInputQueueSeriesBind);

    std::fprintf(stderr, "=== ALL PASS ===\n");
    return 0;
}
