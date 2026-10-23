// run_state_renderer_test.cpp
//
// Step 5.5 — renderer channel rows from metric samples.
// Tests the v2 channel row rendering helpers:
//   GatherChannelIds, LookupLifecycleState, SummarizeWorkerLiveness
// and the full channel_snapshot row format produced by RenderRuntimePanel.
//
// Uses MetricRegistry + ChannelMetrics::Bind/PublishFromSnapshot to build a
// realistic SampleMap without manual label construction.

#include "refuzz/telemetry/observation/run_state_renderer.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"
#include "refuzz/core/metrics/channel_metrics.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/metrics/policy_state_publisher.hpp"
#include "refuzz/core/runtime_state.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using refuzz::core::RuntimeSnapshot;
using refuzz::core::metrics::MetricRegistry;
using refuzz::core::metrics::ChannelMetrics;
using refuzz::telemetry::RunStateStore;

namespace cc = refuzz::core::channel_contract;

// ─────────────────────────────────────────────────────────────────────────────
// Macros
// ─────────────────────────────────────────────────────────────────────────────

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",               \
                         #cond, __LINE__);                                      \
            return 1;                                                           \
        }                                                                       \
    } while (0)

#define CHECK_MSG(cond, msg)                                                    \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::fprintf(stderr, "CHECK failed: %s (line %d) -- %s\n",         \
                         #cond, __LINE__, (msg));                               \
            return 1;                                                           \
        }                                                                       \
    } while (0)

#define RUN_TEST(fn)                                                            \
    do {                                                                        \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                             \
        int rc = fn();                                                          \
        if (rc != 0) {                                                          \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                        \
            return rc;                                                          \
        }                                                                       \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                            \
    } while (0)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Build a minimal RuntimeSnapshot with ts_us set so the renderer won't early-exit.
static RuntimeSnapshot MakeSnapshot()
{
    RuntimeSnapshot snap;
    snap.ts_us = 1000;
    snap.policy_phase = "normal";
    snap.policy_switch_count = 0;
    return snap;
}

// Build a SampleMap from a MetricRegistry by collecting ALL samples.
// Previously collected only "channel." prefix; extended to collect everything
// so that fuzzer.current_policy (and future prefixes) are also included.
// Existing tests are unaffected: they only assert on substrings; extra samples
// in the map do not change what they check.
static RunStateStore::SampleMap BuildSampleMap(const MetricRegistry& registry)
{
    auto samples = registry.Collect();
    RunStateStore::SampleMap m;
    for (auto& s : samples) {
        RunStateStore::SampleKey key{s.name, s.labels};
        m.emplace(std::move(key), std::move(s));
    }
    return m;
}

// [6b-3 — 当前版本] ChannelSnapshot 内嵌子结构已移除, 测试辅助聚合 snap + 3 parts
struct ChannelSnapPack {
    cc::ChannelSnapshot snap;
    cc::ChannelRuntimeSnapshot runtime;
    cc::HealthMonitorSnapshot health;
    cc::ChannelRecoverySnapshot recovery;
};

static ChannelSnapPack MakeChannelSnap(uint32_t channel_id,
                                       cc::ChannelLifecycleState state,
                                       uint64_t generation,
                                       uint32_t total_slots,
                                       uint32_t free_slots,
                                       uint32_t inflight)
{
    ChannelSnapPack pack;
    pack.snap.channel_id = channel_id;
    pack.snap.lifecycle_state = state;
    pack.snap.generation = generation;
    pack.runtime.total_slots = total_slots;
    pack.runtime.free_slots = free_slots;
    pack.runtime.inflight = inflight;
    pack.health.sampled_ts_us = 99999;
    return pack;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 0 — 一 worker 一行 + stall 是连续量
//
// [心跳重定义] is_alive 是判死之后的终态,判死要等满 silent_budget_s(300s)。只报
// alive/dead 的话面板就是"299s 一直 alive,然后啪一下 dead" —— stall 没有过程可看。
// 这里锁住的是:同样的 is_alive=true,靠 silent_s / recovering / slot 能渲出**不同**的
// 状态,且状态是单调推进的(running → stalling → dead),不跳变。
//
// 尤其 recovering:daemon 只要活着,程序 hang 到点必然去轮换 domain(proc_epoch +1)。
// "静默但 epoch 在涨" = 它活着、正在自救、卡的是被测程序(合法,最长 65s);
// "静默且 epoch 冻着" = 连自救都没做 = 卡的是 daemon 自己。两者处置完全不同。
// ─────────────────────────────────────────────────────────────────────────────

static int TestPerWorkerRows()
{
    MetricRegistry registry;
    ChannelMetrics m{};
    m.Bind(registry, /*channel_id=*/0);

    auto pack = MakeChannelSnap(0, cc::ChannelLifecycleState::kRunning, 1, 6, 2, 4);

    auto mk = [](uint32_t id, bool alive, uint32_t silent_s, uint32_t epoch,
                 bool recovering, cc::WorkerSlotState slot) {
        cc::WorkerLivenessEntry e;
        e.worker_id       = id;
        e.is_alive        = alive;
        e.silent_s        = silent_s;
        e.silent_budget_s = 300;
        e.proc_epoch      = epoch;
        e.recovering      = recovering;
        e.slot            = slot;
        return e;
    };
    // 正常跑
    pack.health.worker_liveness.push_back(
        mk(0, true, 0, 3, false, cc::WorkerSlotState::kExecuting));
    // 手上没活 —— 令牌静止是正确行为,不是故障
    pack.health.worker_liveness.push_back(
        mk(1, true, 0, 0, false, cc::WorkerSlotState::kEmpty));
    // daemon 在自救:静默 18s 但 epoch 涨到 7 → 卡的是被测程序,合法
    pack.health.worker_liveness.push_back(
        mk(2, true, 18, 7, true, cc::WorkerSlotState::kExecuting));
    // 真可疑:静默 142s、epoch 冻着、且活派下去没人取(daemon 的取活循环是 1ms 级的)
    pack.health.worker_liveness.push_back(
        mk(3, true, 142, 2, false, cc::WorkerSlotState::kDispatched));
    // 已判死
    pack.health.worker_liveness.push_back(
        mk(4, false, 300, 2, false, cc::WorkerSlotState::kExecuting));

    m.PublishFromSnapshot(pack.snap, pack.runtime, pack.health, pack.recovery, registry);

    const auto sample_map = BuildSampleMap(registry);
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        MakeSnapshot(), sample_map, {}, "");

    // 这一条同时钉住 CounterValue 必须先 NormalizeLabels:注册侧(GaugeOf)按 key 排序后
    //   入 key,而 CounterValue 是精确 find —— 按语义顺序写的 {channel_id, worker_id,
    //   state} 与存进去的 {channel_id, state, worker_id} 不是同一个 key,会**静默**查不中
    //   返回 0 → alive=false → 每个 worker 都渲成 dead。历史调用方碰巧都传有序 label,
    //   所以这个坑一直没暴露,加 worker 行时才踩中。
    CHECK_MSG(out.find("worker channel=0 id=0 state=running slot=executing"
                       " silent=0s/300s proc_epoch=3") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("worker channel=0 id=1 state=idle slot=empty"
                       " silent=0s/300s proc_epoch=0") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("worker channel=0 id=2 state=recovering slot=executing"
                       " silent=18s/300s proc_epoch=7") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("worker channel=0 id=3 state=stalling slot=dispatched"
                       " silent=142s/300s proc_epoch=2") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("worker channel=0 id=4 state=dead slot=executing"
                       " silent=300s/300s proc_epoch=2") != std::string::npos, out.c_str());
    // channel 行保留 alive/total 概览(channel 多起来时才有俯瞰)
    CHECK_MSG(out.find("health=workers=4/5") != std::string::npos, out.c_str());
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — ChannelRowFromSamples
// One channel with known values → verify rendered string field by field.
// ─────────────────────────────────────────────────────────────────────────────

static int TestChannelRowFromSamples()
{
    MetricRegistry registry;
    ChannelMetrics m{};
    m.Bind(registry, /*channel_id=*/0);

    auto pack = MakeChannelSnap(0,
        cc::ChannelLifecycleState::kRunning,
        /*generation=*/3,
        /*total_slots=*/8, /*free_slots=*/5, /*inflight=*/3);
    pack.health.sampled_ts_us = 54321;
    pack.health.worker_liveness.push_back({0, /*is_alive=*/true});
    m.PublishFromSnapshot(pack.snap, pack.runtime, pack.health, pack.recovery, registry);

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();

    // RenderRuntimePanel with empty events
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    // Check for the channel_snapshot line
    CHECK_MSG(out.find("channel_snapshot id=0") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("lifecycle=running") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("generation=3") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("booted=1") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("slots=8") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("free_slots=5") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("inflight=3") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("health=workers=1/1") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find(",k=0,v=0,w=0,i=0") != std::string::npos,
              out.c_str());
    CHECK_MSG(out.find("sampled_ts_us=54321") != std::string::npos,
              out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — MultipleChannelsSortedByID
// 3 channels with IDs 3, 1, 2 → rendered in order 1, 2, 3.
// ─────────────────────────────────────────────────────────────────────────────

static int TestMultipleChannelsSortedByID()
{
    MetricRegistry registry;

    ChannelMetrics m3{}, m1{}, m2{};
    m3.Bind(registry, 3);
    m1.Bind(registry, 1);
    m2.Bind(registry, 2);

    auto p3 = MakeChannelSnap(3, cc::ChannelLifecycleState::kRunning,  1, 4, 4, 0);
    auto p1 = MakeChannelSnap(1, cc::ChannelLifecycleState::kBooting,  0, 0, 0, 0);
    auto p2 = MakeChannelSnap(2, cc::ChannelLifecycleState::kDegraded, 2, 8, 2, 6);

    m3.PublishFromSnapshot(p3.snap, p3.runtime, p3.health, p3.recovery, registry);
    m1.PublishFromSnapshot(p1.snap, p1.runtime, p1.health, p1.recovery, registry);
    m2.PublishFromSnapshot(p2.snap, p2.runtime, p2.health, p2.recovery, registry);

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    // Find positions
    const auto pos1 = out.find("channel_snapshot id=1");
    const auto pos2 = out.find("channel_snapshot id=2");
    const auto pos3 = out.find("channel_snapshot id=3");

    CHECK_MSG(pos1 != std::string::npos, out.c_str());
    CHECK_MSG(pos2 != std::string::npos, out.c_str());
    CHECK_MSG(pos3 != std::string::npos, out.c_str());
    CHECK_MSG(pos1 < pos2, "id=1 must come before id=2");
    CHECK_MSG(pos2 < pos3, "id=2 must come before id=3");

    // Also verify lifecycle names rendered correctly
    CHECK_MSG(out.find("lifecycle=booting") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("lifecycle=degraded") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("lifecycle=running") != std::string::npos, out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — MissingChannelSamplesDegradeGracefully
// Bind channel metrics but do NOT call PublishFromSnapshot → all gauges are 0,
// lifecycle is all-zero (no one-hot set) → "unknown", no crash.
// ─────────────────────────────────────────────────────────────────────────────

static int TestMissingChannelSamplesDegradeGracefully()
{
    MetricRegistry registry;
    ChannelMetrics m{};
    m.Bind(registry, 5);
    // Do NOT call PublishFromSnapshot — gauges remain at default (0), counters at 0.

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();

    // Must not crash, must produce sensible output
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    // channel.generation=0 → booted=0
    CHECK_MSG(out.find("channel_snapshot id=5") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("booted=0") != std::string::npos, out.c_str());
    // All lifecycle gauges at 0 → unknown
    CHECK_MSG(out.find("lifecycle=unknown") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("slots=0") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("free_slots=0") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("inflight=0") != std::string::npos, out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — WorkerLivenessAggregation
// 3 workers: 2 alive + 1 dead → health=workers=2/3
// ─────────────────────────────────────────────────────────────────────────────

static int TestWorkerLivenessAggregation()
{
    MetricRegistry registry;
    ChannelMetrics m{};
    m.Bind(registry, 0);

    auto pack = MakeChannelSnap(0,
        cc::ChannelLifecycleState::kRunning, 1, 4, 1, 3);
    pack.health.worker_liveness.push_back({0, /*is_alive=*/true});
    pack.health.worker_liveness.push_back({1, /*is_alive=*/true});
    pack.health.worker_liveness.push_back({2, /*is_alive=*/false});
    m.PublishFromSnapshot(pack.snap, pack.runtime, pack.health, pack.recovery, registry);

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    CHECK_MSG(out.find("health=workers=2/3") != std::string::npos, out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — CrashCounterCumulative
// Crash counters are cumulative (D1=a): large values pass through as-is.
// ─────────────────────────────────────────────────────────────────────────────

static int TestCrashCounterCumulative()
{
    MetricRegistry registry;
    ChannelMetrics m{};
    m.Bind(registry, 0);

    // Manually increment crash counters many times
    constexpr int kKernelCrashes = 1000;
    constexpr int kVmCrashes     = 500;
    constexpr int kWorkerCrashes = 250;
    constexpr int kInternalFaults = 42;
    constexpr int kNoOutputs = 17;

    for (int i = 0; i < kKernelCrashes; ++i) {
        if (m.health_crash[0]) m.health_crash[0]->Inc();
    }
    for (int i = 0; i < kVmCrashes; ++i) {
        if (m.health_crash[1]) m.health_crash[1]->Inc();
    }
    for (int i = 0; i < kWorkerCrashes; ++i) {
        if (m.health_crash[2]) m.health_crash[2]->Inc();
    }
    for (int i = 0; i < kInternalFaults; ++i) {
        if (m.health_crash[3]) m.health_crash[3]->Inc();
    }
    for (int i = 0; i < kNoOutputs; ++i) {
        if (m.health_crash[4]) m.health_crash[4]->Inc();
    }

    // Also call PublishFromSnapshot with some baseline snap — crash counters are
    // source-incremented at the event, never pushed from the snapshot.
    auto pack = MakeChannelSnap(0,
        cc::ChannelLifecycleState::kRunning, 1, 4, 4, 0);
    m.PublishFromSnapshot(pack.snap, pack.runtime, pack.health, pack.recovery, registry);

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    CHECK_MSG(out.find(",k=1000,") != std::string::npos, out.c_str());
    CHECK_MSG(out.find(",v=500,") != std::string::npos, out.c_str());
    CHECK_MSG(out.find(",w=250,") != std::string::npos, out.c_str());
    CHECK_MSG(out.find(",i=42 ") != std::string::npos, out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 — NoChannelSamples → no channel_snapshot line
// If no channel.* metrics are in the registry, no channel row is rendered.
// ─────────────────────────────────────────────────────────────────────────────

static int TestNoChannelSamplesProducesNoRow()
{
    // Empty SampleMap
    const RunStateStore::SampleMap sample_map;
    const RuntimeSnapshot rt_snap = MakeSnapshot();
    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    CHECK_MSG(out.find("channel_snapshot") == std::string::npos, out.c_str());

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7 — LifecycleOneHot all states
// Verify that each of the 7 lifecycle states round-trips through metric →
// LookupLifecycleState → renderer correctly.
// ─────────────────────────────────────────────────────────────────────────────

static int TestLifecycleStateAllValues()
{
    struct Case { cc::ChannelLifecycleState state; const char* expected; };
    static const Case kCases[] = {
        { cc::ChannelLifecycleState::kStopped,    "stopped"    },
        { cc::ChannelLifecycleState::kBooting,    "booting"    },
        { cc::ChannelLifecycleState::kRunning,    "running"    },
        { cc::ChannelLifecycleState::kDegraded,   "degraded"   },
        { cc::ChannelLifecycleState::kRecovering, "recovering" },
        { cc::ChannelLifecycleState::kFailed,     "failed"     },
        { cc::ChannelLifecycleState::kClosed,     "closed"     },
    };

    for (const auto& c : kCases) {
        MetricRegistry registry;
        ChannelMetrics m{};
        m.Bind(registry, 0);

        auto pack = MakeChannelSnap(0, c.state, 1, 4, 4, 0);
        m.PublishFromSnapshot(pack.snap, pack.runtime, pack.health, pack.recovery, registry);

        const auto sample_map = BuildSampleMap(registry);
        const RuntimeSnapshot rt_snap = MakeSnapshot();
        const std::string out = refuzz::telemetry::RenderRuntimePanel(
            rt_snap, sample_map, {}, "");

        std::string expected_field = std::string("lifecycle=") + c.expected;
        CHECK_MSG(out.find(expected_field) != std::string::npos,
                  (std::string("Expected '") + expected_field + "' in: " + out).c_str());
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8 — PoliciesRowFromSamples (6b-2)
// Publish 3 policy kinds via PolicyStatePublisher and verify the rendered
// "policies mutation=... scheduling=... corpus=..." line reflects them.
// Note: renderer output key is "scheduling=" (backward-compat) while the
//       metric kind label is "schedule".
// ─────────────────────────────────────────────────────────────────────────────

static int TestPoliciesRowFromSamples()
{
    MetricRegistry registry;

    refuzz::core::metrics::PolicyStatePublisher pub;
    pub.Bind(registry);
    pub.Set("mutation", "havoc");
    pub.Set("schedule", "priority");
    pub.Set("corpus",   "cov_guided");

    const auto sample_map = BuildSampleMap(registry);
    const RuntimeSnapshot rt_snap = MakeSnapshot();

    const std::string out = refuzz::telemetry::RenderRuntimePanel(
        rt_snap, sample_map, {}, "");

    CHECK_MSG(out.find("policies mutation=havoc") != std::string::npos, out.c_str());
    CHECK_MSG(out.find("scheduling=priority")     != std::string::npos, out.c_str());
    CHECK_MSG(out.find("corpus=cov_guided")       != std::string::npos, out.c_str());

    return 0;
}

// [6b-3 — 当前版本] Test 9 (ExecChannelRowRemoved) 已删除:
//   RuntimeSnapshot.executor 字段 + ChannelSnapshotEntry 类型随 ExecutorSnapshot 一起移除,
//   exec_channel 行在 6b-2 时已从 renderer 拿掉, 本断言已无独立意义。

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    std::fprintf(stderr, "=== run_state_renderer_test ===\n");

    RUN_TEST(TestPerWorkerRows);
    RUN_TEST(TestChannelRowFromSamples);
    RUN_TEST(TestMultipleChannelsSortedByID);
    RUN_TEST(TestMissingChannelSamplesDegradeGracefully);
    RUN_TEST(TestWorkerLivenessAggregation);
    RUN_TEST(TestCrashCounterCumulative);
    RUN_TEST(TestNoChannelSamplesProducesNoRow);
    RUN_TEST(TestLifecycleStateAllValues);
    RUN_TEST(TestPoliciesRowFromSamples);

    std::fprintf(stderr, "=== ALL PASS ===\n");
    return 0;
}
