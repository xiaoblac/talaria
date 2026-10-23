// channel_input_queue_metric_test.cpp
//
// 验证 020_naming_catalog §4.6 的 channel.input_queue.* 5 条 series 在
// Channel 层接通后的 end-to-end 行为,以及 deferred_count_ 不变量。
//
// 关键测试:
//   - cap=4 small-cap 场景:用 BackpressuredTestDataPlane 强制所有 Submit kBusy,
//     灌远多于 cap 的请求,断言 depth <= capacity 永真 (覆盖搬迁/erase 同步窗口)。
//   - busy_rejects 单调递增, full_episodes >= 1, full_us 在解锁后 > 0。
//   - capacity gauge == cfg 值 (Attach 后)。
//
// 使用裸 CHECK + RUN_TEST 宏,与 channel_completion_wakeup_test.cpp 风格对齐。

#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"
#include "refuzz/core/metrics/channel_metrics.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace cc = refuzz::core::channel_contract;
namespace ch = refuzz::channel;
namespace data = refuzz::channel::data;
namespace factory = refuzz::channel::factory;
namespace health = refuzz::channel::health;
namespace recovery = refuzz::channel::recovery;
namespace metrics = refuzz::core::metrics;

namespace {

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

#define RUN_TEST(fn)                                                               \
    do {                                                                           \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                                \
        const int rc = fn();                                                       \
        if (rc != 0) {                                                             \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                           \
            return rc;                                                             \
        }                                                                          \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                               \
    } while (0)

// ─────────────────────────────────────────────────────────────────────
// BackpressuredTestDataPlane
//   block_submit_=true  → Submit() 永远 kBusy,稳定造 backlog;
//   block_submit_=false → kSent (并把请求记到 last_*,测试可手工 CompleteLast)。
// ─────────────────────────────────────────────────────────────────────

class BackpressuredTestDataPlane final : public data::IDataPlane {
public:
    void SetBlockSubmit(bool block) noexcept
    {
        block_submit_.store(block, std::memory_order_relaxed);
    }

    ch::Result<void> Prepare() override { return ch::Result<void>::Ok(); }
    void Close() override
    {
        closed_.store(true, std::memory_order_release);
        WakePoller();
    }
    void Pause() override {}
    void Resume() override {}

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput& req) override
    {
        if (block_submit_.load(std::memory_order_relaxed)) {
            return data::SubmitOutcome::kBusy;
        }
        {
            std::lock_guard<std::mutex> lock(mu_);
            last_executor_id_ = req.executor_id;
            last_dispatch_gen_ = req.dispatch_gen;
            ++submit_count_;
        }
        cv_.notify_all();
        return data::SubmitOutcome::kSent;
    }

    void Poll(std::vector<data::DispatchOutcome>& out,
              std::chrono::microseconds timeout) override
    {
        std::unique_lock<std::mutex> lock(mu_);
        if (timeout > std::chrono::microseconds{0} &&
            completions_.empty() && !wake_pending_ &&
            !closed_.load(std::memory_order_acquire)) {
            cv_.wait_for(lock, timeout, [this] {
                return !completions_.empty() || wake_pending_ ||
                       closed_.load(std::memory_order_acquire);
            });
        }
        while (!completions_.empty()) {
            out.push_back(std::move(completions_.front()));
            completions_.pop_front();
        }
        wake_pending_ = false;
    }

    void WakePoller() noexcept override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            wake_pending_ = true;
        }
        cv_.notify_all();
    }

    void ResetWorker(uint32_t) override {}
    void ResetAll() override {}
    std::vector<data::InflightEntry> SnapshotInflight() const override { return {}; }
    bool IsPaused() const noexcept override { return false; }
    bool IsClosed() const noexcept override
    {
        return closed_.load(std::memory_order_acquire);
    }
    uint32_t MaxWorkerSlots() const noexcept override { return 1; }
    bool IsWorkerSendable(uint32_t worker_id) const override { return worker_id == 0; }

    void CompleteLast()
    {
        data::DispatchOutcome outcome;
        {
            std::lock_guard<std::mutex> lock(mu_);
            outcome.worker_id = 0;
            outcome.executor_id = last_executor_id_;
            outcome.dispatch_gen = last_dispatch_gen_;
            outcome.kind = data::DispatchOutcomeKind::kOk;
            completions_.push_back(std::move(outcome));
            wake_pending_ = true;
        }
        cv_.notify_all();
    }

private:
    std::atomic<bool> block_submit_{true};
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<data::DispatchOutcome> completions_;
    uint32_t submit_count_ = 0;
    uint64_t last_executor_id_ = 0;
    uint32_t last_dispatch_gen_ = 0;
    bool wake_pending_ = false;
    std::atomic<bool> closed_{false};
};

// ─────────────────────────────────────────────────────────────────────
// Minimal Health / Recovery stubs
// ─────────────────────────────────────────────────────────────────────

class MinimalHealthMonitor final : public health::IHealthMonitor {
public:
    ch::Result<void> Start() override { return ch::Result<void>::Ok(); }
    void Stop() noexcept override {}
    void AddSensor(std::unique_ptr<health::IHealthSensor>) override {}
    void BindChannelSignals(health::HealthMonitorView) noexcept override {}
    void SetWorkerAlive(uint32_t, bool) noexcept override {}
    void RearmSingleWorker(uint32_t) override {}
    bool HasPendingCrashEvents() const noexcept override { return false; }
    std::vector<health::CrashEvent> DrainCrashEvents() override { return {}; }
    void SuspendMonitoring() override {}
    void ResumeMonitoring() override {}
    ch::Result<void> Reboot() override { return ch::Result<void>::Ok(); }
    cc::HealthMonitorSnapshot GetSnapshot() const override { return {}; }
};

class MinimalRecovery final : public recovery::IRecovery {
public:
    recovery::RecoveryObservationResult ObserveFault(
        uint64_t,
        cc::ChannelFaultReason,
        cc::ChannelFaultSource,
        const recovery::FaultContext&) override
    {
        recovery::RecoveryObservationResult r;
        r.accepted = true;
        r.abort_scope = cc::ChannelAbortScope::kNone;
        r.recovery_action = cc::RecoveryAction::kNone;
        return r;
    }
    ch::Result<recovery::RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason, cc::RecoveryAction, uint32_t) override
    {
        return ch::Result<recovery::RecoveryResult>::Ok(recovery::RecoveryResult{});
    }
    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override { return true; }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}
    void NoteHealthy() override {}
    recovery::RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}
};

// ─────────────────────────────────────────────────────────────────────
// Harness — Build channel(cap=4) + Attach metrics 在 Boot 之前
// ─────────────────────────────────────────────────────────────────────

struct Harness {
    metrics::MetricRegistry              registry;
    metrics::ChannelMetrics              channel_metrics;
    BackpressuredTestDataPlane*          dp = nullptr;
    std::unique_ptr<ch::Channel>         channel;

    ~Harness()
    {
        if (channel) channel->Close();
    }
};

std::unique_ptr<Harness> MakeHarness(uint32_t channel_id, std::size_t cap)
{
    auto h = std::make_unique<Harness>();

    auto dp = std::make_unique<BackpressuredTestDataPlane>();
    h->dp = dp.get();

    ch::ChannelComponents components;
    components.substrate = std::make_unique<factory::MockSubstrate>();
    components.control   = std::make_unique<factory::MockControlPlane>(1);
    components.data      = std::move(dp);
    components.console   = std::make_unique<factory::NullConsoleSource>();
    components.health    = std::make_unique<MinimalHealthMonitor>();
    components.recovery  = std::make_unique<MinimalRecovery>();
    components.channel_cfg.channel_id = channel_id;
    components.channel_cfg.n_workers  = 1;
    components.channel_cfg.backend_id = "input_queue_metric_test";
    components.channel_cfg.loop_interval = std::chrono::milliseconds{20};
    components.channel_cfg.health_check_interval = std::chrono::seconds{10};
    components.channel_cfg.input_queue_capacity = cap;
    // [payload-bound fail-closed] Channel::Submit 现对 payload.size() > max_payload 返 kInvalid;
    // mock substrate 无 shm_,故必须走 config-driven 上界(否则 max_payload=0 → 所有非空
    // payload 被拒成 kInvalid → 请求永不入队,input-queue 背压/episode 全测不到)。
    components.channel_cfg.max_payload_size = 65536;

    auto built = ch::ChannelBuilder::Build(std::move(components));
    if (!built.ok()) {
        std::fprintf(stderr, "ChannelBuilder failed: %s\n",
                     built.error().message.c_str());
        return nullptr;
    }
    h->channel = std::move(built.value());

    // Bind metrics 然后 Attach BEFORE Boot — capacity gauge / Inc 都依赖 metrics_
    // 在主路径 publish 之前已经注入。
    h->channel_metrics.Bind(h->registry, channel_id);
    h->channel->AttachObservabilityPublishers(
        /*snapshot_bus=*/nullptr,
        /*event_bus=*/nullptr,
        &h->channel_metrics,
        &h->registry);

    auto boot = h->channel->Boot();
    if (!boot.ok()) {
        std::fprintf(stderr, "Channel::Boot failed: %s\n",
                     boot.error().message.c_str());
        return nullptr;
    }
    return h;
}

cc::ChannelDispatchRequest MakeRequest(uint64_t executor_id)
{
    cc::ChannelDispatchRequest req;
    req.executor_id    = executor_id;
    req.seed_id        = 0;
    req.origin_seed_id = 0;
    req.payload        = {0xAA, 0xBB};
    return req;
}

// ─────────────────────────────────────────────────────────────────────
// Test 1 — 契约校验:cap=0 / cap>UINT32_MAX 在 Builder 处被拒
// ─────────────────────────────────────────────────────────────────────

int TestBuilderRejectsInvalidCapacity()
{
    auto make_components = [](std::size_t cap) {
        ch::ChannelComponents components;
        components.substrate = std::make_unique<factory::MockSubstrate>();
        components.control   = std::make_unique<factory::MockControlPlane>(1);
        components.data      = std::make_unique<BackpressuredTestDataPlane>();
        components.console   = std::make_unique<factory::NullConsoleSource>();
        components.health    = std::make_unique<MinimalHealthMonitor>();
        components.recovery  = std::make_unique<MinimalRecovery>();
        components.channel_cfg.channel_id = 999;
        components.channel_cfg.n_workers  = 1;
        components.channel_cfg.backend_id = "invalid_cap_test";
        components.channel_cfg.input_queue_capacity = cap;
        return components;
    };

    {
        auto built = ch::ChannelBuilder::Build(make_components(0));
        CHECK(!built.ok());
    }
    {
        const std::size_t too_big =
            static_cast<std::size_t>(std::numeric_limits<uint32_t>::max()) + 1u;
        auto built = ch::ChannelBuilder::Build(make_components(too_big));
        CHECK(!built.ok());
    }
    {
        // 边界值 1 / UINT32_MAX 应被接受
        auto built1 = ch::ChannelBuilder::Build(make_components(1));
        CHECK(built1.ok());
        auto builtMax = ch::ChannelBuilder::Build(
            make_components(static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())));
        CHECK(builtMax.ok());
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// Test 2 — capacity gauge 在 Attach 后等于 cfg 值 (cap=4)
// ─────────────────────────────────────────────────────────────────────

int TestCapacityGaugeReflectsCfg()
{
    auto h = MakeHarness(/*channel_id=*/1, /*cap=*/4);
    CHECK(h != nullptr);

    CHECK(h->channel_metrics.input_queue_capacity != nullptr);
    CHECK(h->channel_metrics.input_queue_capacity->Value() == 4);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// Test 3 — 核心:cap=4,灌 32 个 Submit (DP 全 kBusy),断言:
//   - depth 永远 <= capacity (覆盖 deferred_count_ 同步窗口)
//   - full_episodes >= 1, busy_rejects > 0 (kBusy DP 制造稳定饱和)
//   - 所有 counter 单调
// ─────────────────────────────────────────────────────────────────────

int TestSmallCapDepthInvariantUnderBackpressure()
{
    auto h = MakeHarness(/*channel_id=*/2, /*cap=*/4);
    CHECK(h != nullptr);
    h->dp->SetBlockSubmit(true);  // (默认就是 true,显式表达意图)

    auto* depth_g     = h->channel_metrics.input_queue_depth;
    auto* cap_g       = h->channel_metrics.input_queue_capacity;
    auto* episodes_c  = h->channel_metrics.input_queue_full_episodes;
    auto* rejects_c   = h->channel_metrics.input_queue_busy_rejects;
    auto* full_us_c   = h->channel_metrics.input_queue_full_us;
    CHECK(depth_g && cap_g && episodes_c && rejects_c && full_us_c);

    uint64_t prev_episodes = 0;
    uint64_t prev_rejects  = 0;
    uint64_t prev_full_us  = 0;

    for (uint64_t i = 1; i <= 64; ++i) {
        h->channel->Submit(MakeRequest(i),
                           std::chrono::microseconds{0});

        // 不变量:depth ∈ [0, capacity]
        const int64_t d = depth_g->Value();
        CHECK(d >= 0);
        CHECK(d <= cap_g->Value());

        // counter 单调
        const uint64_t e = episodes_c->Value();
        const uint64_t r = rejects_c->Value();
        const uint64_t u = full_us_c->Value();
        CHECK(e >= prev_episodes);
        CHECK(r >= prev_rejects);
        CHECK(u >= prev_full_us);
        prev_episodes = e;
        prev_rejects  = r;
        prev_full_us  = u;

        // 给 loop 一点时间搬迁/试发(虽然 dp.Submit 全 kBusy,但 drain 仍会跑一遍)
        std::this_thread::sleep_for(std::chrono::microseconds{100});
    }

    // backlog 一定有,depth>0 或者已经累计过 episode
    CHECK(episodes_c->Value() >= 1u);
    CHECK(rejects_c->Value()  >= 1u);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────
// Test 4 — 解锁 backpressure 后 full_us 应增加 (有 episode 退出),
//          depth 最终回到 0。
// ─────────────────────────────────────────────────────────────────────

int TestFullUsAccumulatesOnEpisodeExit()
{
    auto h = MakeHarness(/*channel_id=*/3, /*cap=*/4);
    CHECK(h != nullptr);
    h->dp->SetBlockSubmit(true);

    // 先灌满制造一个饱和 episode
    for (uint64_t i = 1; i <= 16; ++i) {
        h->channel->Submit(MakeRequest(i), std::chrono::microseconds{0});
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    auto* episodes_c = h->channel_metrics.input_queue_full_episodes;
    auto* full_us_c  = h->channel_metrics.input_queue_full_us;
    CHECK(episodes_c->Value() >= 1u);

    const uint64_t full_us_before = full_us_c->Value();

    // 解锁 → loop 会把 deferred 全部发出 → cur < cap → 退出边沿 → full_us +=
    h->dp->SetBlockSubmit(false);
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    CHECK(full_us_c->Value() > full_us_before);
    return 0;
}

}  // namespace

int main()
{
    std::fprintf(stderr, "=== channel_input_queue_metric_test ===\n");

    RUN_TEST(TestBuilderRejectsInvalidCapacity);
    RUN_TEST(TestCapacityGaugeReflectsCfg);
    RUN_TEST(TestSmallCapDepthInvariantUnderBackpressure);
    RUN_TEST(TestFullUsAccumulatesOnEpisodeExit);

    std::fprintf(stderr, "=== ALL PASS ===\n");
    return 0;
}
