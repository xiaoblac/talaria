// channel_target_worker_affinity_test — locks in the ChannelDispatchRequest.
// target_worker_id contract (PR3 step 2):
//
//   1. target_worker_id == kAnyWorkerId (default) → existing round-robin.
//   2. target_worker_id < n_workers (strict affinity) → only that slot ever
//      sees the Submit; no fallback.
//   3. target_worker_id >= n_workers → Submit returns kInvalid (caller bug
//      surfaced up front, no queue insertion).
//
// Uses the same lightweight harness shape as channel_completion_wakeup_test
// (real ShmInfra + ChannelBuilder, mock substrate/control/health/recovery)
// but with a multi-worker RecordingDataPlane that captures per-Submit
// worker_id for assertion.

#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"
#include "refuzz/proto_wire/error_codes.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace cc = refuzz::core::channel_contract;
namespace ch = refuzz::channel;
namespace data = refuzz::channel::data;
namespace factory = refuzz::channel::factory;
namespace health = refuzz::channel::health;
namespace infra = refuzz::channel::infra;
namespace recovery = refuzz::channel::recovery;

namespace {

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                            \
        }                                                                        \
    } while (0)

#define RUN_TEST(fn)                                                             \
    do {                                                                         \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                              \
        const int rc = fn();                                                     \
        if (rc != 0) {                                                           \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                         \
            return rc;                                                           \
        }                                                                        \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                             \
    } while (0)

std::string TempPath(const char* suffix) {
    std::string path = "/tmp/refuzz_affinity_test_";
    path += suffix;
    path += "_";
    path += std::to_string(::getpid());
    return path;
}

std::shared_ptr<infra::ShmInfra> MakeShm(const std::string& path, uint32_t n_workers) {
    infra::InfraConfig cfg;
    cfg.shm_path = path;
    cfg.n_workers = n_workers;
    auto shm = std::make_shared<infra::ShmInfra>(std::move(cfg));
    auto r = shm->Init();
    if (!r.ok()) {
        std::fprintf(stderr, "ShmInfra::Init failed: %s\n", r.error().message.c_str());
        return nullptr;
    }
    return shm;
}

// IDataPlane mock that exposes n_workers via constructor and records the
// worker_id of every Submit call. Drain/Poll are no-ops — affinity tests
// inspect the Submit-side path before any completion plumbing matters.
class RecordingDataPlane final : public data::IDataPlane {
public:
    explicit RecordingDataPlane(uint32_t n_workers) : n_workers_(n_workers) {}

    ch::Result<void> Prepare() override { return ch::Result<void>::Ok(); }
    void Close() override {
        closed_.store(true, std::memory_order_release);
        WakePoller();
    }
    void Pause() override {}
    void Resume() override {}

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput& req) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            submits_.push_back(SubmitRecord{req.worker_id, req.proc_id,
                                            req.executor_id, req.dispatch_gen});
        }
        cv_.notify_all();
        return data::SubmitOutcome::kSent;
    }

    void Poll(std::vector<data::DispatchOutcome>& out,
              std::chrono::microseconds timeout) override {
        std::unique_lock<std::mutex> lock(mu_);
        if (timeout > std::chrono::microseconds{0} &&
            outcomes_.empty() && !wake_pending_ &&
            !closed_.load(std::memory_order_acquire)) {
            cv_.wait_for(lock, timeout, [this] {
                return !outcomes_.empty() || wake_pending_ ||
                       closed_.load(std::memory_order_acquire);
            });
        }
        while (!outcomes_.empty()) {
            out.push_back(std::move(outcomes_.front()));
            outcomes_.pop_front();
        }
        wake_pending_ = false;
    }

    void WakePoller() noexcept override {
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
    bool IsClosed() const noexcept override {
        return closed_.load(std::memory_order_acquire);
    }
    uint32_t MaxWorkerSlots() const noexcept override { return n_workers_; }
    bool IsWorkerSendable(uint32_t worker_id) const override {
        return worker_id < n_workers_;
    }

    struct SubmitRecord {
        uint32_t worker_id;
        uint32_t proc_id;
        uint64_t executor_id;
        uint32_t dispatch_gen;
    };

    std::vector<SubmitRecord> WaitForSubmits(uint32_t count,
                                              std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait_for(lock, timeout, [this, count] {
            return submits_.size() >= count;
        });
        return submits_;
    }

    void PublishOutcome(data::DispatchOutcome outcome) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            outcomes_.push_back(std::move(outcome));
            wake_pending_ = true;
        }
        cv_.notify_all();
    }

private:
    uint32_t n_workers_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<SubmitRecord> submits_;
    std::deque<data::DispatchOutcome> outcomes_;
    bool wake_pending_ = false;
    std::atomic<bool> closed_{false};
};

// Minimal HealthMonitor that never fires events. Channel's loop polls
// HasPendingCrashEvents which we keep false — no recovery interference
// with the affinity-only tests. Mirrors ManualHealthMonitor in
// channel_completion_wakeup_test.cpp but without the publish-worker-dead
// machinery (tests here don't drive crashes).
class StubHealthMonitor final : public health::IHealthMonitor {
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

class StubRecovery final : public recovery::IRecovery {
public:
    recovery::RecoveryObservationResult ObserveFault(
        uint64_t, cc::ChannelFaultReason, cc::ChannelFaultSource,
        const recovery::FaultContext&) override {
        recovery::RecoveryObservationResult r;
        r.accepted = true;
        r.abort_scope = cc::ChannelAbortScope::kNone;
        r.recovery_action = cc::RecoveryAction::kNone;
        return r;
    }
    ch::Result<recovery::RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason, cc::RecoveryAction, uint32_t) override {
        return ch::Result<recovery::RecoveryResult>::Ok(recovery::RecoveryResult{});
    }
    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override {
        return true;
    }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}
    void NoteHealthy() override {}
    recovery::RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}
};

struct ChannelHarness {
    ~ChannelHarness() {
        if (channel) channel->Close();
        if (!shm_path.empty()) ::unlink(shm_path.c_str());
    }
    std::string shm_path;
    std::shared_ptr<infra::ShmInfra> shm;
    RecordingDataPlane* dp = nullptr;
    std::unique_ptr<ch::IChannel> channel;
};

std::unique_ptr<ChannelHarness> MakeChannelHarness(uint32_t channel_id,
                                                    uint32_t n_workers,
                                                    const std::string& tag) {
    auto harness = std::make_unique<ChannelHarness>();
    harness->shm_path = TempPath(tag.c_str());
    harness->shm = MakeShm(harness->shm_path, n_workers);
    if (!harness->shm) return nullptr;

    auto dp = std::make_unique<RecordingDataPlane>(n_workers);
    harness->dp = dp.get();

    ch::ChannelComponents components;
    components.shm = harness->shm;
    components.substrate = std::make_unique<factory::MockSubstrate>();
    components.control = std::make_unique<factory::MockControlPlane>(n_workers);
    components.data = std::move(dp);
    components.console = std::make_unique<factory::NullConsoleSource>();
    components.health = std::make_unique<StubHealthMonitor>();
    components.recovery = std::make_unique<StubRecovery>();
    components.channel_cfg.channel_id = channel_id;
    components.channel_cfg.n_workers = n_workers;
    components.channel_cfg.backend_id = "affinity_test";
    components.channel_cfg.loop_interval = std::chrono::milliseconds{50};
    components.channel_cfg.health_check_interval = std::chrono::seconds{10};
    components.channel_cfg.input_queue_capacity = 16;

    auto built = ch::ChannelBuilder::Build(std::move(components));
    if (!built.ok()) {
        std::fprintf(stderr, "ChannelBuilder failed: %s\n", built.error().message.c_str());
        return nullptr;
    }
    harness->channel = std::move(built.value());
    auto boot = harness->channel->Boot();
    if (!boot.ok()) {
        std::fprintf(stderr, "Channel::Boot failed: %s\n", boot.error().message.c_str());
        return nullptr;
    }
    return harness;
}

cc::ChannelDispatchRequest MakeReq(uint64_t executor_id,
                                    uint32_t target_worker_id) {
    cc::ChannelDispatchRequest req;
    req.executor_id = executor_id;
    req.seed_id = executor_id;
    req.payload = {static_cast<uint8_t>(executor_id & 0xFF)};
    req.target_worker_id = target_worker_id;
    return req;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// Default target_worker_id == kAnyWorkerId: Channel uses existing round-robin
// across n_workers. We don't pin the exact starting slot (impl detail), but
// across 4 submits onto a 2-worker channel the per-worker counts must be 2
// each (perfect alternation).
int TestRoundRobinUnchangedWhenAnyWorker() {
    constexpr uint32_t kN = 2;
    auto h = MakeChannelHarness(/*channel_id=*/1, kN, "rr");
    CHECK(h != nullptr);

    for (uint64_t i = 1; i <= 4; ++i) {
        auto r = h->channel->Submit(MakeReq(i, cc::kAnyWorkerId),
                                    std::chrono::microseconds{0});
        CHECK(r.status == cc::ChannelSubmitStatus::kAccepted);
    }
    auto subs = h->dp->WaitForSubmits(4, std::chrono::milliseconds{500});
    CHECK(subs.size() == 4);
    uint32_t counts[kN] = {0, 0};
    for (auto& s : subs) {
        CHECK(s.worker_id < kN);
        counts[s.worker_id]++;
    }
    CHECK(counts[0] == 2);
    CHECK(counts[1] == 2);
    return 0;
}

// Strict affinity to a single worker: every submit must go to the same slot,
// no round-robin bleed even when other workers are free.
int TestStrictAffinityRoutesAllToTarget() {
    constexpr uint32_t kN = 3;
    auto h = MakeChannelHarness(/*channel_id=*/2, kN, "strict");
    CHECK(h != nullptr);

    constexpr uint32_t kTarget = 1;
    for (uint64_t i = 100; i < 105; ++i) {
        auto r = h->channel->Submit(MakeReq(i, kTarget),
                                    std::chrono::microseconds{0});
        CHECK(r.status == cc::ChannelSubmitStatus::kAccepted);
    }
    auto subs = h->dp->WaitForSubmits(5, std::chrono::milliseconds{500});
    CHECK(subs.size() == 5);
    for (auto& s : subs) {
        CHECK(s.worker_id == kTarget);
    }
    return 0;
}

// target_worker_id >= n_workers: Submit must reject with kInvalid at the
// validation gate, before queueing. The DataPlane must never see this
// request (no late kInvalid masquerading as a routing failure).
int TestInvalidTargetWorkerIdRejected() {
    constexpr uint32_t kN = 2;
    auto h = MakeChannelHarness(/*channel_id=*/3, kN, "invalid");
    CHECK(h != nullptr);

    auto r = h->channel->Submit(MakeReq(/*executor_id=*/999, /*target=*/kN),
                                std::chrono::microseconds{0});
    CHECK(r.status == cc::ChannelSubmitStatus::kInvalid);

    // UINT32_MAX-1 is also out of range (kAnyWorkerId sentinel == UINT32_MAX
    // would be accepted as "no affinity" — explicitly test that the close
    // neighbour stays rejected).
    auto r2 = h->channel->Submit(MakeReq(/*executor_id=*/1000,
                                          cc::kAnyWorkerId - 1),
                                  std::chrono::microseconds{0});
    CHECK(r2.status == cc::ChannelSubmitStatus::kInvalid);

    // Give the loop a beat to confirm nothing leaked through to the dp.
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    auto subs = h->dp->WaitForSubmits(1, std::chrono::milliseconds{50});
    CHECK(subs.empty());
    return 0;
}

// kAnyWorkerId sentinel is the default and must be accepted (regression
// guard against accidental "any > n_workers, therefore kInvalid").
int TestAnyWorkerIdAcceptedAsDefault() {
    auto h = MakeChannelHarness(/*channel_id=*/4, /*n_workers=*/1, "any");
    CHECK(h != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 42;
    req.payload = {1};
    // target_worker_id defaults to kAnyWorkerId — don't set it explicitly.
    auto r = h->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(r.status == cc::ChannelSubmitStatus::kAccepted);
    auto subs = h->dp->WaitForSubmits(1, std::chrono::milliseconds{500});
    CHECK(subs.size() == 1);
    CHECK(subs[0].worker_id == 0);
    return 0;
}

int TestProcIdRoutesToLaneOwner() {
    constexpr uint32_t kN = 3;
    auto h = MakeChannelHarness(/*channel_id=*/5, kN, "proc-lane");
    CHECK(h != nullptr);

    auto req = MakeReq(/*executor_id=*/77, cc::kAnyWorkerId);
    req.target_proc_id = 7;
    auto r = h->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(r.status == cc::ChannelSubmitStatus::kAccepted);
    auto subs = h->dp->WaitForSubmits(1, std::chrono::milliseconds{500});
    CHECK(subs.size() == 1);
    CHECK(subs[0].worker_id == 1);  // 7 % 3
    CHECK(subs[0].proc_id == 7);

    auto conflict = MakeReq(/*executor_id=*/78, /*target_worker_id=*/2);
    conflict.target_proc_id = 7;
    CHECK(h->channel->Submit(conflict, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kInvalid);

    auto out_of_range = MakeReq(/*executor_id=*/79, cc::kAnyWorkerId);
    out_of_range.target_proc_id = cc::kMaxProcIds;
    CHECK(h->channel->Submit(out_of_range, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kInvalid);
    return 0;
}

int TestCompletionProcIdMustMatchRequest() {
    auto h = MakeChannelHarness(/*channel_id=*/6, /*n_workers=*/1,
                                "proc-completion");
    CHECK(h != nullptr);

    auto req = MakeReq(/*executor_id=*/80, cc::kAnyWorkerId);
    req.target_proc_id = 2;
    CHECK(h->channel->Submit(req, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    const auto submits =
        h->dp->WaitForSubmits(1, std::chrono::milliseconds{500});
    CHECK(submits.size() == 1);

    data::DispatchOutcome outcome;
    outcome.worker_id = submits[0].worker_id;
    outcome.proc_id = 4;
    outcome.executor_id = submits[0].executor_id;
    outcome.dispatch_gen = submits[0].dispatch_gen;
    outcome.kind = data::DispatchOutcomeKind::kOk;
    outcome.output = {1, 2, 3};
    h->dp->PublishOutcome(std::move(outcome));

    ch::EventList events;
    CHECK(h->channel->DrainEvents(events, std::chrono::milliseconds{500}));
    bool saw_proc_mismatch = false;
    for (const auto& event : events) {
        const auto* abnormal = event.AsAbnormal();
        if (abnormal == nullptr) continue;
        saw_proc_mismatch =
            abnormal->ctx.executor_id == req.executor_id &&
            abnormal->ctx.proc_id == 4 &&
            abnormal->kind == cc::AbnormalKind::kHarnessFatal &&
            abnormal->diagnostics.error_code ==
                ERR_HARNESS_FORK_SERVER_PROTOCOL &&
            abnormal->output.empty();
    }
    CHECK(saw_proc_mismatch);
    return 0;
}

} // namespace

int main() {
    std::fprintf(stderr, "channel_target_worker_affinity_test\n");
    RUN_TEST(TestRoundRobinUnchangedWhenAnyWorker);
    RUN_TEST(TestStrictAffinityRoutesAllToTarget);
    RUN_TEST(TestInvalidTargetWorkerIdRejected);
    RUN_TEST(TestAnyWorkerIdAcceptedAsDefault);
    RUN_TEST(TestProcIdRoutesToLaneOwner);
    RUN_TEST(TestCompletionProcIdMustMatchRequest);
    std::fprintf(stderr, "OK\n");
    return 0;
}
