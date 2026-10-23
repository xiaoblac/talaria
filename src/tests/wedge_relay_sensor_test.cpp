// wedge_relay_sensor_test.cpp
//
// Verifies the XiUOS Poll-to-health bridge without constructing a full
// HealthMonitor. The sensor must turn one consumed wedge flag into one
// kWorkerDead crash event and mark that worker dead.

#include "refuzz/channel/health/wedge_relay_sensor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <utility>
#include <vector>

namespace health = refuzz::channel::health;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

class FakePublisher final : public health::HealthPublisher {
public:
    void Publish(health::CrashEvent event) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            events_.push_back(std::move(event));
        }
        cv_.notify_all();
    }

    bool IsSuspended() const override {
        return suspended_.load(std::memory_order_acquire);
    }

    void ParkUntilResumed() override {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] {
            return !suspended_.load(std::memory_order_acquire);
        });
    }

    void NotifyThreadExiting() override {}

    void SetWorkerAlive(std::uint32_t worker_id, bool alive) noexcept override {
        last_alive_worker_.store(worker_id, std::memory_order_release);
        last_alive_value_.store(alive, std::memory_order_release);
    }

    bool WaitForEvents(std::size_t count, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, timeout, [this, count] {
            return events_.size() >= count;
        });
    }

    std::vector<health::CrashEvent> Events() const {
        std::lock_guard<std::mutex> lock(mu_);
        return events_;
    }

    std::uint32_t LastAliveWorker() const {
        return last_alive_worker_.load(std::memory_order_acquire);
    }

    bool LastAliveValue() const {
        return last_alive_value_.load(std::memory_order_acquire);
    }

private:
    mutable std::mutex              mu_;
    std::condition_variable         cv_;
    std::vector<health::CrashEvent> events_;
    std::atomic<bool>               suspended_{false};
    std::atomic<std::uint32_t>      last_alive_worker_{UINT32_MAX};
    std::atomic<bool>               last_alive_value_{true};
};

int TestStartRejectsEmptyClosure() {
    health::WedgeRelaySensorConfig cfg;
    FakePublisher publisher;
    health::WedgeRelaySensor sensor({}, cfg);

    auto r = sensor.Start(publisher);
    CHECK(!r.ok());
    return 0;
}

int TestRelaysOneWedgeAsWorkerDead() {
    std::atomic<bool> wedge{false};
    health::WedgeRelaySensorConfig cfg;
    cfg.check_interval = std::chrono::milliseconds(5);
    cfg.worker_id = 3;

    FakePublisher publisher;
    health::WedgeRelaySensor sensor([&] {
        return wedge.exchange(false, std::memory_order_acq_rel);
    }, cfg);

    CHECK(sensor.Start(publisher).ok());
    wedge.store(true, std::memory_order_release);
    CHECK(publisher.WaitForEvents(1, std::chrono::seconds(2)));
    sensor.Stop();

    const auto events = publisher.Events();
    CHECK(events.size() == 1);
    CHECK(events[0].origin == health::CrashEventOrigin::kHeartbeat);
    CHECK(events[0].fragment.kind == health::CrashKind::kWorkerDead);
    CHECK(events[0].fragment.source_worker_id == 3);
    CHECK(publisher.LastAliveWorker() == 3);
    CHECK(!publisher.LastAliveValue());
    CHECK(!wedge.load(std::memory_order_acquire));
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running wedge_relay_sensor_test...\n");
    int run = 0;
    int ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) {
            ++ok;
            std::fprintf(stderr, "  [PASS] %s\n", name);
        } else {
            std::fprintf(stderr, "  [FAIL] %s\n", name);
        }
    };

    exec(TestStartRejectsEmptyClosure, "StartRejectsEmptyClosure");
    exec(TestRelaysOneWedgeAsWorkerDead, "RelaysOneWedgeAsWorkerDead");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
