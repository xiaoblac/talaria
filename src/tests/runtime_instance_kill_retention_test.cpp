// runtime_instance_kill_retention_test.cpp
//
// Pins the [当前版本 stop-single-worker-pid-retention] contract in
// runtime_instance.cpp:StopSingleWorker — when the underlying SSH `kill -9`
// fails (timeout / connection error), the pid slot must stay populated so the
// next recovery attempt re-issues the kill rather than skipping it and racing
// a fresh worker against a still-alive one.

#include "refuzz/channel/runtime/runtime_instance.hpp"
#include "refuzz/channel/substrate/substrate.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace ch     = refuzz::channel;
namespace runtime = refuzz::channel::runtime;
namespace worker = refuzz::channel::worker;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            std::abort();                                                          \
        }                                                                          \
    } while (false)

namespace {

// Records every run_command invocation; lets each call's response be queued
// ahead of time. Once the queue runs out we default to an empty-output success
// so leftover calls don't crash but the test asserts on commands.size() anyway.
struct OpsRecorder {
    std::vector<std::string>                 commands;
    std::vector<ch::Result<std::string>>     responses;

    ch::Result<std::string> Next(std::string cmd)
    {
        commands.push_back(std::move(cmd));
        const std::size_t idx = commands.size() - 1;
        if (idx < responses.size()) {
            return std::move(responses[idx]);
        }
        return ch::Result<std::string>::Ok(std::string{});
    }
};

runtime::SubstrateInstanceOps MakeMockOps(OpsRecorder* rec)
{
    runtime::SubstrateInstanceOps ops;
    ops.start            = []() { return ch::Result<void>::Ok(); };
    ops.stop             = []() {};
    ops.is_alive         = []() { return true; };
    ops.run_command      =
        [rec](const std::string& cmd, std::chrono::milliseconds) {
            return rec->Next(cmd);
        };
    ops.copy_file_to     =
        [](const std::string&, const std::string&, std::chrono::milliseconds) {
            return ch::Result<void>::Ok();
        };
    ops.serial_endpoint  = []() { return std::string{}; };
    ops.monitor_endpoint = []() { return std::string{}; };
    ops.diagnose         = []() { return std::string{}; };
    return ops;
}

worker::WorkerConfig MakeWorkerCfg()
{
    worker::WorkerConfig cfg;
    cfg.n_workers            = 1;
    cfg.worker_remote_path   = "/tmp/test_worker";
    cfg.start_worker_timeout = std::chrono::milliseconds{50};
    cfg.stop_worker_timeout  = std::chrono::milliseconds{50};
    return cfg;
}

// When the SSH `kill -9` times out, the pid slot must be retained so the next
// StopSingleWorker still attempts a real kill.
void TestStopSingleWorkerRetainsPidOnKillTimeout()
{
    OpsRecorder rec;
    // 0: StartSingleWorker → echoes pid 1234
    rec.responses.push_back(ch::Result<std::string>::Ok(std::string("1234\n")));
    // 1: first StopSingleWorker → kill SSH times out
    rec.responses.push_back(
        ch::Error{ch::ErrorKind::kTimeout, "SSH command timed out: kill -9 1234"});
    // 2: second StopSingleWorker → kill succeeds (proves the slot still had 1234)
    rec.responses.push_back(ch::Result<std::string>::Ok(std::string{}));

    runtime::RuntimeInstance inst(MakeMockOps(&rec), MakeWorkerCfg());

    auto r1 = inst.StartSingleWorkerPublic(0);
    CHECK(r1.ok());
    CHECK(rec.commands.size() == 1);
    CHECK(rec.commands[0].find("RFZ_WORKER_") == std::string::npos);
    CHECK(rec.commands[0].find("--worker-id 0") != std::string::npos);

    auto r2 = inst.StopSingleWorker(0);
    CHECK(!r2.ok());
    CHECK(r2.error().kind == ch::ErrorKind::kTimeout);
    CHECK(rec.commands.size() == 2);
    CHECK(rec.commands[1].find("kill -9 1234") != std::string::npos);

    auto r3 = inst.StopSingleWorker(0);
    CHECK(r3.ok());
    CHECK(rec.commands.size() == 3);
    CHECK(rec.commands[2].find("kill -9 1234") != std::string::npos);
}

// kConnection errors (exit_code=255) must behave the same as timeouts.
void TestStopSingleWorkerRetainsPidOnConnectionFailure()
{
    OpsRecorder rec;
    rec.responses.push_back(ch::Result<std::string>::Ok(std::string("5555\n")));
    rec.responses.push_back(
        ch::Error{ch::ErrorKind::kConnection, "ssh exit 255: kill -9 5555"});
    rec.responses.push_back(
        ch::Error{ch::ErrorKind::kConnection, "ssh exit 255 again"});

    runtime::RuntimeInstance inst(MakeMockOps(&rec), MakeWorkerCfg());

    CHECK(inst.StartSingleWorkerPublic(0).ok());

    auto r1 = inst.StopSingleWorker(0);
    CHECK(!r1.ok());
    CHECK(r1.error().kind == ch::ErrorKind::kConnection);

    auto r2 = inst.StopSingleWorker(0);
    CHECK(!r2.ok());  // still trying — pid was not cleared
    CHECK(rec.commands.size() == 3);
    CHECK(rec.commands[2].find("kill -9 5555") != std::string::npos);
}

// When kill genuinely succeeds, the slot must be cleared so subsequent
// StopSingleWorker calls are no-op idempotent and do NOT issue another SSH.
void TestStopSingleWorkerClearsPidOnSuccessfulKill()
{
    OpsRecorder rec;
    rec.responses.push_back(ch::Result<std::string>::Ok(std::string("9876\n")));
    rec.responses.push_back(ch::Result<std::string>::Ok(std::string{}));

    runtime::RuntimeInstance inst(MakeMockOps(&rec), MakeWorkerCfg());

    CHECK(inst.StartSingleWorkerPublic(0).ok());
    CHECK(inst.StopSingleWorker(0).ok());
    CHECK(rec.commands.size() == 2);
    CHECK(rec.commands[1].find("kill -9 9876") != std::string::npos);

    // Second StopSingleWorker hits the pid==0 short-circuit; no SSH issued.
    auto r = inst.StopSingleWorker(0);
    CHECK(r.ok());
    CHECK(rec.commands.size() == 2);
}

// Out-of-range guard still returns kCommand without touching ops.
void TestStopSingleWorkerOutOfRangeReturnsError()
{
    OpsRecorder rec;
    runtime::RuntimeInstance inst(MakeMockOps(&rec), MakeWorkerCfg());
    auto r = inst.StopSingleWorker(42);
    CHECK(!r.ok());
    CHECK(r.error().kind == ch::ErrorKind::kCommand);
    CHECK(rec.commands.empty());
}

#define RUN_TEST(fn)                                                               \
    do {                                                                           \
        fn();                                                                      \
        std::fprintf(stderr, "[PASS] %s\n", #fn);                                  \
    } while (false)

}  // namespace

int main()
{
    RUN_TEST(TestStopSingleWorkerRetainsPidOnKillTimeout);
    RUN_TEST(TestStopSingleWorkerRetainsPidOnConnectionFailure);
    RUN_TEST(TestStopSingleWorkerClearsPidOnSuccessfulKill);
    RUN_TEST(TestStopSingleWorkerOutOfRangeReturnsError);
    return 0;
}
