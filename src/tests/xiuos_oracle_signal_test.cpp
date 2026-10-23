// xiuos_oracle_signal_test.cpp
//
// XiUOS oracle feedback unit test. Verifies that normal Completion verdicts
// with vendor_status / vendor_flags are translated into the standard crash
// pipeline payload, instead of being handled in a private session loop.

#include "refuzz/feedback/aggregator/coverage_guided_aggregator.hpp"
#include "refuzz/feedback/signal/xiuos_oracle_signal.hpp"

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace cc     = refuzz::core::channel_contract;
namespace fuzzer = refuzz::fuzzer;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

cc::ChannelEvent MakeCompletion(std::uint32_t vendor_status,
                                std::uint32_t vendor_flags,
                                std::uint64_t executor_id = 7)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    ev.event_id = 99;
    ev.channel_id = 1;
    ev.generation = 1;

    cc::Completion comp;
    comp.ctx.executor_id = executor_id;
    comp.ctx.seed_id = 1234;
    comp.ctx.origin_seed_id = 1234;
    comp.ctx.worker_id = 3;
    comp.ctx.submit_ts_us = 777;
    comp.ctx.program_payload = {0x10, 0x20, 0x30};
    comp.vendor_status = vendor_status;
    comp.vendor_flags = vendor_flags;
    ev.payload = std::move(comp);
    return ev;
}

int TestNormalCompletionDoesNothing()
{
    fuzzer::XiuosOracleSignal signal;
    auto ev = MakeCompletion(XIUOS_STATUS_OK, 0);
    auto c = signal.Sample(ev);
    CHECK(c.id == "xiuos_oracle");
    CHECK(c.kind == fuzzer::SignalKind::kSanitizer);
    CHECK(!c.fired);
    CHECK(!c.crash_payload.has_value());
    return 0;
}

int TestStateViolationCreatesCrashPayload()
{
    fuzzer::XiuosOracleSignal signal;
    auto ev = MakeCompletion(XIUOS_STATUS_STATE_VIOLATION, 0, 42);
    auto c = signal.Sample(ev);

    CHECK(c.fired);
    CHECK(c.kind == fuzzer::SignalKind::kSanitizer);
    CHECK(c.exec_code == refuzz::proto::ResultCode::kCrashed);
    CHECK(c.crash_payload.has_value());

    const auto& payload = *c.crash_payload;
    CHECK(payload.incident_id == 99);
    CHECK(payload.crash_program.has_value());
    CHECK(payload.crash_program->executor_id == 42);
    CHECK(payload.crash_program->seed_id == 1234);
    CHECK(payload.crash_program->origin_seed_id == 1234);
    CHECK(payload.crash_program->program_payload == std::vector<std::uint8_t>({0x10, 0x20, 0x30}));
    CHECK(payload.crash_program->completion.has_value());
    CHECK(payload.crash_program->completion->result_code == refuzz::proto::ResultCode::kCrashed);
    CHECK(payload.crash_program->completion->crash_signal == 0);
    CHECK(payload.crash_origin_artifact == nullptr);
    return 0;
}

int TestLeakFlagsCreateCrashPayload()
{
    fuzzer::XiuosOracleSignal signal;
    auto ev = MakeCompletion(XIUOS_STATUS_OK, 17);
    auto c = signal.Sample(ev);

    CHECK(c.fired);
    CHECK(c.kind == fuzzer::SignalKind::kResource);
    // [XiUOS leak 一等公民化] leak 现为独立终态 kResourceLeak(不再复用 kExecError),
    // 且 leak delta 走专用 leak_bytes 载体、crash_signal 保持 0(见 xiuos_oracle_signal.cpp)。
    CHECK(c.exec_code == refuzz::proto::ResultCode::kResourceLeak);
    CHECK(c.magnitude == 17);
    CHECK(c.crash_payload.has_value());
    CHECK(c.crash_payload->crash_program.has_value());
    CHECK(c.crash_payload->crash_program->completion->leak_bytes == 17);
    CHECK(c.crash_payload->crash_program->completion->crash_signal == 0);

    fuzzer::CoverageGuidedAggregator agg;
    auto score = agg.Aggregate(ev, std::span<const fuzzer::SignalContribution>(&c, 1));
    CHECK(!score.is_crash);
    CHECK(score.crash_payload.has_value());
    CHECK(score.crash_payload->crash_program->completion->leak_bytes == 17);
    return 0;
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running xiuos_oracle_signal_test...\n");

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

    exec(TestNormalCompletionDoesNothing, "NormalCompletionDoesNothing");
    exec(TestStateViolationCreatesCrashPayload, "StateViolationCreatesCrashPayload");
    exec(TestLeakFlagsCreateCrashPayload, "LeakFlagsCreateCrashPayload");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
