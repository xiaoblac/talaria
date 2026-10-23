// §3.11-C1 P3 — Call.Props integration.
//
// Covers:
//   - text codec round-trip for fail_nth / async / rerun;
//   - serialize_for_exec emits WireSetProps;
//   - ProgramMinimizer's typed artifact path can reset props through
//     typed candidate evaluation;
//   - KernelWireDriver explicitly rejects unsupported non-zero props
//     instead of silently dropping them.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/syz_exec_runner.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/kernel_wire_driver.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace crash = ::refuzz::crash;
namespace pr = ::refuzz::program;
namespace syz = ::refuzz::program::syz;
namespace worker = ::refuzz::worker;

class MockDispatcher final : public worker::IDispatcher {
public:
    struct Record {
        uint64_t nr = 0;
        std::vector<intptr_t> args;
    };

    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        Record record;
        record.nr = nr;
        record.args.assign(args, args + argc);
        records.push_back(std::move(record));
        return worker::PseudoResult{123, 0, nullptr};
    }

    const char* Name() const override { return "mock"; }

    std::vector<Record> records;
};

std::vector<std::uint8_t> ToBytes(std::string_view text)
{
    return std::vector<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()),
        reinterpret_cast<const std::uint8_t*>(text.data() + text.size()));
}

std::unique_ptr<syz::Prog> DecodeProg(std::string_view text)
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(text);
    CHECK(prog_or.has_value());
    CHECK(*prog_or != nullptr);
    return std::move(*prog_or);
}

pr::ProgramTargetKey LinuxAmd64Key()
{
    const auto& target = syz::Target::linux_amd64();
    return pr::ProgramTargetKey{target.os(), target.arch(), target.revision()};
}

pr::ProgramArtifact BuildArtifact(std::unique_ptr<syz::Prog> prog,
                                  std::string_view canonical_text)
{
    auto typed_mut = std::shared_ptr<syz::Prog>(std::move(prog));
    std::shared_ptr<const syz::Prog> typed = typed_mut;
    auto canonical = std::make_shared<const std::vector<std::uint8_t>>(
        ToBytes(canonical_text));

    return pr::ProgramArtifact::Build(
        ::refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        std::static_pointer_cast<const void>(typed),
        typeid(syz::Prog),
        canonical,
        {});
}

std::vector<std::uint8_t> SerializeForExec(const syz::Prog& prog)
{
    auto bytes_or = syz::serialize_for_exec(prog);
    CHECK(bytes_or.has_value());
    CHECK(!bytes_or->empty());
    return std::move(*bytes_or);
}

syz::WireProgram DecodeWire(const std::vector<std::uint8_t>& bytes)
{
    auto wire_or = syz::decode_exec_wire(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    CHECK(wire_or.has_value());
    return std::move(*wire_or);
}

bool HasSetProps(const syz::WireProgram& wire)
{
    for (const auto& instr : wire.instrs) {
        if (std::holds_alternative<syz::WireSetProps>(instr)) {
            return true;
        }
    }
    return false;
}

void TestTextCodecRoundTripsCallProps()
{
    constexpr std::string_view kText =
        "getpid() (fail_nth: 3)\n"
        "getpid() (async)\n"
        "getpid() (rerun: 2)\n";

    auto prog = DecodeProg(kText);
    CHECK(prog->calls().size() == 3);
    CHECK(prog->calls()[0]->props().fail_nth == 3);
    CHECK(!prog->calls()[0]->props().async);
    CHECK(prog->calls()[0]->props().rerun == 0);
    CHECK(prog->calls()[1]->props().fail_nth == 0);
    CHECK(prog->calls()[1]->props().async);
    CHECK(prog->calls()[1]->props().rerun == 0);
    CHECK(prog->calls()[2]->props().fail_nth == 0);
    CHECK(!prog->calls()[2]->props().async);
    CHECK(prog->calls()[2]->props().rerun == 2);

    syz::TextEncoder encoder(syz::Target::linux_amd64());
    const auto encoded = encoder.encode(*prog);
    auto roundtrip = DecodeProg(encoded);
    CHECK(roundtrip->calls().size() == 3);
    CHECK(roundtrip->calls()[0]->props().fail_nth == 3);
    CHECK(roundtrip->calls()[1]->props().async);
    CHECK(roundtrip->calls()[2]->props().rerun == 2);
}

void TestExecWireEmitsSetProps()
{
    auto prog = DecodeProg("getpid() (async)\n");
    const auto bytes = SerializeForExec(*prog);
    const auto wire = DecodeWire(bytes);
    CHECK(wire.num_calls == 1);
    CHECK(HasSetProps(wire));
}

void TestMinimizerResetsCallProps()
{
    constexpr std::string_view kText = "getpid() (async)\n";
    auto artifact = BuildArtifact(DecodeProg(kText), kText);

    crash::ProgramMinimizer minimizer;
    auto test_fn = [](const std::vector<std::uint8_t>& payload)
        -> std::pair<bool, std::string> {
        auto wire_or = syz::decode_exec_wire(
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        if (!wire_or.has_value()) {
            return {false, {}};
        }
        return {!HasSetProps(*wire_or), "target"};
    };
    auto stop_fn = [] { return false; };

    auto result = minimizer.Minimize(
        artifact,
        std::move(test_fn),
        std::move(stop_fn),
        crash::MinimizeMode::kCrash,
        /*guilty_call_index=*/-1);

    CHECK(result.success);
    CHECK(result.minimize_commits > 0);
    CHECK(result.minimize_stage == "call props");
    const auto wire = DecodeWire(result.payload);
    CHECK(!HasSetProps(wire));
}

void TestKernelWireDriverRejectsUnsupportedSetProps()
{
    // Async stays §10 N1 永久非目标 — 这里测的是 (async) 仍 reject。
    // FailNth 走 Honor 路径见 TestKernelWireDriverHonorsFailNth (Epic 6 P2-1)。
    auto prog = DecodeProg("getpid() (async)\n");
    const auto bytes = SerializeForExec(*prog);

    auto dispatcher = std::make_unique<MockDispatcher>();
    auto* dispatcher_raw = dispatcher.get();
    worker::KernelWireDriver driver(
        std::move(dispatcher));

    std::array<std::uint8_t, sizeof(worker::SyzExecResult)> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);

    CHECK(rc != 0);
    CHECK(output_len == 0);
    CHECK(dispatcher_raw->records.empty());
}

// [v2 Epic 6 PR-6-A — FailNth 不再触发 driver-level reject;走 inject_fault
//  hook 真路径(test seam 注入 mock helpers,免依赖真实 /proc/thread-self/fail-nth)]
namespace {
int MockInjectFaultReturnFd(int /*nth*/) { return 7; /* fake fd */ }
bool MockFaultInjectedTrue(int /*fd*/)   { return true; }
}

void TestKernelWireDriverHonorsFailNth()
{
    auto prog = DecodeProg("getpid() (fail_nth: 1)\n");
    const auto bytes = SerializeForExec(*prog);

    auto dispatcher = std::make_unique<MockDispatcher>();
    auto* dispatcher_raw = dispatcher.get();
    worker::KernelWireDriver driver(
        std::move(dispatcher),
        /*pid=*/0,
        &MockInjectFaultReturnFd,
        &MockFaultInjectedTrue);

    std::array<std::uint8_t, sizeof(worker::SyzExecResult)> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);

    CHECK(rc == 0);
    CHECK(output_len == sizeof(worker::SyzExecResult));
    CHECK(dispatcher_raw->records.size() == 1);

    worker::SyzExecResult res{};
    std::memcpy(&res, output.data(), sizeof(res));
    CHECK((res.flags & worker::kCallFlagFaultInjected) != 0);
}

} // namespace

int main()
{
    RUN_TEST(TestTextCodecRoundTripsCallProps);
    RUN_TEST(TestExecWireEmitsSetProps);
    RUN_TEST(TestMinimizerResetsCallProps);
    RUN_TEST(TestKernelWireDriverRejectsUnsupportedSetProps);
    RUN_TEST(TestKernelWireDriverHonorsFailNth);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
