#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/engine/loop_runtime.hpp"
#include "worker/profile/worker_profile.hpp"
#include "worker/program_buffers.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <signal.h>
#include <type_traits>
#include <utility>

volatile sig_atomic_t g_running = 1;

namespace worker = refuzz::worker;
namespace engine = refuzz::worker::engine;
namespace topology = refuzz::worker::topology;

static_assert(!std::is_base_of_v<worker::IWorkerTaskChannel,
                                 worker::IWorkerAdapter>);
static_assert(!std::is_base_of_v<worker::IExecutionDomainRegistry,
                                 worker::IWorkerAdapter>);
static_assert(!std::is_base_of_v<worker::IWorkerRegistrar,
                                 worker::IWorkerAdapter>);
static_assert(std::is_same_v<
              decltype(std::declval<worker::IWorkerAdapter&>().TaskChannel()),
              worker::IWorkerTaskChannel&>);
static_assert(std::is_same_v<
              decltype(std::declval<worker::IWorkerAdapter&>().DomainRegistry()),
              worker::IExecutionDomainRegistry&>);
static_assert(std::is_same_v<
              decltype(std::declval<worker::IWorkerAdapter&>().Registrar()),
              worker::IWorkerRegistrar&>);

namespace {

bool Check(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
    }
    return condition;
}

engine::LoopWorkerBootConfig ValidBootConfig()
{
    auto config = engine::MakeLoopWorkerBootConfig();
    config.buffer_source =
        static_cast<uint32_t>(worker::ProgramBufferSource::kLinearSharedMemory);
    config.window_resource_offset = 0x1000;
    config.window_size = 0x5000;
    config.input_resource_offset = 0x1000;
    config.input_size = 0x1000;
    config.output_resource_offset = 0x2000;
    config.output_size = 0x2000;
    config.result_resource_offset = 0x4000;
    config.result_size = sizeof(ProgramResultPageV3);
    return config;
}

bool TestBootGeometry()
{
    auto config = ValidBootConfig();
    bool ok = Check(engine::LoopWorkerBootGeometryValid(
                        config, sizeof(ProgramResultPageV3)),
                    "valid boot geometry rejected");

    auto underflow = config;
    underflow.input_resource_offset = config.window_resource_offset - 1;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    underflow, sizeof(ProgramResultPageV3)),
                "input offset before window accepted");

    auto overflow = config;
    overflow.window_resource_offset =
        std::numeric_limits<uint64_t>::max() - 0x100;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    overflow, sizeof(ProgramResultPageV3)),
                "overflowing window end accepted");

    auto output_overrun = config;
    output_overrun.output_resource_offset = 0x5f00;
    output_overrun.output_size = 0x200;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    output_overrun, sizeof(ProgramResultPageV3)),
                "output overrun accepted");

    auto small_result = config;
    small_result.result_size = sizeof(ProgramResultPageV3) - 1;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    small_result, sizeof(ProgramResultPageV3)),
                "undersized result page accepted");

    auto unknown_source = config;
    unknown_source.buffer_source = 99;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    unknown_source, sizeof(ProgramResultPageV3)),
                "unknown buffer source accepted");

    auto unknown_kcov_mode = config;
    unknown_kcov_mode.kcov_child_mode = 99;
    ok &= Check(!engine::LoopWorkerBootGeometryValid(
                    unknown_kcov_mode, sizeof(ProgramResultPageV3)),
                "unknown KCOV child mode accepted");
    return ok;
}

bool TestOffsetResolution()
{
    std::array<uint8_t, 0x5000> storage{};
    worker::ProgramBufferMapping mapping{};
    mapping.local_base = storage.data();
    mapping.resource_offset = 0x1000;
    mapping.mapped_size = storage.size();

    uint8_t* resolved = nullptr;
    bool ok = Check(worker::ResolveProgramBufferRange(
                        mapping, 0x2800, 0x100, 0x2000, 0x2000, &resolved),
                    "valid offset range rejected");
    ok &= Check(resolved == storage.data() + 0x1800,
                "valid offset resolved to wrong local address");
    ok &= Check(!worker::ResolveProgramBufferRange(
                    mapping, 0x1fff, 1, 0x2000, 0x2000, &resolved),
                "offset before allowed subrange accepted");
    ok &= Check(!worker::ResolveProgramBufferRange(
                    mapping, 0x3f00, 0x200, 0x2000, 0x2000, &resolved),
                "allowed subrange overrun accepted");
    ok &= Check(!worker::ResolveProgramBufferRange(
                    mapping, 0x5f00, 0x200, 0x1000, 0x5000, &resolved),
                "mapped range overrun accepted");
    return ok;
}

bool TestProfileOwnership()
{
    worker::KernelSyzStdioArgs args{};
    args.coverage_mode = worker::CoverageMode::kNone;
    auto exec_profile = worker::MakeKernelSyzStdioProfile(args);
    bool ok = Check(exec_profile.adapter != nullptr &&
                        exec_profile.topology != nullptr &&
                        std::holds_alternative<
                            worker::ExecRebuiltExecutionComponents>(
                                exec_profile.execution_components),
                    "exec profile constructed daemon execution components");

    args.process_topology = topology::TopologyKind::kDoubleFork;
    auto fork_profile = worker::MakeKernelSyzStdioProfile(args);
    const auto* daemon_components = std::get_if<
        worker::DaemonOwnedExecutionComponents>(
            &fork_profile.execution_components);
    ok &= Check(fork_profile.adapter != nullptr &&
                    fork_profile.topology != nullptr &&
                    daemon_components != nullptr && *daemon_components,
                "legacy fork profile did not construct local components");
    return ok;
}

bool TestSmapsHeaderRecognition()
{
    bool ok = Check(engine::IsSmapsVmaHeaderLine(
                        "7fc8bd417000-7fc8bd418000 rw-p 00000000 00:00 0"),
                    "valid smaps VMA header rejected");
    ok &= Check(!engine::IsSmapsVmaHeaderLine("Anonymous:             4 kB"),
                "Anonymous field accepted as a VMA header");
    ok &= Check(!engine::IsSmapsVmaHeaderLine("AnonHugePages:         0 kB"),
                "AnonHugePages field accepted as a VMA header");
    ok &= Check(!engine::IsSmapsVmaHeaderLine("FilePmdMapped:         0 kB"),
                "FilePmdMapped field accepted as a VMA header");
    ok &= Check(!engine::IsSmapsVmaHeaderLine("7fc8bd417000 rw-p"),
                "address without a range accepted as a VMA header");
    return ok;
}

} // namespace

int main()
{
    return TestBootGeometry() && TestOffsetResolution() &&
                   TestProfileOwnership() && TestSmapsHeaderRecognition()
        ? 0
        : 1;
}
