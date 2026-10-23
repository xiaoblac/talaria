// xiuos_uart_assembler_test.cpp
//
// Phase 2 §B v1 — verify the QemuUartXiuosAssembler wiring and Catalog
// registration. No QEMU is started: Assemble only constructs components,
// AssembleAndBuild additionally runs ChannelBuilder validation. Neither
// touches the socket. Full Channel::Boot end-to-end against a real worker
// is a separate follow-up test (Phase 2 §B continuation).

#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"
#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"
#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/channel/factory/mock_backend_profile.hpp"
#include "refuzz/channel/factory/qemu_uart_xiuos_assembler.hpp"
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <chrono>

#include <cstdio>
#include <memory>
#include <string>

namespace channel = refuzz::channel;
namespace factory = refuzz::channel::factory;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

channel::ChannelBuildContext MakeContext(const factory::XiuosUartProfile& profile) {
    channel::ChannelBuildContext ctx;
    ctx.channel_cfg.channel_id = 1;
    ctx.channel_cfg.n_workers = 1;
    ctx.backend_profile = &profile;
    ctx.vm_index = 0;
    ctx.vm_workdir = "/tmp/xiuos-channel-test";
    return ctx;
}

int TestProfileBackendId() {
    factory::XiuosUartProfile profile;
    CHECK(profile.BackendId() == "qemu_uart_xiuos");
    return 0;
}

int TestAssembleProducesAllComponents() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";  // Substrate StartVM
                                                          // is not called yet
    profile.serial_port = 30001;
    const auto ctx = MakeContext(profile);

    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(comps_r.ok());

    const auto& comps = comps_r.value();
    CHECK(comps.shm == nullptr);          // XiUOS uses no ivshmem
    CHECK(comps.substrate != nullptr);
    CHECK(comps.control != nullptr);
    CHECK(comps.data != nullptr);
    CHECK(comps.console != nullptr);      // NullConsoleSource
    CHECK(comps.steps == nullptr);        // no step-event ring
    CHECK(comps.health != nullptr);       // HealthMonitor with XiUOS sensors
    CHECK(comps.recovery != nullptr);     // Recovery wired to XiUOS substrate
    CHECK(comps.channel_cfg.backend_id == "qemu_uart_xiuos");
    CHECK(comps.channel_cfg.n_workers == 1);
    return 0;
}

int TestAssembleNormalizesNWorkers() {
    // XiUOS is single-worker; Assembler should clamp n_workers to 1
    // regardless of what the orchestrator passed.
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent.elf";
    profile.serial_port = 30002;

    auto ctx = MakeContext(profile);
    ctx.channel_cfg.n_workers = 8;
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(comps_r.ok());
    CHECK(comps_r.value().channel_cfg.n_workers == 1);

    auto ctx2 = MakeContext(profile);
    ctx2.channel_cfg.n_workers = 0;
    auto comps_r2 = asm_inst.Assemble(ctx2);
    CHECK(comps_r2.ok());
    CHECK(comps_r2.value().channel_cfg.n_workers == 1);
    return 0;
}

int TestAssembleRejectsMissingProfile() {
    channel::ChannelBuildContext ctx;
    ctx.backend_profile = nullptr;
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(!comps_r.ok());
    return 0;
}

int TestAssembleRejectsWrongProfileType() {
    factory::MockBackendProfile wrong;
    channel::ChannelBuildContext ctx;
    ctx.backend_profile = &wrong;
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(!comps_r.ok());
    return 0;
}

int TestAssembleRejectsMissingElf() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "";  // intentionally empty
    profile.serial_port = 30003;
    const auto ctx = MakeContext(profile);
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(!comps_r.ok());
    return 0;
}

int TestAssembleRejectsZeroPort() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "/some.elf";
    profile.serial_port = 0;
    const auto ctx = MakeContext(profile);
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(!comps_r.ok());
    return 0;
}

int TestAssembleAndBuildReturnsChannel() {
    // ChannelBuilder validates that substrate/control/data/console/health/
    // recovery are non-null. AssembleAndBuild glues Assemble + Build.
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";
    profile.serial_port = 30004;
    const auto ctx = MakeContext(profile);

    auto built = channel::QemuUartXiuosAssembler::AssembleAndBuild(ctx);
    CHECK(built.ok());
    CHECK(built.value() != nullptr);  // unique_ptr<IChannel> populated; Boot deferred
    return 0;
}

int TestCatalogRegistersAndBuilds() {
    // End-to-end through the public Catalog API (the orchestrator's path).
    channel::ChannelCatalog catalog;
    channel::RegisterBuiltinChannels(catalog);

    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";
    profile.serial_port = 30005;
    const auto ctx = MakeContext(profile);

    auto built = catalog.Build(
        std::string(channel::channel_backend_id::kQemuUartXiuos), ctx);
    CHECK(built.has_value());
    CHECK(built.value() != nullptr);
    return 0;
}

// Phase 2 §B v1 review fix HIGH: Channel::Boot passes 0 ms to
// WaitAllWorkersReady; the CP impl must use its own configured timeout as
// a fallback, and the Assembler must wire ChannelConfig::wait_ready_timeout
// into that CP-side fallback (otherwise the orchestrator-side timeout
// tuning is silently dropped).
int TestAssembleInjectsWaitReadyTimeoutIntoCp() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";
    profile.serial_port = 30006;

    auto ctx = MakeContext(profile);
    ctx.channel_cfg.wait_ready_timeout = std::chrono::milliseconds(31415);

    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(comps_r.ok());

    auto* cp = dynamic_cast<refuzz::channel::control::XiuosUartControlPlane*>(
        comps_r.value().control.get());
    CHECK(cp != nullptr);
    CHECK(cp->config().ready_timeout == std::chrono::milliseconds(31415));
    return 0;
}

// Phase 2 §B closing review fix HIGH: Channel::Submit was reading
// `shm_->MaxInput()` unconditionally; XiUOS has shm == nullptr so that was
// UB. Channel now reads ChannelConfig::max_payload_size first, and the
// XiUOS Assembler MUST populate it (otherwise the fallback would still
// try to deref shm_ which is null). Regression: assert the Assembler
// publishes the worker's wire bound XIUOS_MAX_PAYLOAD = 512.
int TestAssembleSetsMaxPayloadSize() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";
    profile.serial_port = 30007;
    const auto ctx = MakeContext(profile);

    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(comps_r.ok());

    const auto& cfg = comps_r.value().channel_cfg;
    CHECK(comps_r.value().shm == nullptr);
    CHECK(cfg.max_payload_size != 0);  // must be set; otherwise Channel falls
                                       // back to shm_ deref (XiUOS=nullptr).
    CHECK(cfg.max_payload_size == static_cast<std::size_t>(XIUOS_MAX_PAYLOAD));
    return 0;
}

int TestAssembleWiresProgramTimeoutIntoDataPlane() {
    factory::XiuosUartProfile profile;
    profile.elf_path = "/nonexistent/XiZi-virt-rv32.elf";
    profile.serial_port = 30008;
    profile.program_timeout = std::chrono::milliseconds(23456);

    const auto ctx = MakeContext(profile);
    channel::QemuUartXiuosAssembler asm_inst;
    auto comps_r = asm_inst.Assemble(ctx);
    CHECK(comps_r.ok());

    auto* dp = dynamic_cast<refuzz::channel::data::XiuosUartDataPlane*>(
        comps_r.value().data.get());
    CHECK(dp != nullptr);
    CHECK(dp->config().program_timeout == std::chrono::milliseconds(23456));
    return 0;
}

int TestCatalogRejectsMissingProfile() {
    channel::ChannelCatalog catalog;
    channel::RegisterBuiltinChannels(catalog);

    channel::ChannelBuildContext ctx;
    ctx.backend_profile = nullptr;
    auto built = catalog.Build(
        std::string(channel::channel_backend_id::kQemuUartXiuos), ctx);
    CHECK(!built.has_value());
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_assembler_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestProfileBackendId,             "ProfileBackendId");
    exec(TestAssembleProducesAllComponents, "AssembleProducesAllComponents");
    exec(TestAssembleNormalizesNWorkers,    "AssembleNormalizesNWorkers");
    exec(TestAssembleRejectsMissingProfile, "AssembleRejectsMissingProfile");
    exec(TestAssembleRejectsWrongProfileType, "AssembleRejectsWrongProfileType");
    exec(TestAssembleRejectsMissingElf,     "AssembleRejectsMissingElf");
    exec(TestAssembleRejectsZeroPort,       "AssembleRejectsZeroPort");
    exec(TestAssembleAndBuildReturnsChannel, "AssembleAndBuildReturnsChannel");
    exec(TestAssembleInjectsWaitReadyTimeoutIntoCp,
         "AssembleInjectsWaitReadyTimeoutIntoCp");
    exec(TestAssembleSetsMaxPayloadSize,    "AssembleSetsMaxPayloadSize");
    exec(TestAssembleWiresProgramTimeoutIntoDataPlane,
         "AssembleWiresProgramTimeoutIntoDataPlane");
    exec(TestCatalogRegistersAndBuilds,     "CatalogRegistersAndBuilds");
    exec(TestCatalogRejectsMissingProfile,  "CatalogRejectsMissingProfile");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
