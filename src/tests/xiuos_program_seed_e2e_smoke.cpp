// xiuos_program_seed_e2e_smoke.cpp
//
// Phase 2 §B #15 acceptance gate — the full data path:
//
//   tools/xiuos_refuzz/corpus/generated/<rule>/<seq>_<hash>.json
//      → XiuosProgramSeed (JSON loader)
//      → ChannelDispatchRequest.payload  (Encode → XiuosEncodeProgram)
//      → ChannelCatalog.Build("qemu_uart_xiuos") + Channel::Boot()
//      → Channel::Submit / Channel::DrainEvents
//      → Completion.output (256B XiUOS coverage bitmap)
//      → XiuosCoverageSignal.Sample → SignalContribution.interesting
//
// SKIPs (exit 0) if the worker ELF or corpus tree is absent. The default
// seed limit is small enough to keep CI fast (~30s); use XIUOS_E2E_SEED_LIMIT
// to override (0 = run all 1008 generated seeds).

#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/program/xiuos/xiuos_program_seed.hpp"
#include "refuzz/feedback/signal/xiuos_coverage_signal.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace channel  = refuzz::channel;
namespace factory  = refuzz::channel::factory;
namespace infra    = refuzz::channel::infra;
namespace cc       = refuzz::core::channel_contract;
namespace fuzzer   = refuzz::fuzzer;
namespace progxiuos = refuzz::program::xiuos;

namespace {

const char* GetEnvOr(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : fallback;
}

bool FileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

int RunSmoke() {
    const std::string elf_path = GetEnvOr(
        "XIUOS_VIRT_RV32_ELF",
        "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
        "build/XiZi-virt-rv32.elf");
    const std::string qemu_bin = GetEnvOr("XIUOS_QEMU", "qemu-system-riscv32");
    const std::string host     = GetEnvOr("XIUOS_HOST", "127.0.0.1");
    const std::uint16_t port   = static_cast<std::uint16_t>(
        std::atoi(GetEnvOr("XIUOS_PORT", "32571")));
    const std::filesystem::path corpus_root = GetEnvOr(
        "XIUOS_GENERATED_CORPUS_DIR", XIUOS_GENERATED_CORPUS_DIR_DEFAULT);
    const std::size_t seed_limit = static_cast<std::size_t>(
        std::atoi(GetEnvOr("XIUOS_E2E_SEED_LIMIT", "30")));

    if (!FileExists(elf_path)) {
        std::fprintf(stdout,
            "SKIP xiuos_program_seed_e2e_smoke: worker ELF not found at %s\n",
            elf_path.c_str());
        return 0;
    }
    if (!std::filesystem::exists(corpus_root)) {
        std::fprintf(stdout,
            "SKIP xiuos_program_seed_e2e_smoke: corpus dir not found at %s\n",
            corpus_root.string().c_str());
        return 0;
    }

    // ─── Discover seeds ───
    auto seed_paths = progxiuos::DiscoverXiuosProgramSeedFiles(corpus_root);
    if (seed_paths.empty()) {
        std::fprintf(stderr, "FAIL: no seed JSONs under %s\n",
                     corpus_root.string().c_str());
        return 1;
    }
    if (seed_limit > 0 && seed_paths.size() > seed_limit) {
        seed_paths.resize(seed_limit);
    }
    std::fprintf(stdout, "discovered=%zu (cap=%zu)\n",
                 seed_paths.size(), seed_limit);

    // ─── Build + Boot channel ───
    channel::ChannelCatalog catalog;
    channel::RegisterBuiltinChannels(catalog);

    factory::XiuosUartProfile profile;
    profile.qemu_bin    = qemu_bin;
    profile.elf_path    = elf_path;
    profile.serial_host = host;
    profile.serial_port = port;

    channel::ChannelBuildContext ctx;
    ctx.channel_cfg.channel_id = 17;
    ctx.channel_cfg.n_workers = 1;
    ctx.channel_cfg.wait_ready_timeout = std::chrono::seconds(15);
    ctx.channel_cfg.loop_interval = std::chrono::milliseconds(20);
    ctx.channel_cfg.input_queue_capacity = 4;
    ctx.backend_profile = &profile;
    ctx.vm_index = 0;
    ctx.vm_workdir = "/tmp/xiuos-program-seed-e2e";

    auto build_r = catalog.Build(
        std::string(channel::channel_backend_id::kQemuUartXiuos), ctx);
    if (!build_r.has_value()) {
        std::fprintf(stderr, "FAIL: catalog.Build: %s\n",
                     build_r.error().message.c_str());
        return 1;
    }
    auto chan = std::move(build_r.value());

    if (auto r = chan->Boot(); !r.ok()) {
        std::fprintf(stderr, "FAIL: Channel.Boot: %s\n",
                     r.error().message.c_str());
        return 1;
    }
    std::fprintf(stdout, "BOOT_OK\n");

    // ─── Drive seeds; tally coverage signal ───
    fuzzer::XiuosCoverageSignal signal;

    std::size_t processed = 0;
    std::size_t completions = 0;
    std::size_t interesting = 0;
    std::size_t skipped_load_fail = 0;
    std::size_t skipped_submit = 0;

    std::uint64_t executor_id = 0x10000000ull;

    for (const auto& seed_path : seed_paths) {
        ++processed;

        auto seed_r = progxiuos::LoadXiuosProgramSeed(seed_path);
        if (!seed_r.ok()) {
            std::fprintf(stderr, "  LOAD_FAIL %s: %s\n",
                         seed_path.string().c_str(),
                         seed_r.error().message.c_str());
            ++skipped_load_fail;
            continue;
        }
        const auto& seed = seed_r.value();
        const auto payload = seed.Encode();

        cc::ChannelDispatchRequest req;
        req.executor_id = ++executor_id;
        req.seed_id = static_cast<std::uint64_t>(processed);
        req.origin_seed_id = req.seed_id;
        req.payload = payload;
        req.timeout_ms = 5000;
        req.target_worker_id = 0;

        // Submit — may need to wait for the previous program's Completion to
        // free the single in-flight slot. DrainEvents (below) takes care of
        // that on the next iteration, but if we hit kBusy we wait and retry.
        auto submit = chan->Submit(req, std::chrono::microseconds(0));
        std::size_t retries = 0;
        while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 200) {
            // Drain pending events to free the slot.
            channel::EventList tmp;
            chan->DrainEvents(tmp, std::chrono::milliseconds(20));
            for (const auto& ev : tmp) {
                if (ev.IsCompletion()) {
                    ++completions;
                    if (signal.Sample(ev).interesting) ++interesting;
                }
            }
            submit = chan->Submit(req, std::chrono::microseconds(0));
            ++retries;
        }
        if (submit.status != cc::ChannelSubmitStatus::kAccepted) {
            std::fprintf(stderr, "  SUBMIT_FAIL %s status=%d\n",
                         seed_path.filename().string().c_str(),
                         static_cast<int>(submit.status));
            ++skipped_submit;
            continue;
        }

        // Drain at least one matching Completion for THIS executor_id
        // (others from prior submits may also surface and we feed them all
        // into the signal).
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool saw_this = false;
        while (!saw_this && std::chrono::steady_clock::now() < deadline) {
            channel::EventList events;
            chan->DrainEvents(events, std::chrono::milliseconds(100));
            for (const auto& ev : events) {
                if (ev.IsCompletion()) {
                    ++completions;
                    const auto contribution = signal.Sample(ev);
                    if (contribution.interesting) ++interesting;
                    if (ev.AsCompletion() &&
                        ev.AsCompletion()->ctx.executor_id == req.executor_id) {
                        saw_this = true;
                    }
                } else if (ev.IsAbnormal()) {
                    const auto* a = ev.AsAbnormal();
                    std::fprintf(stderr,
                        "  ABNORMAL %s executor_id=0x%lx kind=%d output_size=%zu "
                        "diag.error_code=%u diag.crash_signal=%u\n",
                        seed_path.filename().string().c_str(),
                        static_cast<unsigned long>(a ? a->ctx.executor_id : 0),
                        static_cast<int>(a ? a->kind : cc::AbnormalKind::kUnknown),
                        a ? a->output.size() : 0,
                        a ? a->diagnostics.error_code : 0u,
                        a ? a->diagnostics.crash_signal : 0u);
                } else if (ev.IsFault()) {
                    std::fprintf(stderr,
                        "  FAULT during seed %s\n",
                        seed_path.filename().string().c_str());
                }
            }
        }
        if (!saw_this) {
            std::fprintf(stderr,
                "  NO_COMPLETION %s within 5s\n",
                seed_path.filename().string().c_str());
        }
    }

    // ─── Final drain in case anything is still pending ───
    {
        channel::EventList tail;
        chan->DrainEvents(tail, std::chrono::milliseconds(200));
        for (const auto& ev : tail) {
            if (ev.IsCompletion()) {
                ++completions;
                if (signal.Sample(ev).interesting) ++interesting;
            }
        }
    }

    chan->Close();

    // ─── Acceptance assertions ───
    std::size_t accumulated_nonzero = 0;
    for (auto b : signal.accumulated()) if (b != 0) ++accumulated_nonzero;

    std::fprintf(stdout,
        "RESULT processed=%zu completions=%zu interesting=%zu "
        "accumulated_nonzero=%zu load_fail=%zu submit_fail=%zu\n",
        processed, completions, interesting, accumulated_nonzero,
        skipped_load_fail, skipped_submit);

    if (skipped_load_fail > 0) {
        std::fprintf(stderr, "FAIL: %zu seeds failed to load\n", skipped_load_fail);
        return 1;
    }
    if (completions < processed - skipped_submit) {
        std::fprintf(stderr,
            "FAIL: completions=%zu < processed=%zu - skipped_submit=%zu\n",
            completions, processed, skipped_submit);
        return 1;
    }
    if (interesting == 0) {
        std::fprintf(stderr,
            "FAIL: 0 interesting seeds (first non-empty coverage seed should always be interesting)\n");
        return 1;
    }
    if (accumulated_nonzero == 0) {
        std::fprintf(stderr, "FAIL: coverage bitmap is all-zero after batch\n");
        return 1;
    }

    std::fprintf(stdout, "XIUOS_PROGRAM_SEED_E2E_SMOKE_OK\n");
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_program_seed_e2e_smoke...\n");
    return RunSmoke();
}
