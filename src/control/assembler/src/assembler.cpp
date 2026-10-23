// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/assembler/assembler.hpp"

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/factory/mock_backend_profile.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/control/loop/pending_seed_map.hpp"  // [Step 6] 显式运行时共享态
#include "refuzz/core/metrics/channel_metrics.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/crash/target_toolkit_catalog.hpp"
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/feedback/priority/syzkaller_priority_calculator.hpp"   // [v2 batch 3 PR-Y] default fallback
#include "refuzz/feedback/saturation/kernel_coverage_saturation_filter.hpp"  // [v2 batch 3 G5] default fallback
#include "refuzz/feedback/retry/syzkaller_retry_policy.hpp"              // [v2 SubT-B] default fallback
#include "refuzz/feedback/stability/signal_set_intersection_oracle.hpp"  // [v2 SubT-A] default fallback
#include "refuzz/orchestrator/profile_registry.hpp"
#include "refuzz/control/support/support_checker.hpp"   // [syscall-support-detection]
#include "refuzz/program/syz/target.hpp"
#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"  // [future_cht] static ChoiceTable
#include "refuzz/scheduler/horizon/seed_band2.hpp"        // [future_band2] shadow candidate
#include "refuzz/scheduler/horizon/static_belief_graph.hpp"  // [belief-graph] static prior

#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <utility>
#include <vector>

namespace refuzz::assembler {
namespace {

const char* FindFirstNullCatalog(const resolver::CatalogSet& c)
{
    if (c.mutator == nullptr) {
        return "mutator";
    }
    if (c.scheduler == nullptr) {
        return "scheduler";
    }
    if (c.corpus_store == nullptr) {
        return "corpus_store";
    }
    if (c.feedback == nullptr) {
        return "feedback";
    }
    if (c.signals == nullptr) {
        return "signals";
    }
    if (c.aggregators == nullptr) {
        return "aggregators";
    }
    if (c.channel == nullptr) {
        return "channel";
    }
    if (c.toolkit == nullptr) {
        return "toolkit";
    }
    return nullptr;
}

std::string ReplaceVmIdArg(const std::string& cmd, uint32_t vm_id)
{
    const std::string flag = "--vm-id";
    const std::string value = std::to_string(vm_id);
    const size_t pos = cmd.find(flag);
    if (pos == std::string::npos) {
        std::string out = cmd;
        if (!out.empty()) {
            out += ' ';
        }
        out += flag + " " + value;
        return out;
    }

    size_t value_begin = pos + flag.size();
    while (value_begin < cmd.size() && cmd[value_begin] == ' ') {
        ++value_begin;
    }

    std::string out = cmd;
    if (value_begin >= cmd.size()) {
        out += " " + value;
        return out;
    }

    const size_t value_end = cmd.find(' ', value_begin);
    if (value_end == std::string::npos) {
        out.replace(value_begin, std::string::npos, value);
    } else {
        out.replace(value_begin, value_end - value_begin, value);
    }
    return out;
}

std::unique_ptr<channel::factory::IChannelBackendProfile>
CloneBackendProfileForFuzzChannel(
    const channel::factory::IChannelBackendProfile& base_profile,
    uint32_t channel_index,
    uint32_t base_vm_id)
{
    if (const auto* qemu =
            dynamic_cast<const channel::factory::QemuIvshmemLinuxProfile*>(
                &base_profile)) {
        auto cloned = std::make_unique<channel::factory::QemuIvshmemLinuxProfile>(*qemu);
        cloned->runtime.instance.index = static_cast<int>(channel_index);

        if (channel_index > 0) {
            const std::string suffix = "_fuzz_" + std::to_string(channel_index);
            cloned->infra.shm_path = qemu->infra.shm_path + suffix;
            cloned->transport.doorbell_socket_path =
                qemu->transport.doorbell_socket_path + suffix;
            cloned->runtime.instance.ivshmem_path = cloned->infra.shm_path;
            cloned->runtime.instance.ivshmem_socket =
                cloned->transport.doorbell_socket_path;
            if (!cloned->runtime.instance.serial_log_path.empty()) {
                cloned->runtime.instance.serial_log_path += suffix;
            }
        }

        cloned->worker.worker_start_cmd =
            ReplaceVmIdArg(cloned->worker.worker_start_cmd,
                           base_vm_id + channel_index);
        return cloned;
    }

    if (dynamic_cast<const channel::factory::MockBackendProfile*>(
            &base_profile) != nullptr) {
        return std::make_unique<channel::factory::MockBackendProfile>();
    }

    return nullptr;
}

} // namespace

core::Result<AssembledBundle> Assembler::Assemble(
    const resolver::ResolvedPlan& resolved,
    const resolver::CatalogSet& catalogs,
    const AssembleContext& ctx)
{
    if (ctx.profile_registry == nullptr) {
        return std::unexpected(
            core::ComponentError::Config("assembler", "profile_registry null"));
    }

    if (const char* missing = FindFirstNullCatalog(catalogs)) {
        return std::unexpected(core::ComponentError::Config(
            "assembler",
            std::string("CatalogSet.") + missing + " is null"));
    }

    // [v2 batch 3 PR-W1 — fail-loud framework primitive 装配,关闭 batch 2 L1 silent-fallback debt]
    //
    // 父 plan §2 P7:framework primitive silent fallback 是 footgun。语义:
    //   prof == nullptr               → fallback kernel default(profile 都没找到先撑着,语义同前)
    //   prof != nullptr && !factory   → ComponentError(profile 作者忘 set,bug,不 mask)
    //   prof != nullptr && factory()返 null → ComponentError(factory 实现 bug,不 mask)
    //
    // **位置**:必须在 corpus_store / channel / shm 等有副作用的构造前 — 避免 missing-factory
    // 报错时已经 unlink/open/ftruncate/mmap 了 ivshmem(High review finding 2026-05-09)。
    // factory 调用本身廉价(make_unique<XYZ>),提前到 catalog 校验后立即跑无性能代价。
    //
    // prof 是 registry 反查到的 ProfileDefaults*;后续 repro channel 派生(原 line 215+)
    // 复用此指针。
    const auto* prof = ctx.profile_registry->Find(resolved.profile);
    std::unique_ptr<fuzzer::IStabilityOracle>    stability_oracle_built;
    std::unique_ptr<fuzzer::IRetryPolicy>        retry_policy_built;
    std::unique_ptr<fuzzer::IPriorityCalculator> priority_calculator_built;  // [v2 PR-Y]
    std::unique_ptr<fuzzer::ISaturationFilter>   saturation_filter_built;    // [v2 G5]
    if (prof == nullptr) {
        // profile 都没 Find 到 — 跟 batch 2 silent-fallback 行为一致先撑着,kernel default。
        stability_oracle_built    = std::make_unique<fuzzer::SignalSetIntersectionOracle>();
        retry_policy_built        = std::make_unique<fuzzer::SyzkallerRetryPolicy>();
        priority_calculator_built = std::make_unique<fuzzer::SyzkallerPriorityCalculator>();  // [v2 PR-Y]
        saturation_filter_built   = std::make_unique<fuzzer::KernelCoverageSaturationFilter>();  // [v2 G5]
    } else {
        if (!prof->make_stability_oracle) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' missing make_stability_oracle factory (P7 — silent fallback removed batch 3 PR-W1)"));
        }
        stability_oracle_built = prof->make_stability_oracle();
        if (stability_oracle_built == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' make_stability_oracle returned nullptr (factory bug)"));
        }
        if (!prof->make_retry_policy) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' missing make_retry_policy factory (P7 — silent fallback removed batch 3 PR-W1)"));
        }
        retry_policy_built = prof->make_retry_policy();
        if (retry_policy_built == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' make_retry_policy returned nullptr (factory bug)"));
        }
        // [v2 batch 3 PR-Y] priority_calculator factory — 同 SubT-A/B 模板 P7 fail-loud。
        if (!prof->make_priority_calculator) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' missing make_priority_calculator factory (P7 — silent fallback removed batch 3 PR-W1)"));
        }
        priority_calculator_built = prof->make_priority_calculator();
        if (priority_calculator_built == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' make_priority_calculator returned nullptr (factory bug)"));
        }
        // [v2 batch 3 G5] saturation_filter factory — 同 PR-Y 模板 P7 fail-loud。
        if (!prof->make_saturation_filter) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' missing make_saturation_filter factory (P7 — silent fallback removed batch 3 PR-W1)"));
        }
        saturation_filter_built = prof->make_saturation_filter();
        if (saturation_filter_built == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "assembler",
                std::string("profile '") + prof->name +
                "' make_saturation_filter returned nullptr (factory bug)"));
        }
    }

    auto corpus_built =
        catalogs.corpus_store->Build(resolved.corpus_store, fuzzer::CorpusStoreTraits::BuildContext{});
    if (!corpus_built) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.corpus_store",
            resolved.corpus_store + ": " + corpus_built.error().message));
    }
    std::unique_ptr<fuzzer::ICorpusStore> corpus_store = std::move(*corpus_built);

    auto feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    // [v2 Epic 5 PR-5-B] cmp dedupe truth-store — separate HashFeedbackStore
    // instance per Q3 decision; persisted at Stop alongside the PC store but
    // to a distinct path (orchestrator: coverage_persist_path + ".cmp").
    auto cmp_feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    auto all_pc_feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    auto corpus_pc_feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    auto all_edge_feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    auto corpus_edge_feedback_store = std::make_unique<fuzzer::HashFeedbackStore>();
    auto seed_id_alloc  = std::make_unique<fuzzer::SeedIdAllocator>();

    // TargetToolkitTraits::BuildContext 在 catalog 中为空; sanitizer 等参数在
    // toolkit->create_* 调用时经 TargetToolkitBuildArgs 传入(见 target_toolkit_catalog)。
    auto tk_built = catalogs.toolkit->Build(
        resolved.target_toolkit, crash::TargetToolkitTraits::BuildContext{});
    if (!tk_built) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.toolkit",
            resolved.target_toolkit + ": " + tk_built.error().message));
    }
    std::unique_ptr<crash::TargetToolkit> target_toolkit = std::move(*tk_built);

    auto mutator_manager = std::make_unique<fuzzer::MutatorManager>();
    // [v1 BuildContext 仅 corpus_store — ROLLBACK: uncomment 这两行,删除 v2 块]
    // fuzzer::MutatorEngineTraits::BuildContext mut_ctx;
    // mut_ctx.corpus_store = corpus_store.get();

    fuzzer::MutatorEngineTraits::BuildContext mut_ctx;
    mut_ctx.corpus_store         = corpus_store.get();
    // [syscall-support-detection] Resolve the enabled set (whitelist ∩ supported)
    // host-side and thread the per-id mask into the mutator. Under setuid/namespace
    // the cap-gated pseudos (mount/kvm/usb) are unsupported and filtered out here.
    control::support::SupportEnv support_env;
    support_env.sandbox_is_none =
        resolved.config.target.sandbox_mode ==
        ::refuzz::orchestrator::SandboxMode::kNone;
    auto enabled = control::support::resolve_enabled_calls(
        ::refuzz::program::syz::Target::linux_amd64(),
        resolved.config.target.enable_syscalls,
        resolved.config.target.disable_syscalls,
        support_env);
    if (!enabled.ok) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.support", enabled.error));
    }
    mut_ctx.enabled_calls_mask = std::move(enabled.mask);
    for (const auto* entry : catalogs.mutator->All()) {
        auto built = catalogs.mutator->Build(entry->meta.id, mut_ctx);
        if (!built) {
            return std::unexpected(core::ComponentError::Config(
                "assembler.mutator",
                std::string(entry->meta.id) + ": " + built.error().message));
        }
        mutator_manager->AddEngine(std::move(*built), /*activate=*/false);
    }
    if (!mutator_manager->SwitchEngineByName(resolved.mutator_engine)) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.mutator",
            "SwitchEngineByName failed: " + resolved.mutator_engine));
    }

    // [seed-future-value] build the structural future(seed) signal when enabled
    // (config fuzzer.seed_horizon_enabled). Injected into every scheduler engine
    // via the catalog BuildContext; the engine caches future(seed) at OnSeedAdded.
    // Off → null → SeedFutureValue returns 0 (no model build, no per-admit cost).
    // Owned by the bundle (declared before scheduler_manager → outlives engines).
    std::unique_ptr<fuzzer::SeedHorizon> seed_horizon;
    if (resolved.config.fuzzer.seed_horizon_enabled) {
        const auto& target = ::refuzz::program::syz::Target::linux_amd64();
        seed_horizon = std::make_unique<fuzzer::SeedHorizon>(target);
        // [future_cht / Psyzkaller] inject the static call-transition successor
        // table (top-K per call) from the ChoiceTable. Row-sums are constant after
        // normalize_rows(), so the SIGNAL is the masked horizon (TransitionValue);
        // here we just hand over the sparse successor priors (id-indexed).
        ::refuzz::mutator::syz_v2::ChoiceTable ct;
        ct.build(target);
        const auto& prios = ct.prios();
        constexpr std::size_t kTopSucc = 32;
        std::vector<std::vector<std::pair<int, double>>> succ(prios.size());
        for (std::size_t i = 0; i < prios.size(); ++i) {
            const auto& row = prios[i];
            std::vector<std::pair<int, double>> nz;
            for (std::size_t j = 0; j < row.size(); ++j) {
                if (j != i && row[j] > 0) {
                    nz.emplace_back(static_cast<int>(j), static_cast<double>(row[j]));
                }
            }
            const std::size_t k = std::min(kTopSucc, nz.size());
            std::partial_sort(nz.begin(), nz.begin() + k, nz.end(),
                              [](const auto& a, const auto& b) { return a.second > b.second; });
            nz.resize(k);
            succ[i] = std::move(nz);
        }
        seed_horizon->SetCallSucc(std::move(succ));
    }

    // [future_band2] band-② shadow candidate (gated on seed_horizon + a map path).
    // Loads the static function→block-count map; inert if the path is empty/unreadable.
    std::unique_ptr<fuzzer::SeedBand2> seed_band2;
    if (resolved.config.fuzzer.seed_horizon_enabled &&
        !resolved.config.fuzzer.seed_band2_map_path.empty()) {
        auto b2 = std::make_unique<fuzzer::SeedBand2>();
        if (b2->LoadFunctionMap(resolved.config.fuzzer.seed_band2_map_path)) {
            seed_band2 = std::move(b2);
        }
    }

    // [belief-graph] static 8-mechanism unlock-potential prior (graph_M.tsv, offline-produced by
    // scripts/seed_horizon/substrate). Gated on the path alone (independent of seed_horizon). Inert if empty/
    // unreadable. SHADOW ONLY — the scheduler caches belief(seed) at admit (SeedBeliefValue).
    std::unique_ptr<fuzzer::StaticBeliefGraph> belief_graph;
    if (!resolved.config.fuzzer.belief_graph_path.empty()) {
        auto bg = std::make_unique<fuzzer::StaticBeliefGraph>();
        if (bg->LoadFromTsv(resolved.config.fuzzer.belief_graph_path)) {
            belief_graph = std::move(bg);
        }
    }

    auto scheduler_manager = std::make_unique<fuzzer::SchedulerManager>();
    // [value-weighted policies] 把 corpus store 交给 scheduler engine,size/rarity
    // 加权 policy 据它读 per-seed cover。corpus_store 比 scheduler_manager 先声明
    // 于 bundle(后析构),raw ptr 生命周期安全。
    fuzzer::SchedulerEngineTraits::BuildContext sched_ctx{};
    sched_ctx.corpus_store = corpus_store.get();
    sched_ctx.seed_horizon = seed_horizon.get();  // [seed-future-value] null = off
    sched_ctx.seed_band2   = seed_band2.get();    // [future_band2] null = off
    sched_ctx.belief_graph = belief_graph.get();  // [belief-graph] null = off
    for (const auto* entry : catalogs.scheduler->All()) {
        auto built = catalogs.scheduler->Build(entry->meta.id, sched_ctx);
        if (!built) {
            return std::unexpected(core::ComponentError::Config(
                "assembler.scheduler",
                std::string(entry->meta.id) + ": " + built.error().message));
        }
        scheduler_manager->AddEngine(std::move(*built));
    }
    if (!scheduler_manager->SwitchEngineByName(resolved.scheduler_engine)) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.scheduler",
            "SwitchEngineByName failed: " + resolved.scheduler_engine));
    }

    auto feedback_manager = std::make_unique<fuzzer::FeedbackManager>();
    fuzzer::FeedbackEngineTraits::BuildContext fb_ctx;
    fb_ctx.signals        = catalogs.signals;
    fb_ctx.aggregators    = catalogs.aggregators;
    fb_ctx.feedback_store = feedback_store.get();
    // [v1 coverage_sink 装配 — ROLLBACK: uncomment]
    // fb_ctx.coverage_sink  = ctx.coverage_tracker;
    // [v2 PR-K-0 — sink/tracker 已删除,见 kcov-coverage-curve.md §4.2]
    // [v2 Epic 5 PR-5-B — cmp dedupe store wired through engine→signal ctx]
    fb_ctx.cmp_feedback_store = cmp_feedback_store.get();
    fb_ctx.coverage_config.raw_pc               = resolved.config.coverage_raw_pc;
    fb_ctx.coverage_config.cover_edges          = resolved.config.coverage_cover_edges;
    fb_ctx.coverage_config.max_entries_per_exec = resolved.config.coverage_max_pcs_per_exec;
    fb_ctx.coverage_config.sample_rate          = resolved.config.coverage_sample_rate;
    fb_ctx.coverage_config.filter_signal        = resolved.config.coverage_filter_signal;
    fb_ctx.coverage_config.kernel_text_start    = resolved.config.coverage_kernel_text_start;
    fb_ctx.coverage_config.kernel_text_end      = resolved.config.coverage_kernel_text_end;
    // [v2 batch 3 PR-Y] priority_calculator 注入 — KcovCoverageSignal 通过
    // SignalTraits::BuildContext.priority_calculator 拿到 raw ptr。所有权仍在
    // bundle.priority_calculator(已在 line 304 move 进 bundle)。
    fb_ctx.priority_calculator = priority_calculator_built.get();
    // [v2 batch 3 G5] saturation_filter 注入 — 同 PR-Y pattern。
    fb_ctx.saturation_filter   = saturation_filter_built.get();

    core::Result<std::unique_ptr<fuzzer::IFeedbackEngine>> built_fb;
    if (resolved.ad_hoc_feedback_spec.has_value()) {
        built_fb = fuzzer::BuildFromSpec(fb_ctx, *resolved.ad_hoc_feedback_spec);
    } else {
        built_fb = catalogs.feedback->Build(resolved.feedback_engine, fb_ctx);
    }
    if (!built_fb) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.feedback",
            resolved.feedback_engine + ": " + built_fb.error().message));
    }
    feedback_manager->AddEngine(std::move(*built_fb));
    if (!feedback_manager->SwitchEngineByName(resolved.feedback_engine)) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.feedback",
            "SwitchEngineByName failed: " + resolved.feedback_engine));
    }

    if (resolved.config.channel_backend == nullptr) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.channel", "resolved.config.channel_backend is null"));
    }
    channel::ChannelConfig main_cfg = resolved.config.channel_common;
    if (main_cfg.channel_id == 0) {
        main_cfg.channel_id = 1;
    }
    main_cfg.use = channel::ChannelUse::kFuzz;
    channel::ChannelBuildContext main_ctx;
    main_ctx.channel_cfg     = main_cfg;
    main_ctx.backend_profile = resolved.config.channel_backend.get();
    main_ctx.vm_index        = 0;
    main_ctx.vm_workdir      = resolved.config.layout.vm_dir(0);
    auto main_built =
        catalogs.channel->Build(resolved.channel_backend_id, main_ctx);
    if (!main_built) {
        return std::unexpected(core::ComponentError::Config(
            "assembler.channel",
            resolved.channel_backend_id + ": " + main_built.error().message));
    }
    std::unique_ptr<channel::IChannel> main_channel = std::move(*main_built);

    AssembledBundle out;

    std::vector<std::unique_ptr<channel::IChannel>> additional_fuzz_channels;
    const uint32_t fuzz_channel_count =
        std::max<uint32_t>(1, resolved.config.fuzz_channel_count);
    if (fuzz_channel_count > 1 && ctx.metric_registry != nullptr) {
        out.additional_fuzz_channel_metrics.reserve(fuzz_channel_count - 1);
    }
    for (uint32_t i = 1; i < fuzz_channel_count; ++i) {
        auto fuzz_profile = CloneBackendProfileForFuzzChannel(
            *resolved.config.channel_backend,
            i,
            resolved.config.vm_id);
        if (fuzz_profile == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "assembler.channel",
                "cannot derive additional fuzz channel for backend profile '" +
                    std::string{resolved.config.channel_backend->BackendId()} + "'"));
        }

        channel::ChannelConfig fuzz_cfg = resolved.config.channel_common;
        fuzz_cfg.channel_id = main_cfg.channel_id + i;
        fuzz_cfg.use = channel::ChannelUse::kFuzz;

        channel::ChannelBuildContext fctx;
        fctx.channel_cfg     = fuzz_cfg;
        fctx.backend_profile = fuzz_profile.get();
        fctx.vm_index        = i;
        fctx.vm_workdir      = resolved.config.layout.vm_dir(i);

        auto fuzz_built =
            catalogs.channel->Build(resolved.channel_backend_id, fctx);
        if (!fuzz_built) {
            return std::unexpected(core::ComponentError::Config(
                "assembler.channel",
                resolved.channel_backend_id + " fuzz channel " +
                    std::to_string(i) + ": " + fuzz_built.error().message));
        }

        additional_fuzz_channels.push_back(std::move(*fuzz_built));
        if (ctx.metric_registry != nullptr) {
            out.additional_fuzz_channel_metrics.emplace_back();
            out.additional_fuzz_channel_metrics.back().Bind(
                *ctx.metric_registry, fuzz_cfg.channel_id);
        }
    }

    std::vector<std::unique_ptr<channel::IChannel>> repro_channels;
    // [v2 metric bus — Step 5a] repro_channel_metrics is built in the same loop as
    // repro_channels so that each metrics entry uses the authoritative repro_cfg.channel_id
    // rather than a vector index that diverges when iterations are skipped (null profile
    // or build failure causes `continue`).
    //
    // Reserve before the loop to prevent pointer invalidation after Bind.
    // The worst-case count is dedicated_vm_count; actual size may be smaller.
    // prof 已在函数顶部 lookup 过(PR-W1 fail-loud factory 装配前置 — 见函数顶部注释)。
    if (prof != nullptr && resolved.config.repro.enable &&
        resolved.config.repro.dedicated_vm_count > 0 && prof->derive_repro_channel_cfg) {
        if (ctx.metric_registry != nullptr) {
            out.repro_channel_metrics.reserve(resolved.config.repro.dedicated_vm_count);
        }
        for (uint32_t i = 0; i < resolved.config.repro.dedicated_vm_count; ++i) {
            auto [repro_cfg, repro_profile] =
                prof->derive_repro_channel_cfg(resolved.config, i);
            if (repro_profile == nullptr) {
                continue;
            }
            repro_cfg.use = channel::ChannelUse::kRepro;
            channel::ChannelBuildContext rctx;
            rctx.channel_cfg     = repro_cfg;
            rctx.backend_profile = repro_profile.get();
            rctx.vm_index        = 0;
            rctx.vm_workdir      = resolved.config.layout.repro_dir(i);
            auto rch = catalogs.channel->Build(resolved.channel_backend_id, rctx);
            if (!rch) {
                continue;
            }
            repro_channels.push_back(std::move(*rch));
            // [v2 metric bus — Step 5a] Bind using repro_cfg.channel_id (authoritative),
            // not vector index. This is correct even when earlier iterations were skipped.
            if (ctx.metric_registry != nullptr) {
                out.repro_channel_metrics.emplace_back();
                out.repro_channel_metrics.back().Bind(*ctx.metric_registry, repro_cfg.channel_id);
            }
        }
    }

    out.corpus_store       = std::move(corpus_store);
    out.seed_horizon       = std::move(seed_horizon);  // [seed-future-value]
    out.seed_band2         = std::move(seed_band2);    // [future_band2]
    out.belief_graph       = std::move(belief_graph);  // [belief-graph]
    out.feedback_store     = std::move(feedback_store);
    // [v2 Epic 5 PR-5-B — cmp dedupe store ownership transfers to bundle]
    out.cmp_feedback_store = std::move(cmp_feedback_store);
    out.all_pc_feedback_store = std::move(all_pc_feedback_store);
    out.corpus_pc_feedback_store = std::move(corpus_pc_feedback_store);
    out.all_edge_feedback_store = std::move(all_edge_feedback_store);
    out.corpus_edge_feedback_store = std::move(corpus_edge_feedback_store);
    out.seed_id_alloc      = std::move(seed_id_alloc);
    // [v2 batch 3 PR-W1 + PR-Y] framework primitive 已在函数顶部 fail-loud 校验
    // + 构造,这里只是从 local 转移所有权进 bundle。详顶部注释。
    out.stability_oracle    = std::move(stability_oracle_built);
    out.retry_policy        = std::move(retry_policy_built);
    out.priority_calculator = std::move(priority_calculator_built);  // [v2 PR-Y]
    out.saturation_filter   = std::move(saturation_filter_built);    // [v2 G5]
    out.target_toolkit     = std::move(target_toolkit);
    out.feedback_manager   = std::move(feedback_manager);
    out.scheduler_manager  = std::move(scheduler_manager);
    out.mutator_manager    = std::move(mutator_manager);
    out.main_channel       = std::move(main_channel);
    out.additional_fuzz_channels = std::move(additional_fuzz_channels);
    out.repro_channels     = std::move(repro_channels);

    // [v2 metric bus — Step 5a] Bind main channel metrics.
    // Bind is idempotent; nullptr registry degrades to no-op (old behavior).
    if (ctx.metric_registry != nullptr) {
        out.main_channel_metrics.Bind(*ctx.metric_registry, main_cfg.channel_id);
    }

    // ── Step 10: 显式运行时共享态构造(stage framework 已物删)──
    //   唯一保留的运行时共享态是 PendingSeedMap(候选区 + triage-pending buffer)。旧的
    //   StageChain / StageSharedState / FollowUpDispatcher + 9 条 chain 校验已随 stage
    //   framework 一并删除 —— job 模型下运行时工作由 job_scheduler 表达,未认领 completion
    //   由 FuzzerLoop::ProcessCatchAllCompletion 承接。orchestrator 物化 boot corpus 进它。
    out.pending_seed_map = std::make_shared<control::PendingSeedMap>();

    return out;
}

} // namespace refuzz::assembler
