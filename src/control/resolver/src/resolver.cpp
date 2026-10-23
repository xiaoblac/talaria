// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/resolver/resolver.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace refuzz::resolver {
namespace {

void FillIfEmpty(std::string& field, const std::string& def)
{
    if (field.empty()) {
        field = def;
    }
}

const char* FindFirstNullCatalog(const CatalogSet& c)
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

} // namespace

core::Result<ResolvedPlan> Resolver::Resolve(
    startup::LaunchPlan plan,
    const orchestrator::ProfileRegistry& registry,
    const CatalogSet& catalogs,
    ResolveOptions options)
{
    if (plan.profile.empty()) {
        return std::unexpected(core::ComponentError::Config(
            "resolver", "LaunchPlan.profile is empty"));
    }
    const auto* prof = registry.Find(plan.profile);
    if (prof == nullptr) {
        return std::unexpected(core::ComponentError::Config(
            "resolver", "profile not found: " + plan.profile));
    }

    FillIfEmpty(plan.mutator_engine, prof->defaults.mutator_engine);
    FillIfEmpty(plan.scheduler_engine, prof->defaults.scheduler_engine);
    FillIfEmpty(plan.corpus_store, prof->defaults.corpus_store);
    FillIfEmpty(plan.corpus_admission, prof->defaults.corpus_admission);
    if (!options.ad_hoc_feedback_spec.has_value()) {
        FillIfEmpty(plan.feedback_engine, prof->defaults.feedback_engine);
    }
    // [模式驱动后端选择] snapshot 执行模式且未显式指定 backend → 用 profile 声明的
    // per-mode(snapshot)默认;否则 continuous 默认。显式 channel_backend_id 仍优先
    // (FillIfEmpty 只填空)。"模式 → 后端" 的映射在 profile 里声明,不在 frontend 写死。
    {
        const std::string& chan_default =
            (plan.snapshot_mode && !prof->snapshot_channel_backend_id.empty())
                ? prof->snapshot_channel_backend_id
                : prof->defaults.channel_backend_id;
        FillIfEmpty(plan.channel_backend_id, chan_default);
    }
    // [能力校验] 请求 snapshot 则所选 backend 必须声明 snapshot 能力;否则明确报错
    // (该 profile 没有支持 snapshot 的后端),而不是静默退回 continuous。
    if (plan.snapshot_mode &&
        !refuzz::channel::ChannelBackendSupportsSnapshot(plan.channel_backend_id)) {
        return std::unexpected(core::ComponentError::Config(
            "resolver",
            "snapshot execution requested but channel backend '" +
                plan.channel_backend_id + "' does not support snapshot (profile '" +
                plan.profile + "')"));
    }
    FillIfEmpty(plan.target_toolkit, prof->defaults.target_toolkit);


    if (prof->configure) {
        if (auto r = prof->configure(plan.config); !r) {
            return std::unexpected(r.error());
        }
    }


    if (prof->validate) {
        std::string err;
        if (!prof->validate(plan.config, err)) {
            return std::unexpected(core::ComponentError::Config(
                "resolver", "profile validation failed: " + err));
        }
    }

    if (const char* missing = FindFirstNullCatalog(catalogs)) {
        return std::unexpected(core::ComponentError::Config(
            "resolver", std::string("CatalogSet.") + missing + " is null"));
    }

    auto must_find = [](const auto& cat, const std::string& id, const char* field)
        -> core::Result<void> {
        if (cat.Find(id) == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "resolver",
                std::string(field) + " id not registered: " + id));
        }
        return {};
    };

    if (auto r = must_find(*catalogs.mutator, plan.mutator_engine, "mutator_engine"); !r) {
        return std::unexpected(r.error());
    }
    if (auto r = must_find(*catalogs.scheduler, plan.scheduler_engine, "scheduler_engine"); !r) {
        return std::unexpected(r.error());
    }
    if (auto r = must_find(*catalogs.corpus_store, plan.corpus_store, "corpus_store"); !r) {
        return std::unexpected(r.error());
    }
    if (auto r = must_find(*catalogs.channel, plan.channel_backend_id, "channel_backend_id");
        !r) {
        return std::unexpected(r.error());
    }
    if (auto r = must_find(*catalogs.toolkit, plan.target_toolkit, "target_toolkit"); !r) {
        return std::unexpected(r.error());
    }

    if (options.ad_hoc_feedback_spec.has_value()) {
        const auto& spec = *options.ad_hoc_feedback_spec;
        if (catalogs.feedback->Find(spec.engine_id) != nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "resolver",
                "ad-hoc engine_id collides with named engine: " + spec.engine_id));
        }
        if (auto r = must_find(*catalogs.aggregators, spec.aggregator_id, "ad_hoc.aggregator");
            !r) {
            return std::unexpected(r.error());
        }
        for (const auto& sid : spec.signal_ids) {
            if (auto r = must_find(*catalogs.signals, sid, "ad_hoc.signal"); !r) {
                return std::unexpected(r.error());
            }
        }
    } else {
        if (auto r = must_find(*catalogs.feedback, plan.feedback_engine, "feedback_engine");
            !r) {
            return std::unexpected(r.error());
        }
    }

    ResolvedPlan out;
    out.profile          = std::move(plan.profile);
    out.mutator_engine   = std::move(plan.mutator_engine);
    out.scheduler_engine = std::move(plan.scheduler_engine);
    out.corpus_store     = std::move(plan.corpus_store);
    out.corpus_admission = std::move(plan.corpus_admission);
    if (options.ad_hoc_feedback_spec.has_value()) {
        out.feedback_engine = options.ad_hoc_feedback_spec->engine_id;
    } else {
        out.feedback_engine = std::move(plan.feedback_engine);
    }
    out.channel_backend_id = std::move(plan.channel_backend_id);
    out.target_toolkit     = std::move(plan.target_toolkit);
    out.ad_hoc_feedback_spec = std::move(options.ad_hoc_feedback_spec);
    out.config               = std::move(plan.config);
    return out;
}

} // namespace refuzz::resolver
