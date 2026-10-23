// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/startup/parse_launch_plan.hpp"

#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/config_parser/parse_config_from_json.hpp"
#include "refuzz/logging/host_logger.hpp"

#include "util/json.hpp"

#include <fstream>
#include <string>
#include <vector>

namespace refuzz::startup {
namespace {

core::Result<std::string> RequireStringField(const nlohmann::json& obj,
                                             const char* owner,
                                             const char* field)
{
    if (!obj.contains(field) || !obj[field].is_string()) {
        return std::unexpected(core::ComponentError::Config(
            "startup", std::string(owner) + "." + field + " must be string"));
    }
    auto value = obj[field].get<std::string>();
    if (value.empty()) {
        return std::unexpected(core::ComponentError::Config(
            "startup", std::string(owner) + "." + field + " must be non-empty"));
    }
    return value;
}


} // namespace

core::Result<ParseResult> ParseLaunchPlan(
    const std::string& json_path,
    ParseOptions options)
{
    std::ifstream in(json_path);
    if (!in) {
        return std::unexpected(core::ComponentError::Config(
            "startup", "failed to open json: " + json_path));
    }

    nlohmann::json root;
    try {
        in >> root;
    } catch (const std::exception& e) {
        return std::unexpected(core::ComponentError::Config(
            "startup", std::string("parse json failed: ") + e.what()));
    }

    if (!root.is_object()) {
        return std::unexpected(core::ComponentError::Config(
            "startup", "config root must be a JSON object"));
    }

    orchestrator::OrchestratorConfig cfg;
    if (!orchestrator::ParseConfigFromJson(root, cfg)) {
        return std::unexpected(core::ComponentError::Config(
            "startup", "ParseConfigFromJson failed for " + json_path));
    }

    LaunchPlan plan;
    plan.profile = cfg.profile;

    const auto comp = root.value("components", nlohmann::json::object());
    plan.mutator_engine    = comp.value("mutator_engine", std::string{});
    plan.scheduler_engine = comp.value("scheduler_engine", std::string{});
    plan.corpus_store     = comp.value("corpus_store", std::string{});
    plan.corpus_admission = comp.value("corpus_admission", std::string{});
    plan.feedback_engine  = comp.value("feedback_engine", std::string{});
    // 显式 channel_backend_id 优先(与 Resolver 注释 "显式 channel_backend_id 仍优先"
    // 一致):① components.channel_backend_id(显式覆盖)→ ② 解析出的
    // cfg.channel_backend_id(各 backend parser 已据 channel.backend_id 设)。
    // snapshot 例外:留空,让 Resolver 按 snapshot_mode 选 per-mode 后端(snapshot 配置
    // 不在 config 写死 backend)。**修复**:XiUOS family 同一 "xiuos" profile 下
    // qemu_uart_xiuos vs ch32_uart_xiuos 的区分原本丢失(profile 默认恒 qemu_uart_xiuos,
    // plan 又空 → 被默认填成 qemu)→ 现由 cfg.channel_backend_id 承载,物理板 backend 才选得对。
    plan.channel_backend_id = comp.value(
        "channel_backend_id",
        cfg.snapshot_fuzzing ? std::string{} : cfg.channel_backend_id);
    plan.target_toolkit   = comp.value("target_toolkit", std::string{});

    // Frontend 只传达"执行模式诉求",NOT 挑后端:把 snapshot_fuzzing 反映成后端无关的
    // plan.snapshot_mode。具体选哪个 channel backend 由 Resolver 按 "模式 → profile
    // per-mode 默认 + backend 能力" 转译,frontend 不写死任何 backend id。
    plan.snapshot_mode = cfg.snapshot_fuzzing;

    plan.config = std::move(cfg);
    // [Step 6 stage 清场] "stages" JSON 块已废(LaunchPlan 无 stage 字段);不再解析。

    std::optional<fuzzer::FeedbackEngineSpec> spec;
    if (root.contains("feedback_engine_spec")) {
        const auto& s = root["feedback_engine_spec"];
        if (!s.is_object()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "feedback_engine_spec must be object"));
        }
        fuzzer::FeedbackEngineSpec sp;
        if (!s.contains("engine_id") || !s["engine_id"].is_string()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "feedback_engine_spec.engine_id missing"));
        }
        sp.engine_id = s["engine_id"].get<std::string>();
        if (sp.engine_id.empty()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "feedback_engine_spec.engine_id empty"));
        }
        if (!s.contains("signal_ids") || !s["signal_ids"].is_array()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "feedback_engine_spec.signal_ids must be array"));
        }
        for (const auto& si : s["signal_ids"]) {
            if (!si.is_string()) {
                return std::unexpected(core::ComponentError::Config(
                    "startup", "feedback_engine_spec.signal_ids entries must be string"));
            }
            sp.signal_ids.push_back(si.get<std::string>());
        }
        if (sp.signal_ids.empty()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "feedback_engine_spec.signal_ids must be non-empty"));
        }
        if (!s.contains("aggregator_id") || !s["aggregator_id"].is_string()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "aggregator_id missing"));
        }
        sp.aggregator_id = s["aggregator_id"].get<std::string>();
        if (sp.aggregator_id.empty()) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "aggregator_id empty"));
        }
        // [verdict 重构] dispatcher_id 已废弃:准入行为现由 corpus admit-mode 决定。
        if (s.contains("aggregator_context")) {
            const auto& ac = s["aggregator_context"];
            if (!ac.is_object()) {
                return std::unexpected(core::ComponentError::Config(
                    "startup", "aggregator_context must be object"));
            }
            if (ac.contains("signal_weights") && ac["signal_weights"].is_object()) {
                for (auto it = ac["signal_weights"].begin(); it != ac["signal_weights"].end(); ++it) {
                    if (!it.value().is_number()) {
                        return std::unexpected(core::ComponentError::Config(
                            "startup", "signal_weights value must be number"));
                    }
                    sp.aggregator_ctx.signal_weights[it.key()] = it.value().get<double>();
                }
            }
            if (ac.contains("interesting_threshold") && ac["interesting_threshold"].is_number()) {
                sp.aggregator_ctx.interesting_threshold = ac["interesting_threshold"].get<double>();
            }
        }
        spec = std::move(sp);
    }

    if (spec.has_value() && !plan.feedback_engine.empty()) {
        refuzz::logging::HostLineBuilder("Startup", "override")
            << "components.feedback_engine='" << plan.feedback_engine
            << "' will be overridden by feedback_engine_spec.engine_id='"
            << spec->engine_id << "'\n";
    }

    auto ovr = OverrideLaunchPlanFromArgs(plan, spec, options);
    if (!ovr) {
        return std::unexpected(ovr.error());
    }

    ParseResult out;
    out.plan = std::move(plan);
    out.ad_hoc_feedback_spec = std::move(spec);
    return out;
}

} // namespace refuzz::startup
