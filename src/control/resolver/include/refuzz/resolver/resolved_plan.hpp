// Copyright 2026 reFuzz project author -------youngkk.
//
// ResolvedPlan
//
// Resolver 的输出。与 LaunchPlan 字段结构一致,但语义保证:
//   1. 所有选择字段非空(Resolver 已按 profile.defaults 填空);
//   2. config 已经过 profile.configure() 注入 target-specific 修改;
//   3. 所有选择 id 都已在对应 Catalog 中查过、确认存在。
//
// 独立的类型(不是 LaunchPlan 的别名)保证 Assembler 只接受已解析的计划,
// 防止"未 Resolve 的 LaunchPlan 直接喂给 Assembler"这类错误在编译期就被挡住。

#pragma once

// [Step 6 stage 清场] stage_build_context.hpp(StageSpec)已删;ResolvedPlan 不再含 stage 字段。
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/orchestrator/orchestrator_config.hpp"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::resolver {

struct ResolvedPlan {
    // Profile 名称。
    std::string profile;

    // ── 组件选择(保证非空、且已在 catalog 中查到) ──
    // 与 LaunchPlan 字段一一对应;详见 startup/launch_plan.hpp 的 catalog 映射。
    std::string mutator_engine;
    std::string scheduler_engine;
    std::string corpus_store;
    std::string corpus_admission;
    std::string feedback_engine;
    std::string channel_backend_id;
    std::string target_toolkit;

    // ── Feedback ad-hoc spec ──
    //
    //「模式二」：交互 / JSON 前端允许用户勾选信号、选聚合、
    // 选分发临时合成一个未注册到 catalog 的 engine。Resolver 约定：
    //   * 若 ad_hoc_feedback_spec 有值，Assembler 用它临时 BuildFromSpec，
    //     并把生成 engine 的名字设为 active；此时忽略 feedback_engine。
    //   * 否则走命名 engine，Assembler 在 FeedbackEngineCatalog 中查 id。
    // Spec 的 engine_id 不得与任何已注册命名 engine 冲突；由 Resolver 校验。
    std::optional<fuzzer::FeedbackEngineSpec> ad_hoc_feedback_spec;

    // 经过 profile.configure 注入的最终配置。
    orchestrator::OrchestratorConfig config;

    // [Step 6 stage 清场] stage_specs / producer_chain / consumer_chain 已删(stage framework 退役)。
};

} // namespace refuzz::resolver
