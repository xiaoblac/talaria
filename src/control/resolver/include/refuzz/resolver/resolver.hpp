// Copyright 2026 reFuzz project author -------youngkk.
//
// Resolver
//
// 把 LaunchPlan(用户意图,可能含空字段)结合 ProfileDefaults(profile 默认)
// 和 CatalogSet(各领域注册的 id)解析为 ResolvedPlan(所有字段已敲定、id 已
// 校验存在)。Resolver 是纯函数:相同输入 → 相同输出 + 相同错误。
//
// 算法步骤(顺序保证):
//   1. profile lookup       — registry.Find(plan.profile),失败即报错
//   2. fill_defaults        — 空串字段用 profile.defaults.<field> 填充
//   3. configure            — 调 profile.configure(plan.config),透传错误
//   4. validate             — 调 profile.validate(plan.config, err),失败即报错
//   5. CatalogSet nullptr   — 入口一次性诊断(FindFirstNullCatalog)
//   6. id 存在性             — 在各 catalog 里 Find,逐项确认
//   7. ad-hoc spec 校验     — 若 options.ad_hoc_feedback_spec 有值,校验
//                              engine_id 不冲突命名 engine,signal/agg/disp
//                              都已注册;此时跳过 feedback_engine 的 fill +
//                              must_find,output.feedback_engine 显式置为
//                              spec.engine_id(让日志/Assembler 始终从同一
//                              字段读取 active id)。
//
// 顺序理由:fill 与 configure 完全正交(configure 不读 LaunchPlan id),
// 先填 id 让后续日志/错误带上决议结果;
#pragma once

#include "refuzz/core/error.hpp"
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/orchestrator/profile_registry.hpp"
#include "refuzz/resolver/catalog_set.hpp"
#include "refuzz/resolver/resolved_plan.hpp"
#include "refuzz/startup/launch_plan.hpp"

#include <optional>

namespace refuzz::resolver {

// Resolve 的旁路选项。当前仅 ad_hoc_feedback_spec;保留为结构体而非
// 默认参数,方便未来扩字段(例:strict_mode、自定义 validator)而不破
// 坏 ABI / 调用方源码兼容。
struct ResolveOptions {
    // 临时合成一个未注册的 feedback engine。若有值,Resolver 跳过命名
    // engine 的 fill / must_find,改为校验 spec 内部 id 全部已注册,且
    // engine_id 不与命名 engine 冲突。详见 ResolvedPlan 的 ad_hoc 注释。
    std::optional<fuzzer::FeedbackEngineSpec> ad_hoc_feedback_spec;
};

class Resolver {
public:
    // 把 plan 按 by-value 移入,内部填空 + move 到 ResolvedPlan.config。
    // 调用方需 Resolve(std::move(plan), ...)(因为 OrchestratorConfig
    // 含 unique_ptr 字段,move-only)。
    static core::Result<ResolvedPlan> Resolve(
        startup::LaunchPlan plan,
        const orchestrator::ProfileRegistry& registry,
        const CatalogSet& catalogs,
        ResolveOptions options = {});
};

} // namespace refuzz::resolver
