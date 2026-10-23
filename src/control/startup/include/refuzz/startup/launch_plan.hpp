// Copyright 2026 reFuzz project author -------youngkk.
//
// LaunchPlan
//
// 用户意图的归一化表示。两种前端(JSON 和交互模式)最终都产出一个 LaunchPlan,
// 后面的 Resolver 补齐默认值、Assembler 查 catalog 装配,Orchestrator 只负责
// Start/Wait/Stop。
//
// 选择字段为空串 = "使用 profile 默认值"。Resolver 会根据 profile.defaults
// 填充所有空串字段,产出 ResolvedPlan。
//
// 字段与 Catalog 的对应(P2 落地):
//   mutator_engine      ↔ MutatorEngineCatalog        ("syz")
//   scheduler_engine    ↔ SchedulerEngineCatalog      ("priority_scheduler")
//   corpus_store        ↔ CorpusStoreCatalog          ("in_memory")
//   feedback_engine     ↔ FeedbackEngineCatalog       ("kernel_kcov" / "null")
//   channel_backend_id  ↔ ChannelCatalog              ("qemu_ivshmem_linux" ...)
//   target_toolkit      ↔ TargetToolkitCatalog        ("kernel_linux_syz")
//   stage_specs / producer_chain / consumer_chain ↔ StageCatalog
// target_toolkit 是一个能力包,替代原来的 crash_analysis / repro_engine /
// diagnostic_provider / seed_payload 四个独立选择——它们在 target 维度天然
// 一体,共享 symbolizer / sanitizer mode。
//
// 注意:config 字段保留了原有的 OrchestratorConfig,不做拆分。新架构只是
// 在"用户选哪个组件"这一层引入清晰的数据流,底层配置仍然沿用现有结构。

#pragma once

// [Step 6 stage 清场] stage_build_context.hpp(StageSpec)已删;LaunchPlan 不再含 stage 字段。
#include "refuzz/orchestrator/orchestrator_config.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::startup {

struct LaunchPlan {
    // Profile 名称(如 "kernel")。必填;空串由 Resolver 当作错误处理。
    std::string profile;

    // ── 组件选择(空串 = 使用 profile 默认值) ──────────────────────
    //
    // 这些字符串是各领域 Catalog 里注册的 id。Resolver 会:
    //   1. 若为空,用 profile.defaults.<field> 填充;
    //   2. 在对应 Catalog 中查找 id,查不到则返回错误。
    //
    std::string mutator_engine;        // MutatorEngineCatalog
    std::string scheduler_engine;      // SchedulerEngineCatalog
    std::string corpus_store;          // CorpusStoreCatalog
    std::string corpus_admission;      // (v2) 准入过滤策略,v1 保留字段
    std::string feedback_engine;       // FeedbackEngineCatalog
    std::string channel_backend_id;    // ChannelCatalog
    std::string target_toolkit;        // TargetToolkitCatalog (crash + repro + diag + seed 合为一包)

    // 执行模式诉求(后端无关):true = 请求 snapshot 执行。Resolver 据此从 profile 的
    // per-mode 默认里选 channel_backend_id(而非 continuous 默认),并校验所选 backend
    // 声明了 snapshot 能力。仅当 channel_backend_id 为空且 snapshot_mode 时触发 per-mode
    // 选择;显式 channel_backend_id 仍优先。
    bool snapshot_mode = false;

    // 底层运行配置(QEMU 参数、fuzzer loop 参数、repro 参数等)。
    // 不在组件选择之列,是原始配置对象。
    orchestrator::OrchestratorConfig config;

    // [Step 6 stage 清场] stage_specs / producer_chain / consumer_chain 已删(stage framework
    //   退役;job 模型下运行时工作由 job_scheduler 表达,不再有 chain 声明)。
};

} // namespace refuzz::startup
