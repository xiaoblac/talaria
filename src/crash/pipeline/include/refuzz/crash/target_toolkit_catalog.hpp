// Copyright 2026 reFuzz project author -------youngkk.
//
// TargetToolkitCatalog — 目标特定"能力包"的注册表。
//
// 设计意图：
//   多数 fuzz 工具(syzkaller/AFL++/libFuzzer)的 crash 分析、repro 最小化、
//   诊断附件采集、初始种子构造这四项能力在同一个 target 下是一体的——
//   它们共享 symbolizer、sanitizer mode、target 的报告格式约定等。跨
//   target(kernel / userspace / hypervisor)才会整套替换。因此与 mutator
//   "engine 粒度 catalog" 不同，此 Catalog 以 **target 能力包** 为粒度。
//
// LaunchPlan / Resolver / Assembler 流程：
//   LaunchPlan.target_toolkit (id, 例如 "kernel_linux_syz")
//       → ProfileDefaults 填空
//       → Assembler 调 catalog.Build(id, ctx) 得到 TargetToolkit
//       → Assembler 用 toolkit.create_* 装配 analysis_engine / repro_engine /
//                   diagnostic_provider、并注入 initial seed payload。
//
// 非职责：
//   - channel 创建不在此 Catalog。channel 与 executor 耦合较深，预计独立
//     在一轮 refactor 里抽取成 ChannelCatalog。
//   - CrashPipelineManager 当前仅一个实现，直接 new；若将来出现 "同步/异步
//     triage interpreter" 的分叉才单独 catalog。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/worker/mode.hpp"
#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"
#include "refuzz/crash/infra/diagnostic_attachment_provider.hpp"
#include "refuzz/crash/pipeline/core/crash_analysis_engine.hpp"
#include "refuzz/crash/repro/core/repro_engine.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace refuzz::crash {

// Assembler 在调用 create_analysis_engine / create_repro_engine 时提供的最小
// 上下文。不引入 OrchestratorConfig 以避免 refuzz_crash 反向依赖 refuzz_control。
// 如未来 factory 需要更多字段,Orchestrator 装配处由 OrchestratorConfig 映射
// 到本结构体传入。
struct TargetToolkitBuildArgs {
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode =
        refuzz::channel::worker::WorkerSanitizerMode::kNone;
};

// target 能力包：封装同一 target 下的 crash/repro/诊断/种子 四项工厂函数。
// 由 Catalog::Build 返回 unique_ptr<TargetToolkit>,Assembler 在装配时调用
// 各 create_* lambda 得到最终实例。
struct TargetToolkit {
    // 稳定 id,与 Catalog 中注册的 meta.id 一致,用于日志/诊断。
    std::string id;

    using AnalysisEngineFactory = std::function<
        std::unique_ptr<ICrashAnalysisEngine>(
            const TargetToolkitBuildArgs&,
            Addr2lineSymbolizer*)>;
    AnalysisEngineFactory create_analysis_engine;

    using ReproEngineFactory = std::function<
        std::unique_ptr<IReproEngine>(
            const TargetToolkitBuildArgs&,
            Addr2lineSymbolizer*)>;
    ReproEngineFactory create_repro_engine;

    // 可为 nullptr lambda;当前实现一律返回 nullptr provider,
    // 留口子以支持 "QEMU worker log tail → attachment" 之类的未来扩展。
    using DiagProviderFactory = std::function<
        std::unique_ptr<IDiagnosticAttachmentProvider>(
            refuzz::channel::IChannel*)>;
    DiagProviderFactory create_diagnostic_provider;

    // [v1 — ROLLBACK: uncomment below and remove v2 block]
    // // 生成 target-specific 的最小初始种子 payload。
    // using SeedPayloadFactory = std::function<std::vector<uint8_t>()>;
    // SeedPayloadFactory build_seed_payload;

    // [v2 PR2 — Corpus Generation Adaptation 当前版本]
    // SeedPayloadFactory / build_seed_payload 字段已删除。
    // 不再有 "硬编码 canonical bootstrap seed" 的 target 概念——
    // syzkaller 也没有这玩意儿，corpus-independent generation 改由
    // ExploreJob（control/src/job/explore_job.cpp）调 IMutatorEngine::Generate 完成。
};

struct TargetToolkitTraits {
    using Product = TargetToolkit;

    // 当前 target toolkit 无需外部依赖即可构造(所有 create_* 都是 lambda,
    // 装配期再传入依赖)。BuildContext 留空,保持与 MutatorEngineCatalog /
    // SchedulerEngineCatalog 一致的 Traits 签名。
    struct BuildContext {};
};

using TargetToolkitCatalog = refuzz::catalog::TypedCatalog<TargetToolkitTraits>;

// 注册内置 target toolkit。当前只有:
//   "kernel_linux_syz" — Linux kernel target,syzkaller 系 crash/repro + getpid
//                         getuid 最小种子。与原 kernel_profile 中四个工厂等价。
void RegisterBuiltinTargetToolkits(TargetToolkitCatalog& catalog);

} // namespace refuzz::crash
