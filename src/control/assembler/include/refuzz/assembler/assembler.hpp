// Copyright 2026 reFuzz project author -------youngkk.
//
// Assembler
//
// 从 ResolvedPlan + CatalogSet 造出 fuzzer 核心 AssembledBundle。
// 纯函数:相同输入 → 相同输出 + 相同错误(除 std::make_unique OOM
// 之外)。不启动线程、不做 IO(channel Build 里的 IO 除外,那是
// backend 实现细节)、不触碰全局单例。
//
// 装配步骤(顺序强约定,因为有依赖):
//   1. CorpusStore(CatalogSet.corpus_store)
//   2. HashFeedbackStore + SeedIdAllocator(非 catalog)
//   3. TargetToolkit(CatalogSet.toolkit)
//   4. MutatorManager + catalog.All() 全装 + SwitchEngineByName(resolved)
//      - BuildContext 必须 { .corpus_store = corpus_store.get() }
//   5. SchedulerManager + 同 4 风格(BuildContext 为空)
//   6. FeedbackManager + 单 engine:
//      - ad-hoc:BuildFromSpec(fb_ctx, *resolved.ad_hoc_feedback_spec)
//      - 否则:   catalog.Build(resolved.feedback_engine, fb_ctx)
//      - AddEngine(engine, activate=false) + SwitchEngineByName(resolved.feedback_engine)
//        (Feedback 虽然目前只装一个,仍统一走 switch,为未来多 engine 扩展留接口)
//   7. 主 Channel(resolved.config.channel_backend 必须非 null,
//                 局部复制 channel_cfg、兜底 channel_id、置 use=kFuzz)
//   8. Repro channels(resolved.config.repro.enable + dedicated_vm_count > 0 +
//                     profile.derive_repro_channel_cfg 存在时逐个 Build,
//                     每个 ctx.channel_cfg.use=kRepro)
//
// 错误处理:
//   * ctx.profile_registry == nullptr → Error(kConfig, "profile_registry null")
//   * resolved.config.channel_backend == nullptr → Error(kConfig, "channel_backend null")
//   * 任一 catalog.Build 失败 → 整体失败(错误 message 前缀 step 名)
//   * repro channel 单项 derive 返回 null profile / catalog.Build 失败 →
//     **仅 skip 该 index,不整体失败**(Orchestrator 现状一致)

#pragma once

#include "refuzz/assembler/assemble_context.hpp"
#include "refuzz/assembler/assembled_bundle.hpp"
#include "refuzz/core/error.hpp"
#include "refuzz/resolver/catalog_set.hpp"
#include "refuzz/resolver/resolved_plan.hpp"

namespace refuzz::assembler {

class Assembler {
public:
    static core::Result<AssembledBundle> Assemble(
        const resolver::ResolvedPlan& resolved,
        const resolver::CatalogSet& catalogs,
        const AssembleContext& ctx);
};

} // namespace refuzz::assembler
