// [mab-stage-selection Step 1 / mab-task-action-space §3.4] MabArm —— producer 的调度分组。
//
// 详见 docs/plans/mab-stage-selection.md §4.1 + docs/plans/mab-task-action-space.md §3.4。
// 两类:**bandit 臂**(gen / mut,task-MAB 仲裁)+ **非-bandit 调度层**(triage / enrich,
// FuzzerLoop 在 bandit 之前按优先级 drain、不进 reward)。ProducedKind 按下表归组
// (mutational → mutate;smash/hints/fault → enrich;verify/reexec/minimize → triage)。
// 本头极小,供 ProducerCtx / 各 stage / selector 共享,不拉 selector 全量依赖。

#pragma once

#include <cstdint>

namespace refuzz::control::mab {

enum class MabArm : std::uint8_t {
    kGenerate = 0,  // generation_stage(bandit 臂)
    kMutate   = 1,  // mutational(bandit 臂:变异既有 seed)
    kTriage   = 2,  // corpus_verify + triage_reexec + minimize(非-bandit 层:处理新发现的管线)
    kEnrich   = 3,  // smash + hints + fault(非-bandit 层:对刚 admit 的 seed 做确定性富化)
    kCollide  = 4,  // collide(非-bandit **变换层**:对 gen/mut 刚产出的新程序 task 做 async 并发变换)。
                    //   不是生产者——它不造 task,只加工 ctx.pending_task。FuzzerLoop 在 4 个生产 pass
                    //   之后、提交之前跑一趟 arm=kCollide 的变换相(见 fuzzer_loop.cpp 生产→变换→提交)。
                    //   不进 bandit reward、不参与 gen/mut 仲裁;仅作变换相的 MabSkipStage 门控标识。
};

inline constexpr int kMabArmCount = 5;

// MabArm → Exp3Bandit 的 arm_id(uint64)。
inline std::uint64_t MabArmId(MabArm a) { return static_cast<std::uint64_t>(a); }

inline const char* MabArmName(MabArm a)
{
    switch (a) {
    case MabArm::kGenerate: return "generate";
    case MabArm::kMutate:   return "mutate";
    case MabArm::kTriage:   return "triage";
    case MabArm::kEnrich:   return "enrich";
    case MabArm::kCollide:  return "collide";
    }
    return "?";
}

} // namespace refuzz::control::mab
