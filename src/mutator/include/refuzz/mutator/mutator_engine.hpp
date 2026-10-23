#pragma once

#include "refuzz/program/artifact.hpp"   // §3.10 step 3 — MutateTyped
#include "refuzz/program/seed.hpp"
#include "refuzz/program/state_altitude.hpp"  // seed-value signal C — AnalyzeStateAltitude

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// [v2 Epic 5 PR-5-C] forward-declare CompMap so non-syz engines need not
// pull the hints subtree headers. SyzV2MutatorEngine includes the full
// header via its own override site.
namespace refuzz::mutator::syz_v2::hints {
class CompMap;
} // namespace refuzz::mutator::syz_v2::hints

namespace refuzz::fuzzer {

// 每个变异范式实现一套 engine；Manager 仅负责 engine 路由，
// policy 生命周期由 engine 自治。
//
// policy 切换语义(v2):
//   * SwitchPolicyByName 可由任意线程调用,仅记录 pending;
//   * engine 在下一次 Mutate()/MutateTyped() 入口自行完成 apply;
//   * FuzzerLoop/Manager/Telemetry 不感知"两阶段切换"。
//
// §3.10 step 3 — typed pipeline:
//   * `MutateTyped(artifact)` is the primary mutator contract on the
//     v2 hot path. Native syz_v2 implementations clone the artifact's
//     typed view and mutate the clone, returning a fresh artifact
//     without text decode/encode on the hot path (D2/D4/D5).
//   * `Mutate(seed)` is retained as a compatibility wrapper; v1
//     profiles still use it (D6 v1-exempt). v2 stages migrate to
//     MutateTyped in step 6 of `docs/typed-program-pipeline/100_*`.
//   * Default `MutateTyped` returns kSkipped so legacy / non-typed
//     engines stay valid without overriding (per plan: "legacy engines
//     can return wrapped bytes artifacts" — minimum compliant form is
//     a no-op skip).
class IMutatorEngine {
public:
    virtual ~IMutatorEngine() = default;
    virtual std::string Name() const = 0;

    // [v1 — Mutate(Seed) bytes path. Stays compileable for rollback
    //  per §3.10 D1; v1 stages still call this.]
    virtual std::vector<uint8_t> Mutate(const Seed& seed) = 0;

    // [v2 — MutateTyped(artifact). Default impl returns kSkipped so
    //  engines that haven't been retyped don't accidentally claim
    //  ownership of the typed pipeline. SyzV2MutatorEngine overrides
    //  with a native typed mutation path.]
    virtual ::refuzz::program::MutationResult
    MutateTyped(const ::refuzz::program::ProgramArtifact& artifact);

    // [v2 — Corpus-independent generation path. §015 §5 / §6.1：
    //  ExploreJob（control/src/job/explore_job.cpp）调用此方法产出全新随机程序
    //  （无 corpus seed 输入）。SyzV2 引擎实现 = 现有 GenerateFreshProg（ChoiceTable
    //  + PseudoSelectionPolicy + ncalls 分布）+ MakeArtifactFromTypedProg
    //  + sanitize_fix。默认 kSkipped：v1 / 不支持 generation 的 engine
    //  保持兼容；调用者据 status==kOk + artifact.valid() 决策。
    //  生成成功 changed=true（按 D5 语义，generation 视为"全新输出"）。]
    virtual ::refuzz::program::MutationResult Generate();

    // [collide 变换层] 对一份已产出的新程序 artifact 做 race-triggering async 变换
    //  (mirror prog/collide.go AssignRandomAsync)：DeepClone → 给部分 call 打 async →
    //  wrap 回 artifact。返回 status=kOk + collide 变体 artifact，或 kSkipped（v1 /
    //  非 typed engine / As<Prog> 取不到）。CollideProducerStage 调用它，kOk 时用返回
    //  artifact 替换待投任务并置 kExecFlagIntraThreaded（threaded 执行下 async 才并发）。
    //  默认 kSkipped 保持兼容。
    virtual ::refuzz::program::MutationResult
    Collide(const ::refuzz::program::ProgramArtifact& artifact);

    virtual bool SwitchPolicyByName(std::string_view name) = 0;
    virtual std::string ActivePolicyName() const = 0;

    // Notification from corpus admission. Engines that depend on
    // corpus state (SyzV2MutatorEngine rebuilds ChoiceTable here)
    // override; default is a no-op so engines without corpus
    // dependencies stay valid. The seed argument is reserved for
    // hints/KCOV_CMP consumers that need payload inspection.
    virtual void OnSeedAdmitted(const Seed& /*seed*/) {}

    // [machine-check C4.6] Replace the per-id enabled-calls mask and rebuild any
    // derived state (the ChoiceTable), so generation/mutation only emit the
    // machine-checked supported set. Called once at startup after the
    // machine-check resolves `enabled` (whitelist ∩ supported ∩ transitive).
    // Default no-op: engines without a syscall whitelist stay valid.
    virtual void SetEnabledCalls(std::vector<std::uint8_t> /*enabled_mask*/) {}

    // [v2 Epic 5 PR-5-C — MutateWithHints]
    // Mirror of upstream `(*Prog).MutateWithHints(callIndex, comps,
    // exec)`. Engines that don't support hints leave the default
    // no-op in place; SyzV2MutatorEngine overrides to invoke the
    // typed `MutateProgWithHints` algorithm and surface candidates as
    // ProgramArtifact via the `on_candidate` callback. The callback
    // returns false to abort iteration early (matches upstream
    // `doMore=false` convention).
    //
    // `seed` carries the program payload to mutate; engines deserialize
    // their own typed Prog (or reuse seed.artifact when valid).
    // `comps` is borrowed; the engine MUST NOT outlive the call.
    using HintsArtifactCallback =
        std::function<bool(::refuzz::program::ProgramArtifact)>;
    virtual void MutateWithHints(
        const Seed& /*seed*/,
        int /*call_index*/,
        const ::refuzz::mutator::syz_v2::hints::CompMap& /*comps*/,
        const HintsArtifactCallback& /*on_candidate*/) {}

    // [seed-value signal C] State-space altitude of a program
    // (docs/plans/seed-value-signals.md §2.3). Reads the artifact's typed IR
    // (As<T>() — only legal inside syz-owned engines) and returns the neutral
    // program::StateAltitude POD. Default returns nullopt so non-typed / legacy
    // engines stay valid; SyzV2MutatorEngine overrides. Generic control/corpus
    // code calls this seam and never touches As<T>() itself.
    virtual std::optional<::refuzz::program::StateAltitude>
    AnalyzeStateAltitude(const ::refuzz::program::ProgramArtifact& /*artifact*/) {
        return std::nullopt;
    }
};

inline ::refuzz::program::MutationResult
IMutatorEngine::MutateTyped(const ::refuzz::program::ProgramArtifact& /*artifact*/) {
    ::refuzz::program::MutationResult r;
    r.status  = ::refuzz::program::MutationStatus::kSkipped;
    r.changed = false;
    // r.artifact stays default-constructed (invalid).
    return r;
}

inline ::refuzz::program::MutationResult
IMutatorEngine::Generate() {
    ::refuzz::program::MutationResult r;
    r.status  = ::refuzz::program::MutationStatus::kSkipped;
    r.changed = false;
    // r.artifact stays default-constructed (invalid).
    return r;
}

inline ::refuzz::program::MutationResult
IMutatorEngine::Collide(const ::refuzz::program::ProgramArtifact& /*artifact*/) {
    ::refuzz::program::MutationResult r;
    r.status  = ::refuzz::program::MutationStatus::kSkipped;
    r.changed = false;
    // r.artifact stays default-constructed (invalid).
    return r;
}

} // namespace refuzz::fuzzer
