// SyzV2MutatorEngine — v2 IR generation + mutation engine (§3.4 + §3.5).
//
// Wraps the v2 generator (refuzz::mutator::syz_v2::generate_program) and
// the v2 mutation op/policy registries (§3.5: ops/syz_v2_op_wrappers,
// policies/syz_v2_mutation_policies) under the mutator/ subsystem
// contract (IMutatorEngine). Plugged in the same catalog→manager→handle
// path as the v1 SyzMutatorEngine, so that `control/`, `assembler/`,
// `FuzzerLoop` see only the engine boundary and do not have to know
// about the v2 generator's free-function internals.
//
// Mutate(seed) routing:
//   * empty payload  → call generate_program (§3.4 path), encode, return.
//   * non-empty seed → TextDecoder.decode(payload). If decode fails or
//     the active policy returns no op, fall back to the original
//     payload (no mutation). Otherwise apply the selected op, encode
//     the mutated Prog, return.
//
// Output bytes are the canonical .syz text form (TextEncoder), the
// same artifact §3.4 / §3.5 oracles consume — validate-on-generated,
// text-RT-on-generated, mutate-on-corpus.
//
// Thread model follows mutator/design.md §7.2: engine switch is
// concurrency-safe; Mutate() is invoked from a single FuzzerLoop
// thread; internal RNG (master_ and mut_rand_) is therefore not
// guarded.

#pragma once

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/choice_table_handle.hpp"
#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::fuzzer {

class ICorpusStore;

class SyzV2MutatorEngine final : public IMutatorEngine {
public:
    // Defaults match prog/rand.go expectations: ncalls ∈ [2, 8] uniform
    // for from-scratch generation. `corpus_store` is borrowed (may be
    // null when a tool runs the engine outside a fuzz session); it is
    // used by the splice op (§3.5 M2) to sample a donor seed.
    //
    // [impl-kind removed] There is no PseudoSelectionPolicy. The generator's
    // pseudo gate is syz's (disabled) attr + the enable/disable whitelist
    // (`enabled_calls`, applied at ChoiceTable build time); environment
    // gating lives host-side in control/support.
    explicit SyzV2MutatorEngine(
        const ::refuzz::program::syz::Target&            target,
        ICorpusStore*                                    corpus_store = nullptr,
        uint64_t                                         master_seed  = std::random_device{}(),
        int                                              ncalls_lo    = 2,
        int                                              ncalls_hi    = 8,
        std::vector<std::uint8_t>                        enabled_calls = {});

    std::string Name() const override;
    std::vector<uint8_t> Mutate(const Seed& seed) override;

    // §3.10 step 3 — native typed mutation. Clones the artifact's
    // typed view (D4), runs the active policy's selected op on the
    // clone, and returns a new artifact wrapping the cloned Prog
    // with a lazy canonical-text provider (D3 + plan §5.2 oracle #17:
    // no decode_text/encode_text on the hot path).
    ::refuzz::program::MutationResult
    MutateTyped(const ::refuzz::program::ProgramArtifact& artifact) override;

    // [v2 — §015 §5 / §6.1] Corpus-independent generation.
    // 等价 syzkaller `target.Generate(rnd, RecommendedCalls, ChoiceTable)`：
    //   1. GenerateFreshProg() ← 内部 master_ rng / EnsureChoiceTableSnapshot
    //      / pseudo_policy_ / ncalls 分布
    //   2. sanitize_fix(prog) ← 与 MutateTyped 末尾一致的不变量修复
    //   3. MakeArtifactFromTypedProg ← typed authority + 懒 canonical 文本
    // 生成失败（GenerateFreshProg 返回 nullptr）→ status=kEngineError、artifact 留 invalid。
    // 由 ExploreJob::GenerateProgram（explore_job.cpp）在建 task 前 .valid() 校验，valid 失败不 emit。
    ::refuzz::program::MutationResult Generate() override;

    // [collide 变换层] mirror prog/collide.go AssignRandomAsync。取 artifact 的 typed
    // Prog（As<syz::Prog>，D2 只能在本 syz-owned engine 内）→ AssignRandomAsync（DeepClone
    // + 给部分 call 打 async）→ MakeArtifactFromTypedProg。artifact 无 typed view →
    // kSkipped。返回 status=kOk + collide 变体；CollideProducerStage 据此替换待投任务。
    ::refuzz::program::MutationResult
    Collide(const ::refuzz::program::ProgramArtifact& artifact) override;

    // [Epic 3 PR-3-A4] Test-only entry: mirrors Mutate(seed) dispatch
    // (empty payload → GenerateFresh, non-empty → MutateViaPolicy)
    // but returns the typed Prog before encoding. Lets tests verify
    // res()/uses_ back-edge invariants directly without an
    // encode/decode round trip filtering inconsistencies. Returns
    // nullptr when the engine declines to mutate (decode fail / no
    // policy / op rejected) — same trigger set as Mutate returning
    // seed.payload unchanged.
    std::unique_ptr<::refuzz::program::syz::Prog>
    MutateProgForTesting(const Seed& seed);

    bool SwitchPolicyByName(std::string_view name) override;
    std::string ActivePolicyName() const override;

    // Triggers a ChoiceTable rebuild + COW publish so the mutator
    // hot path picks up fresh dynamic priorities; read side stays
    // lock-free via atomic_load on shared_ptr.
    void OnSeedAdmitted(const Seed& seed) override;

    // [machine-check C4.6] Swap the per-id enabled mask and rebuild the
    // ChoiceTable so generation/mutation only emit the machine-checked set.
    void SetEnabledCalls(std::vector<std::uint8_t> enabled_mask) override;

    // [v2 Epic 5 PR-5-C] MutateWithHints — see IMutatorEngine.
    // Decodes seed.payload via the engine's TextDecoder, runs
    // hints::MutateProgWithHints on the typed Prog, and surfaces each
    // mutated candidate as a ProgramArtifact (typed authority +
    // re-serialize-on-demand) via on_candidate. Returns immediately if
    // decoding fails or call_index is out of range.
    void MutateWithHints(
        const Seed& seed,
        int         call_index,
        const ::refuzz::mutator::syz_v2::hints::CompMap& comps,
        const HintsArtifactCallback& on_candidate) override;

    // [seed-value signal C] As<syz::Prog>() + ComputeStateAltitude. See
    // IMutatorEngine::AnalyzeStateAltitude.
    std::optional<::refuzz::program::StateAltitude>
    AnalyzeStateAltitude(const ::refuzz::program::ProgramArtifact& artifact) override;

private:
    // §3.4 generation path — emit a fresh Prog, encode to text bytes.
    std::vector<uint8_t> GenerateFresh();

    // §3.4 generation path — typed-Prog core. GenerateFresh wraps
    // this with encoder.encode + bytes return; MutateProgForTesting
    // calls it directly for in-prog assertions.
    std::unique_ptr<::refuzz::program::syz::Prog> GenerateFreshProg();

    // §3.5 mutation path — decode seed, run policy → op, re-encode.
    // Returns the original payload unchanged when no op fires (decode
    // fail, empty Prog, policy returns nullptr, or op returns false).
    std::vector<uint8_t> MutateViaPolicy(const Seed& seed);

    // §3.5 mutation path — typed-Prog core. MutateViaPolicy wraps
    // this with encoder.encode + bytes return; MutateProgForTesting
    // calls it directly. Returns nullptr on the same trigger set
    // that makes MutateViaPolicy return seed.payload unchanged.
    std::unique_ptr<::refuzz::program::syz::Prog>
    MutateProgViaPolicy(const Seed& seed);

    // [speed-compare arm D growth-parity] syzkaller-style multi-op mutation loop:
    // keep selecting+applying ops, stopping after each successful op with prob 1/3
    // (mirrors prog/mutation.go `stop = ok && r.oneOf(3)`). Single-op mutation kept
    // reFuzz programs at ~corpus_len+1; the loop + growth-biased op weights pull
    // length toward the recommended size, like syz `Mutate(rnd, RecommendedCalls)`.
    // Returns true if any op mutated `prog`.
    bool RunMutationOps(::refuzz::program::syz::Prog& prog,
                        ::refuzz::mutator::syz_v2::SyzV2MutationContext& ctx);

    // Lazy registry init — populates ops_/policies_ on first use.
    void EnsureMutationComponents();

    // Lazy pending-switch apply — invoked at top of every Mutate.
    bool ApplyPendingSwitchIfAny();

    int FindPolicyIndex(std::string_view policy_name) const;

    // Fixed positions in policies_ — keep stable so SwitchPolicyByName
    // by index works even when registry layout changes downstream.
    static constexpr int kBalancedPolicyIndex = 0;

    const ::refuzz::program::syz::Target&         target_;
    ICorpusStore*                                 corpus_store_;  // borrowed; may be null
    // [syscall-enable-whitelist] per-id enabled mask; empty = all enabled.
    std::vector<std::uint8_t>                     enabled_calls_;
    ::refuzz::program::syz::TextEncoder    encoder_;
    ::refuzz::program::syz::TextDecoder    decoder_;
    std::mt19937_64                        master_;        // generation per-prog seed source
    std::uniform_int_distribution<int>     length_dist_;
    ::refuzz::mutator::syz_v2::RandGen     mut_rand_;      // mutation-side RNG, persistent

    // Policy state — pending atomic slot, applied lazily on Mutate entry.
    int                  active_policy_idx_ = kBalancedPolicyIndex;
    std::atomic<int>     next_policy_idx_{kBalancedPolicyIndex};

    std::vector<std::unique_ptr<::refuzz::mutator::syz_v2::ISyzV2MutatorOp>>      ops_;
    std::vector<std::unique_ptr<::refuzz::mutator::syz_v2::ISyzV2MutationPolicy>> policies_;

    // ChoiceTable for biased syscall picks. shared_ptr COW: the
    // engine atomic-stores a fresh table on rebuild; readers grab a
    // snapshot via EnsureChoiceTableSnapshot for one Mutate call.
    // The snapshot destructor releases the old table the moment no
    // reader holds it.
    ::refuzz::mutator::syz_v2::ChoiceTableHandle EnsureChoiceTableSnapshot();
    void RebuildChoiceTable();
    std::shared_ptr<::refuzz::mutator::syz_v2::ChoiceTable> choice_table_;
    // [v2 admit-worker async] RebuildChoiceTable 现在可能从两条线程进:
    //   (a) hot path Mutate -> EnsureChoiceTableSnapshot 首次 lazy build
    //   (b) AsyncAdmitWorker -> OnSeedAdmitted -> RebuildChoiceTable
    // rebuild_mu_ 串行化两者,避免并发跑 fresh->build 同一份 corpus 浪费 CPU。
    // mutator hot path Mutate 自身**不**持此锁 — 它读 atomic_load(choice_table_) 拿 snapshot,
    // rebuild 完成后通过 atomic_store 发布,reader 永远拿到 stable 旧/新。
    std::mutex                                              rebuild_mu_;
    // [v2 syzkaller-parity throttle] 上次 rebuild 时 corpus 大小,用于 33/333 节流。
    //   syzkaller 上游 pkg/fuzzer/fuzzer.go:406-426 同款语义:
    //     corpus < 100  → 每多 33 个 admit 才 rebuild
    //     corpus ≥ 100  → 每多 333 个
    //   作用是给 dynamic prio 一个最小统计样本,避免早期 1-32 个 seed 时
    //   的噪声 prio 被 ChoiceTable 立即采纳,导致 corpus 焦点漂移。
    //   atomic 保护:OnSeedAdmitted (admit_worker 线程) 与 EnsureChoiceTableSnapshot
    //   (fuzz 主线程 lazy first build) 都会读写。
    std::atomic<std::size_t>                                ct_built_at_corpus_size_{0};
};

// [Epic 3 PR-3-A4] Diagnostics: TU-local counter incremented inside
// the engine's splice_pending_extras helper when extras are actually
// spliced into the prog (applied==true AND affected_call_index in
// range AND non-empty buffer). Used by mutate_resource_extras_test
// case 3 to assert the splice path was exercised at least once
// across a deterministic mutate-on-corpus sweep — without this, a
// regression that gates the splice with `if (false)` would still
// leave the round-trip check passing on the unspliced prog.
uint64_t splice_pending_extras_hits();
void     reset_splice_pending_extras_hits();

} // namespace refuzz::fuzzer
