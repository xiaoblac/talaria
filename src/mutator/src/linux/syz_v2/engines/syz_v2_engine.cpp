// reFuzz syz_v2 mutator — engine implementation (§3.4 + §3.5 + §3.10).

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"

#include "refuzz/fuzzer/interfaces.hpp"
// [v2 Epic 5 PR-5-C] hints algorithm port — MutateProgWithHints invoked
// from the engine's MutateWithHints override.
#include "refuzz/mutator/linux/syz_v2/collide/assign_async.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/syz_v2_op_wrappers.hpp"
#include "refuzz/mutator/linux/syz_v2/policies/syz_v2_mutation_policies.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/state_altitude.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/size.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace refuzz::fuzzer {

namespace mut_v2 = ::refuzz::mutator::syz_v2;
namespace syz    = ::refuzz::program::syz;

namespace {

// [Epic 3 PR-3-A4] Diagnostics counter (TU-local, thread_local).
// Incremented inside splice_pending_extras when extras are actually
// spliced into `prog` — i.e. applied==true AND the index contract
// held AND the buffer was non-empty. Read-only via the accessor
// below. Used by mutate_resource_extras_test case 3 to gate
// "mutate-on-corpus actually exercised the splice path".
thread_local uint64_t g_splice_pending_extras_hits = 0;

// Drains GenState's pending_extras (producer calls created by a
// nested create_resource invocation inside mutate_resource_arg) and
// splices them in front of ctx.affected_call_index in `prog`. When
// the op rejected (applied == false), extras are dropped without
// splicing — the consumer mutation that produced them was undone.
//
// Contract: pending_extras_ is populated only by mutate_resource_arg,
// which is only reachable through mutate_arg_impl — and that op sets
// affected_call_index = idx before recursing. If the index is unset
// or out of range when extras are present, some new push site
// bypassed that contract; a silent insert at index 0 would corrupt
// the producer→consumer ordering. Drop instead.
void splice_pending_extras(syz::Prog& prog,
                           mut_v2::SyzV2MutationContext& ctx,
                           bool applied) {
    if (ctx.gen_state == nullptr || !ctx.gen_state->has_pending_extras()) {
        return;
    }
    auto extras = ctx.gen_state->take_pending_extras();
    if (!applied) return;
    auto& calls = prog.mutable_calls();
    if (ctx.affected_call_index < 0 ||
        static_cast<std::size_t>(ctx.affected_call_index) > calls.size()) {
        // Contract violation — extras present but no consumer index.
        // Drop instead of splicing at index 0; a wrong-position splice
        // would silently invert producer→consumer ordering and the
        // resulting prog would still validate (the producer chain
        // contains its own self-consistent calls), masking the bug.
        return;
    }
    const auto insert_at = static_cast<std::size_t>(ctx.affected_call_index);
    calls.insert(calls.begin() + static_cast<std::ptrdiff_t>(insert_at),
                 std::make_move_iterator(extras.begin()),
                 std::make_move_iterator(extras.end()));
    ++g_splice_pending_extras_hits;
}

} // namespace

uint64_t splice_pending_extras_hits()       { return g_splice_pending_extras_hits; }
void     reset_splice_pending_extras_hits() { g_splice_pending_extras_hits = 0; }

// ============================================================
// ctor / Name
// ============================================================

SyzV2MutatorEngine::SyzV2MutatorEngine(
    const syz::Target&                 target,
    ICorpusStore*                      corpus_store,
    uint64_t                           master_seed,
    int                                ncalls_lo,
    int                                ncalls_hi,
    std::vector<std::uint8_t>          enabled_calls)
    : target_(target)
    , corpus_store_(corpus_store)
    , enabled_calls_(std::move(enabled_calls))
    , encoder_(target)
    , decoder_(target, syz::DecodeMode::kNonStrict)
    , master_(master_seed)
    , length_dist_(ncalls_lo, ncalls_hi)
    , mut_rand_(master_seed ^ 0x9E3779B97F4A7C15ULL)
{}

std::string SyzV2MutatorEngine::Name() const
{
    // Must match catalog registration id; SwitchEngineByName("syz")
    // routes through this name (V2 engine, occupies the "syz" slot
    // after V1 retirement).
    return "syz";
}

// ============================================================
// Mutate
// ============================================================

// [v2 PR2 — 保留原 Mutate(seed) 行为]
// PR2 加了 IMutatorEngine::Generate() 新 API（ExploreJob 主路径用，见 explore_job.cpp）。
// 但 `Mutate(empty seed) → GenerateFresh` 这条路径在 9 个 mutator/corpus 单测
// 里被当作 "产一个 V2 IR canonical 文本" 的便捷入口（mutate_resource_extras /
// corpus_v2_artifact_roundtrip / smash_repeat_decode_count / minimize_typed_smoke
// 等）。并非 dead code——production 路径下因 bootstrap 删除确实不可达，但
// test 入口仍可达。保留这条路径，避免 9 个测试同时改 fixture。
std::vector<uint8_t> SyzV2MutatorEngine::Mutate(const Seed& seed)
{
    ApplyPendingSwitchIfAny();
    EnsureMutationComponents();

    if (seed.payload.empty()) {
        return GenerateFresh();
    }
    return MutateViaPolicy(seed);
}

std::unique_ptr<syz::Prog> SyzV2MutatorEngine::GenerateFreshProg()
{
    const uint64_t prog_seed = master_();
    const int      ncalls    = length_dist_(master_);

    auto ct_snap = EnsureChoiceTableSnapshot();
    auto prog = mut_v2::generate_program(
        target_, prog_seed, ncalls,
        (ct_snap && ct_snap->ready()) ? ct_snap.get() : nullptr);
    if (!prog || prog->calls().empty()) {
        return nullptr;
    }
    return prog;
}

std::vector<uint8_t> SyzV2MutatorEngine::GenerateFresh()
{
    auto prog = GenerateFreshProg();
    if (!prog) return {};
    try {
        std::string text = encoder_.encode(*prog);
        return std::vector<uint8_t>(text.begin(), text.end());
    } catch (...) {
        return {};
    }
}

// [v2 PR2 — IMutatorEngine::Generate 新接口实现]
// 对齐 syzkaller `target.Generate(rnd, RecommendedCalls, ChoiceTable)`，
// 但走 reFuzz 自己的 IR：GenerateFreshProg → sanitize_fix → MakeArtifactFromTypedProg。
// 该方法由 ExploreJob 调用（§015 §5 / §6.1，explore_job.cpp），corpus 空时 / 稳态下
// MAB 选中 generate 臂时使用，**不依赖** corpus seed。
::refuzz::program::MutationResult SyzV2MutatorEngine::Generate()
{
    namespace pr = ::refuzz::program;

    ApplyPendingSwitchIfAny();
    EnsureMutationComponents();

    auto prog = GenerateFreshProg();
    if (!prog) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kEngineError;
        r.changed = false;
        return r;
    }

    // §3.11 follow-up — 与 MutateTyped 末尾对齐：sanitize_fix 修复
    // PTRACE_TRACEME / MREMAP_MAYMOVE-without-FIXED 等 target 特定不变量。
    // GenerateFreshProg 来自 generator 内部一般已合规，但此处兜底，避免
    // 未来 generator op 改动后 invariant 破坏经 typed 路径漏到 executor。
    syz::sanitize_fix(*prog);

    // [R5 size-recompute] Recompute all LenType args from the generated body
    // before lowering to exec-wire (mirrors syz assignSizesCall post-generate).
    syz::assign_sizes_prog(*prog);

    std::shared_ptr<const syz::Prog> sp(prog.release());
    pr::MutationResult r;
    r.artifact = syz::MakeArtifactFromTypedProg(std::move(sp));
    r.changed  = true;
    r.status   = pr::MutationStatus::kOk;
    return r;
}

// ============================================================
// Collide — collide 变换层（mirror prog/collide.go AssignRandomAsync）
// ============================================================
//
// 由 CollideProducerStage 调用：对 gen/mut 刚产出的新程序 artifact 做 async 变换，
// 让部分 call 在 threaded 执行下并发跑触发 race。**不**变异、**不**重算 size（async
// 只加 per-call 属性，不改 call 结构；源 prog 已经 sanitize_fix + assign_sizes 过）。
::refuzz::program::MutationResult
SyzV2MutatorEngine::Collide(const ::refuzz::program::ProgramArtifact& artifact)
{
    namespace pr = ::refuzz::program;

    ApplyPendingSwitchIfAny();
    EnsureMutationComponents();

    // D9: hard target check（同 MutateTyped，无 fallback）。
    pr::ProgramTargetKey expected{target_.os(), target_.arch(), target_.revision()};
    pr::CheckTargetOrDie(artifact, expected);

    // D2: typed view 必须在（collide 只在 v2 typed 路径有意义）。
    auto src_prog = artifact.As<syz::Prog>();
    if (src_prog == nullptr || src_prog->calls().empty()) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kSkipped;
        r.changed = false;
        return r;
    }

    // AssignRandomAsync 内部 DeepClone + 打 async；随机性走 mut_rand_（单线程 hot path）。
    auto collided = mut_v2::collide::AssignRandomAsync(*src_prog, mut_rand_);
    if (!collided || collided->calls().empty()) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kSkipped;
        r.changed = false;
        return r;
    }

    std::shared_ptr<const syz::Prog> sp(collided.release());
    pr::MutationResult r;
    r.artifact = syz::MakeArtifactFromTypedProg(std::move(sp));
    r.changed  = true;
    r.status   = pr::MutationStatus::kOk;
    return r;
}

bool SyzV2MutatorEngine::RunMutationOps(syz::Prog& prog,
                                        mut_v2::SyzV2MutationContext& ctx)
{
    if (active_policy_idx_ < 0 ||
        active_policy_idx_ >= static_cast<int>(policies_.size()) ||
        !policies_[static_cast<size_t>(active_policy_idx_)]) {
        return false;
    }
    auto* policy = policies_[static_cast<size_t>(active_policy_idx_)].get();
    // SelectOp signatures take a Seed for legacy reasons; v2 ops don't read it.
    static const Seed kEmptySeed;

    // Mutation loop. Three requirements drive its shape:
    //   (T) Termination — bounded unconditionally by the iteration cap below.
    //   (P) Productivity — produce a CHANGED program whenever one is achievable.
    //       Returning the input unchanged wastes the execution slot (the fuzzer
    //       already holds that program's coverage), so a *declined* op must NOT
    //       end the loop — it just retries. Ending early on a few declines would
    //       abandon a productive mutation merely because insert_call / mutate_arg
    //       weren't selected yet (e.g. with no splice donor, splice declines
    //       ~43% of picks early on). An input that is genuinely un-mutatable
    //       (no op can ever apply) does not arise in practice: insert_call grows
    //       any program below RecommendedCalls and remove_call frees a slot in a
    //       full one, so an applying op always exists; the cap still bounds the
    //       worst case and surfaces it as kSkipped.
    //   (D) Distribution — after each *successful* op, stop with probability 1/5
    //       (geometric, mean ~5 ops), so the growth-biased weights pull length
    //       toward RecommendedCalls.
    bool any_applied = false;
    for (int iter = 0; iter < 64; ++iter) {  // 64 = termination backstop only
        const mut_v2::ISyzV2MutatorOp* op =
            policy->SelectOp(ops_, kEmptySeed, prog, ctx, mut_rand_);
        if (op == nullptr) {
            break;
        }
        const bool applied = op->Apply(prog, ctx, mut_rand_);
        splice_pending_extras(prog, ctx, applied);
        if (!applied) {
            continue;  // retry — a decline is not a reason to stop
        }
        any_applied = true;
        // 1/5 chance to stop after each successful op.
        if (!prog.calls().empty() &&
            mut_rand_.n_out_of(1, mut_v2::kExpectedMutationIterations)) {
            break;
        }
    }
    return any_applied;
}

std::unique_ptr<syz::Prog>
SyzV2MutatorEngine::MutateProgViaPolicy(const Seed& seed)
{
    // Decode seed to v2 Prog. On decode failure return nullptr; the
    // bytes wrapper preserves the original payload, the test wrapper
    // surfaces nullptr — Mutate is best-effort, not validation.
    std::string_view text(reinterpret_cast<const char*>(seed.payload.data()),
                          seed.payload.size());
    auto decoded = decoder_.decode(text);
    if (!decoded.has_value() || !decoded.value() || decoded.value()->calls().empty()) {
        return nullptr;
    }
    auto prog_ptr = std::move(decoded.value());
    syz::Prog& prog = *prog_ptr;

    // Build per-mutation context. gen_state 是 reFuzz 容器:choice_table /
    // pseudo_policy / corpus_store 注入式依赖留在 engine,survives 跨 op。
    //
    // [v2 Epic 7 PR-12 B2 — Step 3] 删了"预 analyze 整个 prog"循环 ——
    // 分析产物 (resources_/ma/va/files/strings) 改由各 mutation op 入口
    // 自己调 gs.analyze_for_mutation_boundary(prog, boundary) 重建,
    // 语义对齐上游 prog/analysis.go::analyze(p, c)。背景:
    // 旧版 reFuzz 全 prog 一次性 analyze → resources_ 含所有 call(包括
    // 未来 call) 的 producers → insert_call/mutate_arg 在 mid-position
    // 选 producer 时撞上未来 call 的 ret → encoder 写 wire 时
    // [kResult] unknown res reference (Step 2.5 钉死 27/28 = 96.4% 是
    // TOPO_REVERSED:consumer_call_idx < producer_call_idx)。
    auto ct_snap = EnsureChoiceTableSnapshot();
    mut_v2::GenState gs(target_);
    if (ct_snap && ct_snap->ready()) gs.set_choice_table(ct_snap.get());
    gs.set_corpus_store(corpus_store_);

    // Pick splice donor lazily — splice op is the only consumer; null
    // is acceptable (op handles fallback). The donor is decoded from a
    // sampled corpus seed if a corpus store is wired.
    std::unique_ptr<syz::Prog> donor_prog;
    if (corpus_store_ != nullptr) {
        std::mt19937_64 sampler_rng(mut_rand_.engine()());
        if (auto donor_id = corpus_store_->SampleSeedId(sampler_rng);
            donor_id.has_value()) {
            if (auto donor_handle = corpus_store_->GetSeed(*donor_id);
                donor_handle && !donor_handle->payload.empty()) {
                std::string_view donor_text(
                    reinterpret_cast<const char*>(donor_handle->payload.data()),
                    donor_handle->payload.size());
                auto donor_decoded = decoder_.decode(donor_text);
                if (donor_decoded.has_value() && donor_decoded.value() &&
                    !donor_decoded.value()->calls().empty()) {
                    donor_prog = std::move(donor_decoded.value());
                }
            }
        }
    }

    mut_v2::SyzV2MutationContext ctx;
    ctx.target       = &target_;
    ctx.splice_donor = donor_prog.get();
    ctx.gen_state    = &gs;
    ctx.choice_table = (ct_snap && ct_snap->ready()) ? ct_snap.get() : nullptr;
    // [mutator syz-parity] syzkaller Mutate uses ncalls = max(RecommendedCalls, len)
    // as the per-mutation length cap (prog/mutation.go), NOT a flat MaxCalls. Short
    // programs may grow to RecommendedCalls(30); already-long ones keep their length
    // (≤ kMaxCalls=40, the absolute corpus bound). Flat-40 let reFuzz over-grow.
    ctx.max_calls    = std::max(mut_v2::kRecommendedCalls,
                                static_cast<int>(prog.calls().size()));

    // [speed-compare arm D growth-parity] multi-op loop (was: one op per call) —
    // null policy / all-decline → no-op, caller surfaces original payload.
    if (!RunMutationOps(prog, ctx)) {
        return nullptr;
    }
    return prog_ptr;
}

std::vector<uint8_t> SyzV2MutatorEngine::MutateViaPolicy(const Seed& seed)
{
    auto prog_ptr = MutateProgViaPolicy(seed);
    if (!prog_ptr) {
        // Decode fail / no policy / op rejected — preserve original.
        return seed.payload;
    }
    try {
        std::string text_out = encoder_.encode(*prog_ptr);
        return std::vector<uint8_t>(text_out.begin(), text_out.end());
    } catch (...) {
        return seed.payload;
    }
}

std::unique_ptr<syz::Prog>
SyzV2MutatorEngine::MutateProgForTesting(const Seed& seed)
{
    ApplyPendingSwitchIfAny();
    EnsureMutationComponents();
    if (seed.payload.empty()) {
        return GenerateFreshProg();
    }
    return MutateProgViaPolicy(seed);
}

// ============================================================
// MutateTyped — §3.10 step 3 typed hot path
// ============================================================
//
// The hot path here MUST NOT call TextDecoder / TextEncoder /
// serialize_for_exec (oracle #17 + #18 + #20). Inputs come typed,
// mutations happen on a clone, outputs leave typed; canonical text is
// produced lazily via the artifact's provider only at terminal
// boundaries (corpus disk save / repro write).

::refuzz::program::MutationResult
SyzV2MutatorEngine::MutateTyped(const ::refuzz::program::ProgramArtifact& artifact)
{
    namespace pr = ::refuzz::program;

    ApplyPendingSwitchIfAny();
    EnsureMutationComponents();

    // D9: hard target check (no fallback path).
    pr::ProgramTargetKey expected{target_.os(), target_.arch(), target_.revision()};
    pr::CheckTargetOrDie(artifact, expected);

    // D2/D6: typed view must be present on a v2 hot-path entry.
    auto src_prog = artifact.As<syz::Prog>();
    if (src_prog == nullptr) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kEngineError;
        r.changed = false;
        return r;
    }

    // D4: mutate the clone, never the artifact's typed view.
    auto cloned = syz::DeepClone(*src_prog);
    if (!cloned || cloned->calls().empty()) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kSkipped;
        r.changed = false;
        return r;
    }

    syz::Prog& prog = *cloned;

    // Per-mutation context — mirror MutateViaPolicy.
    // [v2 PR-12 B2 — Step 3] 同 MutateProgViaPolicy:不再预 analyze;由各
    // mutation op 入口自行调 gs.analyze_for_mutation_boundary(prog, c)。
    auto ct_snap = EnsureChoiceTableSnapshot();
    mut_v2::GenState gs(target_);
    if (ct_snap && ct_snap->ready()) gs.set_choice_table(ct_snap.get());
    gs.set_corpus_store(corpus_store_);

    // [speed-compare arm D growth-parity] Typed splice donor — sample a corpus
    // seed's typed artifact (Seed::artifact->As<Prog>()), NO TextDecoder on the hot
    // loop (oracle #17 honored: the artifact is already typed). Previously the typed
    // path passed donor==null, disabling splice — the highest-weight (200) growth
    // op — so reFuzz programs never grew via splice. donor_view holds ownership for
    // the duration of the op loop below.
    std::shared_ptr<const syz::Prog> donor_view;
    if (corpus_store_ != nullptr) {
        std::mt19937_64 sampler_rng(mut_rand_.engine()());
        if (auto donor_id = corpus_store_->SampleSeedId(sampler_rng);
            donor_id.has_value()) {
            if (auto donor_handle = corpus_store_->GetSeed(*donor_id);
                donor_handle && donor_handle->artifact != nullptr) {
                auto dv = donor_handle->artifact->As<syz::Prog>();
                if (dv && !dv->calls().empty()) {
                    donor_view = std::move(dv);
                }
            }
        }
    }

    mut_v2::SyzV2MutationContext ctx;
    ctx.target       = &target_;
    ctx.splice_donor = donor_view.get();
    ctx.gen_state    = &gs;
    ctx.choice_table = (ct_snap && ct_snap->ready()) ? ct_snap.get() : nullptr;
    // [mutator syz-parity] syzkaller Mutate uses ncalls = max(RecommendedCalls, len)
    // as the per-mutation length cap (prog/mutation.go), NOT a flat MaxCalls. Short
    // programs may grow to RecommendedCalls(30); already-long ones keep their length
    // (≤ kMaxCalls=40, the absolute corpus bound). Flat-40 let reFuzz over-grow.
    ctx.max_calls    = std::max(mut_v2::kRecommendedCalls,
                                static_cast<int>(prog.calls().size()));

    auto wrap_into_artifact = [&](std::unique_ptr<syz::Prog> p,
                                  bool changed,
                                  pr::MutationStatus status) {
        std::shared_ptr<const syz::Prog> sp(p.release());
        pr::MutationResult r;
        r.artifact = syz::MakeArtifactFromTypedProg(std::move(sp));
        r.changed  = changed;
        r.status   = status;
        return r;
    };

    // [speed-compare arm D growth-parity] multi-op loop (was: one op per call) —
    // null policy / all-decline → unchanged clone (kSkipped), like before.
    const bool applied = RunMutationOps(prog, ctx);
    if (!applied) {
        return wrap_into_artifact(std::move(cloned), /*changed=*/false,
                                  pr::MutationStatus::kSkipped);
    }

    // §3.11 follow-up — apply target-specific invariant repair on the
    // mutated typed Prog before it leaves the engine. Mirrors
    // syzkaller `prog/mutation.go:99` calling `p.sanitizeFix()` at
    // the end of `Mutate()`. Without this hook, mutator outputs
    // (PTRACE_TRACEME, MREMAP_MAYMOVE-without-FIXED, mmap-without-
    // MAP_FIXED, dangerous ioctls, ARCH_SET_FS, ...) flow through
    // wrap_into_artifact → artifact → executor without invariant
    // repair. sanitize_fix is conservative — only touches calls in
    // its dispatch table, no-op for everything else.
    syz::sanitize_fix(prog);

    // [R5 size-recompute / syz-parity mutation.go:268-270] Recompute LenType
    // args from the mutated body before lowering to exec-wire — mutation ops
    // (array resize/append, union arm swap, splice) change buffer/array
    // contents but never touch sibling LenType args, so insn_cnt / iov-len /
    // sockaddr-len would otherwise ship stale.
    // EXCEPTION: calls whose length was deliberately mutated this Mutate()
    // (mutate_len_arg → ctx.size_preserved_calls) are skipped, so an
    // intentionally-inconsistent length survives to the wire — matching syz's
    // preserve=true → updateSizes=false → skip assignSizesCall path that
    // exercises kernel length/bounds validation.
    if (ctx.size_preserved_calls.empty()) {
        syz::assign_sizes_prog(prog);
    } else if (const syz::Target* tgt = prog.target(); tgt != nullptr) {
        for (auto& c : prog.mutable_calls()) {
            if (!c || c->meta() == nullptr) continue;
            if (ctx.size_preserved_calls.count(c.get()) != 0) continue;
            syz::assign_sizes_array(*tgt, c->mutable_args(), c->meta()->args(),
                                    /*autos=*/nullptr);
        }
    }

    // [≥1-call 不变量 — syz parity] 变异 + sanitize 后若程序被清空(某 op 或 sanitize_fix
    //   删空了 calls),绝不把空程序 wrap 成 valid artifact —— 它会被 admit 成 0-call 空 seed,
    //   之后 smash/mutational 对它反复 MutateTyped(空 input → 下方 calls().empty() 早退 kSkipped)
    //   空转烧 task。syzkaller 的 Mutate 始终保证 ≥1 call;这里把空输出当 kSkipped(不发 artifact)。
    if (prog.calls().empty()) {
        pr::MutationResult r;
        r.status  = pr::MutationStatus::kSkipped;
        r.changed = false;
        return r;
    }

    return wrap_into_artifact(std::move(cloned),
                              /*changed=*/applied,
                              pr::MutationStatus::kOk);
}

// ============================================================
// Policy switching
// ============================================================

bool SyzV2MutatorEngine::SwitchPolicyByName(std::string_view name)
{
    EnsureMutationComponents();
    const int idx = FindPolicyIndex(name);
    if (idx < 0) {
        return false;
    }
    next_policy_idx_.store(idx, std::memory_order_release);
    return true;
}

bool SyzV2MutatorEngine::ApplyPendingSwitchIfAny()
{
    EnsureMutationComponents();
    const int next = next_policy_idx_.load(std::memory_order_acquire);
    if (next < 0 || next >= static_cast<int>(policies_.size())) {
        return false;
    }
    if (next == active_policy_idx_) {
        return false;
    }
    active_policy_idx_ = next;
    if (policies_[static_cast<size_t>(active_policy_idx_)]) {
        policies_[static_cast<size_t>(active_policy_idx_)]->OnActivated(ops_);
    }
    return true;
}

std::string SyzV2MutatorEngine::ActivePolicyName() const
{
    if (active_policy_idx_ < 0 ||
        active_policy_idx_ >= static_cast<int>(policies_.size()) ||
        !policies_[static_cast<size_t>(active_policy_idx_)]) {
        return "syz_v2_balanced";
    }
    return std::string(policies_[static_cast<size_t>(active_policy_idx_)]->Name());
}

int SyzV2MutatorEngine::FindPolicyIndex(std::string_view policy_name) const
{
    for (size_t i = 0; i < policies_.size(); ++i) {
        if (policies_[i] && policies_[i]->Name() == policy_name) {
            return static_cast<int>(i);
        }
    }
    // §3.4 backward-compat aliases: "uniform" was the §3.4 name (single
    // generation policy). In §3.5 it routes to the weighted balanced
    // mutation policy — empty seed still falls back to generate, so
    // §3.4 oracle behavior is preserved.
    if (policy_name == "uniform")      return FindPolicyIndex("syz_v2_balanced");
    if (policy_name == "balanced")     return FindPolicyIndex("syz_v2_balanced");
    if (policy_name == "splice_heavy") return FindPolicyIndex("syz_v2_splice_heavy");
    if (policy_name == "insert_call")  return FindPolicyIndex("syz_v2_insert_call");
    if (policy_name == "mutate_arg")   return FindPolicyIndex("syz_v2_mutate_arg");
    if (policy_name == "remove_call")  return FindPolicyIndex("syz_v2_remove_call");
    if (policy_name == "squash_any")   return FindPolicyIndex("syz_v2_squash_any");
    return -1;
}

// ============================================================
// Lazy registry init
// ============================================================


//   (1) 持 rebuild_mu_:防 hot path lazy build 与 worker batch rebuild 并发 build 同一 corpus。
//       hot path Mutate **不持锁**(读 atomic_load),所以 mutate 不被 rebuild 阻塞。
//   (2) decoder 改成栈上局部:hot path Mutate 仍用成员 decoder_(line 196/235),
//       worker 线程跑 RebuildChoiceTable 时构造一个临时 TextDecoder 给 ChoiceTable::build,
//       避免两条线程并发改 decoder_ 内部状态。
//       legacy seed 用的是同一份 syz::Target,DecodeMode::kNonStrict 与成员构造一致。
void SyzV2MutatorEngine::RebuildChoiceTable()
{
    std::lock_guard<std::mutex> rebuild_lk(rebuild_mu_);
    auto fresh = std::make_shared<mut_v2::ChoiceTable>();
    if (corpus_store_ != nullptr) {
        ::refuzz::program::syz::TextDecoder local_decoder(
            target_, ::refuzz::program::syz::DecodeMode::kNonStrict);
        fresh->build(target_, *corpus_store_, local_decoder, enabled_calls_);
    } else {
        fresh->build(target_, enabled_calls_);
    }
    std::shared_ptr<const ::refuzz::program::syz::Target::IChoiceTable>
        as_iface(fresh);
    std::atomic_store(&choice_table_, std::move(fresh));
    target_.set_default_choice_table(std::move(as_iface));
}

// [machine-check C4.6] Swap the enabled mask + rebuild. The mask is set under
// rebuild_mu_ (it is read by RebuildChoiceTable's build under the same lock);
// the rebuild then re-acquires the lock and builds the ChoiceTable from the new
// mask. Called once at startup (no concurrent Mutate), but lock-correct anyway.
void SyzV2MutatorEngine::SetEnabledCalls(std::vector<std::uint8_t> enabled_mask)
{
    {
        std::lock_guard<std::mutex> rebuild_lk(rebuild_mu_);
        enabled_calls_ = std::move(enabled_mask);
    }
    RebuildChoiceTable();
}

// Lazy first build + snapshot for the read side. Mutate hot path
// pulls a snapshot here; if no admission has happened yet, this
// drives the initial build (preserves the §3.6 lazy-init behavior).
mut_v2::ChoiceTableHandle SyzV2MutatorEngine::EnsureChoiceTableSnapshot()
{
    if (auto snap = std::atomic_load(&choice_table_); snap != nullptr) {
        return snap;
    }
    RebuildChoiceTable();
    // [v2 syzkaller-parity throttle] lazy first build 后,记录"build 反映的 corpus 大小"。
    //   后续 OnSeedAdmitted 节流以此为基准。空 corpus 启动 → 0,加完 33 个才触发首次更新。
    if (corpus_store_ != nullptr) {
        ct_built_at_corpus_size_.store(corpus_store_->Size(),
                                       std::memory_order_release);
    }
    return std::atomic_load(&choice_table_);
}


//   严格对齐 syzkaller 上游 pkg/fuzzer/fuzzer.go:406-426 节流逻辑:
//     regenerateEveryProgs = (corpus < 100) ? 33 : 333
//     仅当 ct_built_at_corpus_size_ + regenerateEveryProgs < cur 才 rebuild
//   语义:
//     - admit 数没积够阈值时跳过,**不丢更新**(下次 admit 仍会 evaluate);
//     - rebuild 后 ct_built_at_corpus_size_ 更新为 cur,作为下次节流基准;
//     - 没有 corpus_store 的退化场景(测试 / 极端 wiring) → 直接 rebuild,等价 v1。
//   动机:dynamic prio 需要最小统计样本(≥33 seed)才有意义,否则前期 1-32 个 admit
//   时的噪声 prio 会被 mutator 立即用作引导,导致 corpus 焦点漂移、跨 subsystem 拼凑。
void SyzV2MutatorEngine::OnSeedAdmitted(const Seed& /*seed*/)
{
    if (corpus_store_ == nullptr) {
        RebuildChoiceTable();
        return;
    }
    const std::size_t cur = corpus_store_->Size();
    const std::size_t threshold = (cur < 100) ? 33 : 333;
    const std::size_t prev =
        ct_built_at_corpus_size_.load(std::memory_order_acquire);
    // 注:syzkaller 上游条件是 `prev + threshold < cur`(严格小于);保留同语义。
    if (prev + threshold >= cur) {
        return;  // 还没攒够,跳过本次 rebuild。下次 admit 再判。
    }
    RebuildChoiceTable();
    // 写"反映的 corpus 大小":此处用 cur 而非 build 完成后的 size,
    //   是保守口径(下次会更早再触发 rebuild,避免欠更新)。
    ct_built_at_corpus_size_.store(cur, std::memory_order_release);
}

void SyzV2MutatorEngine::EnsureMutationComponents()
{
    if (!ops_.empty() && !policies_.empty()) {
        return;
    }

    // Op registry order is referenced by FindPolicyIndex via name; the
    // weighted policy iterates the registry, so this order also
    // determines which op wins on equal-roll ties (none currently).
    ops_.push_back(std::make_unique<mut_v2::SyzV2SpliceOp>());
    ops_.push_back(std::make_unique<mut_v2::SyzV2InsertCallOp>());
    ops_.push_back(std::make_unique<mut_v2::SyzV2MutateArgOp>());
    ops_.push_back(std::make_unique<mut_v2::SyzV2SquashAnyOp>());
    ops_.push_back(std::make_unique<mut_v2::SyzV2RemoveCallOp>());

    // Policy registry — index 0 (kBalancedPolicyIndex) is the default.
    policies_.push_back(std::make_unique<mut_v2::SyzV2WeightedMutationPolicy>(
        "syz_v2_balanced"));
    policies_.push_back(std::make_unique<mut_v2::SyzV2SingleOpPolicy>(
        "syz_v2_splice_heavy", "splice"));
    policies_.push_back(std::make_unique<mut_v2::SyzV2SingleOpPolicy>(
        "syz_v2_insert_call", "insert_call"));
    policies_.push_back(std::make_unique<mut_v2::SyzV2SingleOpPolicy>(
        "syz_v2_mutate_arg", "mutate_arg"));
    policies_.push_back(std::make_unique<mut_v2::SyzV2SingleOpPolicy>(
        "syz_v2_remove_call", "remove_call"));
    policies_.push_back(std::make_unique<mut_v2::SyzV2SingleOpPolicy>(
        "syz_v2_squash_any", "squash_any"));

    active_policy_idx_ = kBalancedPolicyIndex;
    next_policy_idx_.store(kBalancedPolicyIndex, std::memory_order_release);
}

// [v2 Epic 5 PR-5-C] MutateWithHints override.
//
// Source-Prog selection (§3.10 D6 artifact-first contract):
//   1. seed.artifact valid AND has typed syz::Prog view → use it
//      directly (zero-cost; the typed view is the authority).
//   2. else, fall back to TextDecoder.decode(seed.payload). This path
//      exists for legacy / pre-V1-retirement callers that hand bytes
//      only; per `core/include/refuzz/core/channel_contract.hpp:339`,
//      payload is exec-wire/cache and is NOT guaranteed to round-trip
//      back to typed Prog. PR-5-D HintsConsumerStage will land
//      seed.artifact valid (built from corpus admit), making path 1
//      the production case.
//
// Each candidate produced by the algorithm is deep-cloned and wrapped
// into a ProgramArtifact (typed authority + lazy canonical text)
// before being handed to `on_candidate`. The clone is necessary
// because hints' working Prog is reused across candidates (in-place
// mutation + restore); without a clone, downstream consumers would
// see the post-restore state.
//
// All decode/access failures → silent return (matches Mutate's
// best-effort contract). call_index out-of-range → no-op inside
// MutateProgWithHints.
void SyzV2MutatorEngine::MutateWithHints(
    const Seed& seed,
    int         call_index,
    const ::refuzz::mutator::syz_v2::hints::CompMap& comps,
    const HintsArtifactCallback& on_candidate)
{
    namespace pr = ::refuzz::program;

    if (!on_candidate) return;

    // Path 1 — artifact-first (production V2 path).
    std::shared_ptr<const syz::Prog> src_prog;
    if (seed.artifact && seed.artifact->valid()) {
        src_prog = seed.artifact->As<syz::Prog>();
    }

    // Path 2 — payload fallback (legacy callers; possible payload may
    // not decode → silent return matches Mutate semantics).
    std::unique_ptr<syz::Prog> decoded_owner;
    if (!src_prog && !seed.payload.empty()) {
        std::string_view text(reinterpret_cast<const char*>(seed.payload.data()),
                              seed.payload.size());
        auto decoded = decoder_.decode(text);
        if (!decoded.has_value() || !decoded.value() ||
            decoded.value()->calls().empty()) {
            return;
        }
        decoded_owner = std::move(decoded.value());
        // Convert unique_ptr<Prog> to shared_ptr<const Prog> so both
        // paths feed the same algorithm entry point.
        src_prog = std::shared_ptr<const syz::Prog>(std::move(decoded_owner));
    }

    if (!src_prog || src_prog->calls().empty()) {
        return;
    }

    auto exec = [&](const syz::Prog& mutated) -> bool {
        // Deep-clone so downstream consumers see a stable snapshot;
        // hints' working Prog will be restored after this returns.
        auto clone = syz::DeepClone(mutated);
        if (clone == nullptr) return true;        // skip but keep iterating
        // [R5 size-recompute] hints replace cmp operands (possibly a LenType
        // value); recompute len args from the body before exec-wire lowering.
        syz::assign_sizes_prog(*clone);
        std::shared_ptr<const syz::Prog> sp(std::move(clone));
        pr::ProgramArtifact artifact = syz::MakeArtifactFromTypedProg(std::move(sp));
        if (!artifact.valid()) return true;
        return on_candidate(std::move(artifact));
    };

    ::refuzz::mutator::syz_v2::hints::MutateProgWithHints(
        *src_prog, call_index, comps, exec);
}

// [seed-value signal C] As<syz::Prog>() lives here (syz-owned engine); generic
// callers receive only the neutral program::StateAltitude POD.
std::optional<::refuzz::program::StateAltitude>
SyzV2MutatorEngine::AnalyzeStateAltitude(
    const ::refuzz::program::ProgramArtifact& artifact)
{
    if (!artifact.valid()) {
        return std::nullopt;
    }
    auto prog = artifact.As<syz::Prog>();
    if (!prog) {
        return std::nullopt;
    }
    return ::refuzz::program::syz::ComputeStateAltitude(*prog);
}

} // namespace refuzz::fuzzer
