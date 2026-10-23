#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"

#include "refuzz/fuzzer/interfaces.hpp"       // ICorpusStore / SeedHandle (GetSeed)
#include "refuzz/program/seed.hpp"            // Seed (handle->metadata)
#include "refuzz/program/seed_metadata.hpp"   // CorpusCoverageMetadata
#include "refuzz/scheduler/horizon/seed_horizon.hpp"  // [seed-future-value]
#include "refuzz/scheduler/horizon/seed_band2.hpp"    // [future_band2] shadow candidate
#include "refuzz/scheduler/horizon/static_belief_graph.hpp"  // [belief-graph] static prior
#include "refuzz/scheduler/rarity_score.hpp"  // [signal A] shared RarityScore

#include <algorithm>  // [v2 batch 3 G6] std::remove for InvalidateSeed

namespace refuzz::fuzzer {

PrioritySchedulerEngine::PrioritySchedulerEngine(const ICorpusStore* corpus_store)
    : corpus_store_(corpus_store)
{}

SchedulerContext PrioritySchedulerEngine::MakeContext()
{
    SchedulerContext ctx{ready_queue_, boosted_, cooled_, cursor_};
    // value-weighted policy 的输入;coverage-blind policy 忽略。
    ctx.seed_cover = &seed_cover_;
    ctx.pc_count   = &pc_count_;
    ctx.rng        = &rng_;
    return ctx;
}

std::string PrioritySchedulerEngine::Name() const
{
    return "priority_scheduler";
}

int PrioritySchedulerEngine::RegisterPolicy(std::string name, std::unique_ptr<ISchedulingPolicy> policy)
{
    if (!policy) {
        return -1;
    }
    const int idx = static_cast<int>(policy_registry_.size());
    policy_name_index_[name] = idx;
    policy_registry_.push_back(std::move(policy));
    if (policy_idx_ < 0) {
        policy_idx_ = idx;
        next_policy_idx_.store(-1, std::memory_order_release);
    }
    return idx;
}

bool PrioritySchedulerEngine::SwitchPolicyByName(std::string_view name)
{
    const auto it = policy_name_index_.find(std::string(name));
    if (it == policy_name_index_.end()) {
        return false;
    }
    next_policy_idx_.store(it->second, std::memory_order_release);
    return true;
}

bool PrioritySchedulerEngine::ApplyPendingSwitchIfAny()
{
    const int next = next_policy_idx_.load(std::memory_order_acquire);
    if (next < 0) {
        return false;
    }
    if (next >= static_cast<int>(policy_registry_.size()) || next == policy_idx_) {
        next_policy_idx_.store(-1, std::memory_order_release);
        return false;
    }
    SchedulerContext ctx = MakeContext();
    policy_registry_[next]->OnActivated(ctx);
    policy_idx_ = next;
    next_policy_idx_.store(-1, std::memory_order_release);
    return true;
}

std::string PrioritySchedulerEngine::ActivePolicyName() const
{
    for (const auto& [name, idx] : policy_name_index_) {
        if (idx == policy_idx_) {
            return name;
        }
    }
    return {};
}

std::optional<SeedSelection> PrioritySchedulerEngine::NextSeedId()
{
    ApplyPendingSwitchIfAny();
    if (policy_idx_ < 0 || policy_idx_ >= static_cast<int>(policy_registry_.size())) {
        return std::nullopt;
    }
    SchedulerContext ctx = MakeContext();
    auto seed = policy_registry_[policy_idx_]->Next(ctx);
    if (!seed.has_value()) {
        return std::nullopt;
    }
    // [mab] policy 把本次抽样的 (pr, γ) 写回 ctx;组成 SeedSelection 作为数据返回(非 MAB
    // policy 不写 → ctx 保持中性默认 1/0,reward 通道也是 no-op)。
    return SeedSelection{*seed, ctx.sel_pr, ctx.sel_gamma};
}

void PrioritySchedulerEngine::OnFeedback(uint64_t seed_id, SeedDisposition disposition)
{
    ApplyPendingSwitchIfAny();
    if (policy_idx_ < 0 || policy_idx_ >= static_cast<int>(policy_registry_.size())) {
        return;
    }
    SchedulerContext ctx = MakeContext();
    policy_registry_[policy_idx_]->OnFeedback(ctx, seed_id, disposition);
}

// [mab-stage-selection Step 2] 转发无状态数值 reward 给 active policy。(pr, γ) 由 control loop
// 从 exec_id 在途簿记取回一并传入 → policy 不持任何 per-seed 在途状态。非 MAB policy default no-op。
void PrioritySchedulerEngine::OnSeedReward(uint64_t seed_id, double pr, double gamma,
                                           double cov_gain, double task_time_s)
{
    ApplyPendingSwitchIfAny();
    if (policy_idx_ < 0 || policy_idx_ >= static_cast<int>(policy_registry_.size())) {
        return;
    }
    policy_registry_[policy_idx_]->OnSeedReward(seed_id, pr, gamma, cov_gain, task_time_s);
}

double PrioritySchedulerEngine::SeedRarityScore(uint64_t seed_id) const
{
    // seed_cover_ is only populated when corpus_store_ was injected (the
    // value-weighted path). Unknown seed → 0 (no information). pc_count_
    // reflects the live corpus frequency at call time (intended non-stationary).
    const auto it = seed_cover_.find(seed_id);
    if (it == seed_cover_.end()) {
        return 0.0;
    }
    return RarityScore(it->second, pc_count_);
}

double PrioritySchedulerEngine::CoverRarityScore(
    const std::vector<std::uint64_t>& cover_pcs) const
{
    // Same corpus pc_count basis as SeedRarityScore, but over an arbitrary PC
    // set (a mutation's executed footprint). 0 when no corpus_store injected.
    return RarityScore(cover_pcs, pc_count_);
}

double PrioritySchedulerEngine::SeedMabGhat(uint64_t seed_id) const
{
    // const observation: read the current active policy without applying any
    // pending switch (slight staleness is fine for a shadow baseline).
    if (policy_idx_ < 0 || policy_idx_ >= static_cast<int>(policy_registry_.size())) {
        return 0.0;
    }
    return policy_registry_[policy_idx_]->SeedMabGhat(seed_id);
}

void PrioritySchedulerEngine::OnSeedAdded(uint64_t seed_id)
{
    ApplyPendingSwitchIfAny();
    if (!known_.insert(seed_id).second) {
        return;
    }
    ready_queue_.push_back(seed_id);

    // [value-weighted policies] corpus_store_ 非空时,缓存该种子的稳定 cover +
    // 累加每个 PC 的种子计数,供 size_weighted(len)/ rarity_weighted(Σ1/count)用。
    // 候选模型保证入库种子带 CorpusCoverageMetadata;无 store / 无 cover 时跳过
    // (加权 policy 对该种子退化为权重 1)。
    if (corpus_store_ != nullptr) {
        if (auto handle = corpus_store_->GetSeed(seed_id)) {
            if (const auto* cc = handle->metadata.Get<CorpusCoverageMetadata>();
                cc != nullptr && !cc->cover_hashes.empty()) {
                for (const std::uint64_t pc : cc->cover_hashes) {
                    ++pc_count_[pc];
                }
                seed_cover_[seed_id] = cc->cover_hashes;
            }
            // [seed-future-value] cache future(seed) from the seed's artifact (the
            // SeedHorizon folds its realized handoffs into the live mask + scores
            // the frontier it bordered). Observation only — drives no selection.
            if (seed_horizon_ != nullptr && handle->artifact &&
                handle->artifact->valid()) {
                future_[seed_id] = seed_horizon_->OnSeedAdmitted(*handle->artifact);
                // [future_cht] masked call-transition horizon (score-then-fold its
                // own calls into the exercised mask). Cached beside future_.
                cht_[seed_id] = seed_horizon_->TransitionValue(*handle->artifact);
            }
            // [future_band2] band-② uncovered-handler-mass-per-call (the kill-shot
            // signal), score-then-fold against the live covered set. Needs both the
            // seed's raw cover (CorpusCoverageMetadata) and the artifact (for ncalls).
            // SHADOW ONLY — cached for SeedBand2Value, drives nothing.
            if (seed_band2_ != nullptr && handle->artifact && handle->artifact->valid()) {
                if (const auto* cc = handle->metadata.Get<CorpusCoverageMetadata>();
                    cc != nullptr && !cc->cover_hashes.empty()) {
                    band2_[seed_id] =
                        seed_band2_->OnSeedAdmitted(cc->cover_hashes, *handle->artifact);
                }
            }
            // [belief-graph] static unlock-potential prior from the seed's calls. Cached
            // beside future_/band2_. Observation only — drives no selection (shadow).
            if (belief_graph_ != nullptr && handle->artifact && handle->artifact->valid()) {
                belief_[seed_id] = belief_graph_->Score(*handle->artifact);
            }
        }
    }
}

double PrioritySchedulerEngine::SeedFutureValue(uint64_t seed_id) const
{
    auto it = future_.find(seed_id);
    return it == future_.end() ? 0.0 : it->second;
}

double PrioritySchedulerEngine::SeedTransitionValue(uint64_t seed_id) const
{
    auto it = cht_.find(seed_id);
    return it == cht_.end() ? 0.0 : it->second;
}

double PrioritySchedulerEngine::SeedBand2Value(uint64_t seed_id) const
{
    auto it = band2_.find(seed_id);
    return it == band2_.end() ? 0.0 : it->second;
}

double PrioritySchedulerEngine::SeedBeliefValue(uint64_t seed_id) const
{
    auto it = belief_.find(seed_id);
    return it == belief_.end() ? 0.0 : it->second;
}

// [belief-graph Phase B] region-precise live calibration — forward the per-exec executed set + per-variant
// new-coverage map to the injected graph (thread-safe inside). No-op when no graph (BeliefActive() gated).
void PrioritySchedulerEngine::ObserveBelief(
    const std::unordered_set<std::string>& executed,
    const std::unordered_map<std::string, std::vector<std::uint64_t>>& new_by_variant)
{
    if (belief_graph_ != nullptr) {
        belief_graph_->Observe(executed, new_by_variant);
    }
}

void PrioritySchedulerEngine::DumpBeliefPosterior(const std::string& path) const
{
    if (belief_graph_ != nullptr) {
        belief_graph_->DumpPosterior(path);
    }
}

// [v2 batch 3 G6] 从所有 pool erase seed_id,使后续 NextSeedId 不返该 id。
// 调用频率低(corpus_verify_consumer 在 retry 上限时一次/seed),线性扫可接受。
// `known_` 也要 erase,否则将来 OnSeedAdded(同 id)会被去重屏蔽 — 虽然 G6 不
// 重新激活 inactive seed,但保留接口对称(future "reactivate" 需求时不需要同改)。
void PrioritySchedulerEngine::InvalidateSeed(uint64_t seed_id)
{
    ready_queue_.erase(std::remove(ready_queue_.begin(), ready_queue_.end(), seed_id),
                       ready_queue_.end());
    // std::deque 没有 remove free function;手动 erase 命中项。
    for (auto it = boosted_.begin(); it != boosted_.end(); ) {
        if (*it == seed_id) {
            it = boosted_.erase(it);
        } else {
            ++it;
        }
    }
    cooled_.erase(seed_id);
    known_.erase(seed_id);
    // [value-weighted policies] 同步清 cover 缓存 + 回退 PC 计数,保持 rarity 准确。
    if (auto it = seed_cover_.find(seed_id); it != seed_cover_.end()) {
        for (const std::uint64_t pc : it->second) {
            if (auto pit = pc_count_.find(pc); pit != pc_count_.end()) {
                if (--pit->second == 0) {
                    pc_count_.erase(pit);
                }
            }
        }
        seed_cover_.erase(it);
    }
    // [seed-future-value] symmetric per-seed cleanup — future_ has the same
    // lifetime as seed_cover_ (populated in OnSeedAdded, dead once evicted).
    // Omitting it leaks unboundedly across MaybeMinimizeCorpus evictions and would
    // return a dead seed's value on id reuse.
    future_.erase(seed_id);
    cht_.erase(seed_id);  // [future_cht] same lifetime as future_
    band2_.erase(seed_id);  // [future_band2] same lifetime as future_
    // cursor_ 是 ready_queue_ 上的索引;ready_queue_ shrink 可能让 cursor 越界,
    // policy.Next 下次访问时自己 wrap;保持简单不在此 fixup。
}

} // namespace refuzz::fuzzer
