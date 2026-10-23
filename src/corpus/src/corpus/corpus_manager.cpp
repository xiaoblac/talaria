#include "refuzz/corpus/corpus_manager.hpp"

#include "refuzz/program/artifact.hpp"               // ProgramArtifact::valid()
#include "refuzz/program/artifact_materializer.hpp"  // MaterializeCanonicalText
#include "refuzz/program/seed_metadata.hpp"          // SeedSourceMetadata + CorpusCoverageMetadata

#include <algorithm>      // std::sort / std::unique (merge cover union)
#include <cstdint>
#include <unordered_map>  // [coverage-ownership] bootstrap best-owner election
#include <utility>
#include <vector>

namespace refuzz::fuzzer {

namespace {

// [syz corpus.go:140 merge] union src (edges+parallel prios) into dst, keeping the
// per-edge MAX prio (syz signalPrio: an edge hit by a successful call dominates).
// Parallel-array invariant preserved; order is irrelevant (sweep iterates all).
void MergeSignalCoverWithPrio(std::vector<std::uint64_t>& dst_edges,
                              std::vector<std::uint8_t>&  dst_prios,
                              const std::vector<std::uint64_t>& src_edges,
                              const std::vector<std::uint8_t>&  src_prios)
{
    std::unordered_map<std::uint64_t, std::uint8_t> m;
    m.reserve(dst_edges.size() + src_edges.size());
    for (std::size_t i = 0; i < dst_edges.size(); ++i) {
        m[dst_edges[i]] = i < dst_prios.size() ? dst_prios[i] : std::uint8_t{0};
    }
    for (std::size_t i = 0; i < src_edges.size(); ++i) {
        const std::uint8_t p = i < src_prios.size() ? src_prios[i] : std::uint8_t{0};
        auto it = m.find(src_edges[i]);
        if (it == m.end() || p > it->second) {
            m[src_edges[i]] = p;
        }
    }
    dst_edges.clear();
    dst_prios.clear();
    dst_edges.reserve(m.size());
    dst_prios.reserve(m.size());
    for (const auto& [e, p] : m) {
        dst_edges.push_back(e);
        dst_prios.push_back(p);
    }
}

// union src PCs into dst, sorted-unique (cover_hashes = syz info.cover union).
void UnionSortedInto(std::vector<std::uint64_t>& dst, const std::vector<std::uint64_t>& src)
{
    if (src.empty()) {
        return;
    }
    dst.insert(dst.end(), src.begin(), src.end());
    std::sort(dst.begin(), dst.end());
    dst.erase(std::unique(dst.begin(), dst.end()), dst.end());
}

}  // namespace

bool NonEmptyPayloadFilter::Test(const Seed& seed, const CorpusContext& /*ctx*/) const
{
    return !seed.payload.empty();
}

FilterSelection AllFiltersPolicy::SelectFilters(
    const std::vector<std::unique_ptr<ICorpusFilter>>& registry,
    const Seed& /*seed*/,
    const CorpusContext& /*ctx*/) const
{
    FilterSelection sel;
    sel.filters.reserve(registry.size());
    for (const auto& filter : registry) {
        sel.filters.push_back(filter.get());
    }
    return sel;
}

FilterSelection NoFilterPolicy::SelectFilters(
    const std::vector<std::unique_ptr<ICorpusFilter>>& /*registry*/,
    const Seed& /*seed*/,
    const CorpusContext& /*ctx*/) const
{
    return FilterSelection{};
}

CorpusManager::CorpusManager(ICorpusStore& store,
                             const core::EngineHandle<ISchedulerEngine>& scheduler_handle,
                             CorpusInbox& inbox,
                             int max_drain,
                             refuzz::fuzzer::metrics::FuzzerMetrics* metrics,
                             AdmitMode admit_mode)
    : store_(store)
    , scheduler_handle_(scheduler_handle)
    , inbox_(inbox)
    , max_drain_(max_drain)
    , metrics_(metrics)
    , admit_mode_(admit_mode)
{
    RegisterFilter("non_empty_payload", std::make_unique<NonEmptyPayloadFilter>());
    // [v2 SubT-D / G8] payload-content dedup,FNV-1a 64-bit。挂在 AllFiltersPolicy
    // 链上;NoFilterPolicy 不受影响。详 docs/admit-pipeline-alignment/
    // 200_batch2_framework_primitives.md §3.D。
    RegisterFilter("content_hash_dedup", std::make_unique<ContentHashDedupFilter>());

    RegisterAdmissionPolicy("all_filters", std::make_unique<AllFiltersPolicy>());
    RegisterAdmissionPolicy("no_filter", std::make_unique<NoFilterPolicy>());
}

int CorpusManager::RegisterFilter(std::string name, std::unique_ptr<ICorpusFilter> filter)
{
    if (!filter) {
        return -1;
    }
    const int idx = static_cast<int>(filter_registry_.size());
    filter_name_index_[std::move(name)] = idx;
    filter_registry_.push_back(std::move(filter));
    return idx;
}

int CorpusManager::RegisterAdmissionPolicy(std::string name,
                                           std::unique_ptr<ICorpusAdmissionPolicy> policy)
{
    if (!policy) {
        return -1;
    }
    const int idx = static_cast<int>(admission_policy_registry_.size());
    admission_policy_name_index_[std::move(name)] = idx;
    admission_policy_registry_.push_back(std::move(policy));
    return idx;
}

bool CorpusManager::SwitchAdmissionPolicyByName(std::string_view name)
{
    const auto it = admission_policy_name_index_.find(std::string(name));
    if (it == admission_policy_name_index_.end()) {
        return false;
    }
    SwitchAdmissionPolicy(it->second);
    return true;
}

void CorpusManager::SwitchAdmissionPolicy(int idx)
{
    if (idx < 0 || idx >= static_cast<int>(admission_policy_registry_.size())) {
        return;
    }
    next_admission_policy_idx_.store(idx, std::memory_order_release);
}

bool CorpusManager::MaybeApplyPendingSwitch()
{
    const int next = next_admission_policy_idx_.load(std::memory_order_acquire);
    if (next == admission_policy_idx_) {
        return false;
    }
    CorpusContext ctx{store_};
    admission_policy_registry_[next]->OnActivated(ctx);
    admission_policy_idx_ = next;
    return true;
}


std::string CorpusManager::ActivePolicyName() const
{
    for (const auto& [name, idx] : admission_policy_name_index_) {
        if (idx == admission_policy_idx_) {
            return name;
        }
    }
    return {};
}

void CorpusManager::SetOnAdmit(std::function<void(const Seed&)> cb)
{
    on_admit_ = std::move(cb);
}

void CorpusManager::SetOnCoverMerge(std::function<void(const Seed&)> cb)
{
    on_cover_merge_ = std::move(cb);
}

OfferResult CorpusManager::OfferVerdict(
    const std::vector<uint8_t>& program_payload,
    const std::shared_ptr<const ::refuzz::program::ProgramArtifact>& artifact,
    const Verdict& verdict,
    SeedSource source,
    bool divert_to_caller,
    uint64_t& next_seed_id,
    SeedOrigin origin,
    uint64_t parent_seed_id)
{
    OfferResult res;

    // 准入判据(承接旧 3 dispatcher 的差异):
    bool should_admit = false;
    switch (admit_mode_) {
    case AdmitMode::kInteresting:  // 旧 corpus_admit
        should_admit = verdict.interesting;
        break;
    case AdmitMode::kAlways:       // 旧 corpus_admit_all
        should_admit = !verdict.is_crash && !verdict.is_timeout && !verdict.is_exec_error;
        break;
    case AdmitMode::kNever:        // 旧 shadow_only
        should_admit = false;
        break;
    }
    if (!should_admit) {
        return res;  // built_seed 空 / admitted_to_inbox=false
    }

    // 构造 Seed —— 逻辑搬自旧 CorpusAdmitDispatcher::Dispatch。
    Seed new_seed;
    new_seed.seed_id = next_seed_id++;
    // [v2 admission canonical-cache normalize] artifact 在场时 materialize canonical
    // text 当 payload(与 boot/LoadAll 路径一致,让下游 ContentHashDedupFilter 跨重启
    // 收敛);否则回落 program_payload(v1 raw 路径或 materialize 失败)。
    if (artifact && artifact->valid()) {
        auto bytes_or = ::refuzz::program::MaterializeCanonicalText(*artifact);
        if (bytes_or.has_value() && *bytes_or != nullptr) {
            new_seed.payload = **bytes_or;
        } else {
            new_seed.payload = program_payload;
        }
    } else {
        new_seed.payload = program_payload;
    }
    new_seed.artifact = artifact;   // v2 typed authority;v1 路径为 nullptr
    new_seed.priority = 1;
    new_seed.metadata.Set(SeedSourceMetadata{source, /*attempt=*/0});
    new_seed.metadata.Set(SeedAdmissionStateMetadata{});
    // [mab lineage Step A] stamp the caller-decided lineage verbatim — same
    // contract as SeedSourceMetadata above. corpus stores; control owns the
    // gen-vs-mut classification. See docs/plans/mab-stage-selection.md §3.
    new_seed.metadata.Set(SeedLineageMetadata{origin, parent_seed_id});

    // divert(triage_enabled):构造好的 Seed 交回 caller 路由到 PendingSeedMap,不进 inbox。
    if (divert_to_caller) {
        res.built_seed = std::move(new_seed);
        return res;
    }
    const bool ok = inbox_.TryPush(std::move(new_seed));
    res.admitted_to_inbox = ok;
    res.inbox_full_drop   = !ok;  // 此分支必有 should_admit=true && !divert,故 !ok 即"尝试但满"
    return res;
}

bool CorpusManager::TryAdmit(Seed candidate, const CorpusContext& ctx)
{
    const auto& policy = *admission_policy_registry_[admission_policy_idx_];
    const FilterSelection selected = policy.SelectFilters(filter_registry_, candidate, ctx);

    for (const ICorpusFilter* filter : selected.filters) {
        if (filter == nullptr) {
            continue;
        }
        if (!filter->Test(candidate, ctx)) {
            return false;
        }
    }

    // [syz corpus.go:140 parity] content-duplicate of a live corpus seed → MERGE its
    // stable signal/cover into that seed instead of reject-and-lose. Iterate the same
    // policy-selected set as Test() above, so NoFilterPolicy (dups allowed) is
    // preserved and AllFiltersPolicy (production) activates the merge. syz accumulates
    // signal on an existing Sig, which keeps owners alive across the sweep; per-call
    // fan-out collapses that land on the same minimized program merge into one item
    // instead of vanishing.
    for (const ICorpusFilter* filter : selected.filters) {
        if (filter == nullptr) {
            continue;
        }
        if (auto existing = filter->DuplicateOf(candidate, ctx); existing.has_value()) {
            MergeIntoExisting(*existing, candidate);
            if (on_cover_merge_) {
                on_cover_merge_(candidate);
            }
            return true;  // admitted via merge — no new seed, signal preserved
        }
    }

    if (!payload_bytes_initialized_) {
        SyncPayloadBytesFromStore();
    }

    // [coverage-ownership bound] admit-all:准入由上游 novelty 闸 + triage 已判定;corpus
    // 不再以覆盖所有权二次门准入 —— 那会把"稳定 PC 经变化边到达"的新覆盖在计入 corpus_pc
    // 前误丢(后期覆盖被压死)。覆盖所有权只在周期 sweep(EstablishInvariantFromStore)里
    // 决定"抛弃谁";sweep 之前每个 seed 都有一段被 MAB 采样积分的"试镜"窗。
    const uint64_t id = candidate.seed_id;
    const int64_t payload_bytes = static_cast<int64_t>(candidate.payload.size());

    // AddSeed 会 move 走 candidate,故先留一份副本供 filter notify / on_admit 使用。
    const bool will_notify = !filter_registry_.empty();
    const bool need_copy   = will_notify || static_cast<bool>(on_admit_);
    Seed kept;
    if (need_copy) {
        kept = candidate;
    }
    if (!store_.AddSeed(std::move(candidate))) {
        return false;
    }
    // scheduler engine 切换由 SchedulerManager 原子完成;每次 acquire 拿到调用瞬间的
    // active engine,正确性由 Manager 保证。
    scheduler_handle_.Get().OnSeedAdded(id);
    if (metrics_ && metrics_->corpus_growth) {
        metrics_->corpus_growth->Inc();
    }
    running_payload_bytes_ += payload_bytes;

    // [v2 SubT-D] 通知所有 filter — 即便 admission policy 没选某 filter,stateful filter
    // (eg. ContentHashDedupFilter)仍需看到所有 admit 才能维持正确 dedup state。
    if (will_notify) {
        for (auto& filter : filter_registry_) {
            if (filter) filter->OnSeedAdded(kept);
        }
    }
    if (on_admit_) {
        on_admit_(kept);
    }
    return true;
}

void CorpusManager::MergeIntoExisting(std::uint64_t existing_seed_id, const Seed& candidate)
{
    // Union the re-discovered program's stable signal/cover into the existing seed.
    // The updater runs under the store's unique_lock (must not call other store
    // methods); it only mutates the passed MetadataMap. `candidate` outlives this
    // synchronous call, so capturing cand_cc by pointer is safe.
    const auto* cand_cc = candidate.metadata.Get<CorpusCoverageMetadata>();
    if (cand_cc != nullptr &&
        (!cand_cc->signal_cover_hashes.empty() || !cand_cc->cover_hashes.empty())) {
        store_.UpdateSeedMetadata(
            existing_seed_id, [cand_cc](refuzz::core::MetadataMap& md) {
                auto* cc = md.Get<CorpusCoverageMetadata>();
                if (cc == nullptr) {
                    // existing seed had no cover (e.g. boot seed) → adopt candidate's,
                    // upgrading it into an ownership-tracked seed at the next sweep.
                    md.Set(*cand_cc);
                    return;
                }
                MergeSignalCoverWithPrio(cc->signal_cover_hashes, cc->signal_cover_prios,
                                         cand_cc->signal_cover_hashes,
                                         cand_cc->signal_cover_prios);
                UnionSortedInto(cc->cover_hashes, cand_cc->cover_hashes);
            });
    }
    // Note: ownership_ / scheduler per-seed cover are refreshed lazily — the next
    // EstablishInvariantFromStore sweep re-elects owners from the merged
    // signal_cover_hashes, so the merged edges keep this seed alive. Scheduler
    // rarity weight stays slightly stale until then (sampling-weight only, not size).
}

void CorpusManager::BootstrapFiltersFromStore()
{
    // 把 store 当前所有 seed 通知给所有 filter,让 stateful filter
    // (eg. ContentHashDedupFilter)同步 LoadAll / 历史持久化加载的 seed。
    // ForEachSeed 走 snapshot 模式,锁外迭代,filter::OnSeedAdded 自带 mutex。
    int64_t bytes = 0;
    store_.ForEachSeed([this, &bytes](const Seed& s) {
        bytes += static_cast<int64_t>(s.payload.size());
        for (auto& filter : filter_registry_) {
            if (filter) filter->OnSeedAdded(s);
        }
    });
    running_payload_bytes_ = bytes;
    payload_bytes_initialized_ = true;
    filters_bootstrapped_ = true;
}

void CorpusManager::SyncPayloadBytesFromStore()
{
    int64_t bytes = 0;
    store_.ForEachSeed([&bytes](const Seed& s) {
        bytes += static_cast<int64_t>(s.payload.size());
    });
    running_payload_bytes_ = bytes;
    payload_bytes_initialized_ = true;
}

void CorpusManager::PublishMetrics()
{
    if (!payload_bytes_initialized_) {
        SyncPayloadBytesFromStore();
    }
    if (metrics_ && metrics_->corpus_size) {
        metrics_->corpus_size->Set(static_cast<int64_t>(store_.Size()));
    }
    if (metrics_ && metrics_->corpus_bytes) {
        metrics_->corpus_bytes->Set(running_payload_bytes_);
    }
    // [coverage-ownership bound] corpus 覆盖的 distinct 稳定边数 = 语料大小的内生上界。
    if (metrics_ && metrics_->corpus_owned_edges) {
        metrics_->corpus_owned_edges->Set(static_cast<int64_t>(ownership_.OwnedEdges()));
    }
}

void CorpusManager::EstablishInvariantFromStore()
{
    if (!payload_bytes_initialized_) {
        SyncPayloadBytesFromStore();
    }

    // Pass 1: per-edge best owner over the whole store (signal_cover_hashes = EDGES,
    // = 准入单元). Seeds with no CorpusCoverageMetadata or empty edge cover are
    // coverage-unknown: kept, but not tracked by the ownership index (never an
    // owner, never evicted).
    std::unordered_map<std::uint64_t, SignalOwnershipIndex::OwnerRecord> best;
    store_.ForEachSeed([&best](const Seed& s) {
        const auto* cc = s.metadata.Get<CorpusCoverageMetadata>();
        if (cc == nullptr || cc->signal_cover_hashes.empty()) {
            return;
        }
        const auto& edges = cc->signal_cover_hashes;
        const auto& prios = cc->signal_cover_prios;
        const auto size = static_cast<std::uint32_t>(s.payload.size());
        for (std::size_t i = 0; i < edges.size(); ++i) {
            const std::uint8_t p =
                i < prios.size() ? prios[i] : static_cast<std::uint8_t>(0);
            auto it = best.find(edges[i]);
            if (it == best.end() ||
                SignalOwnershipIndex::BetterOwner(p, size, s.seed_id, it->second)) {
                best[edges[i]] = SignalOwnershipIndex::OwnerRecord{s.seed_id, p, size};
            }
        }
    });

    std::unordered_map<std::uint64_t, std::uint32_t> owned_count;
    for (const auto& [edge, owner] : best) {
        (void)edge;
        ++owned_count[owner.seed_id];
    }

    // Pass 2: a tracked seed owning NO edge is coverage-subsumed → evict (RemoveSeed
    // + scheduler InvalidateSeed). Coverage union is preserved: every edge's best
    // owner owns ≥1 edge, so best owners survive → all edges stay covered.
    std::vector<std::uint64_t> evict;
    std::vector<int64_t> evict_bytes;
    store_.ForEachSeed([&owned_count, &evict, &evict_bytes](const Seed& s) {
        const auto* cc = s.metadata.Get<CorpusCoverageMetadata>();
        if (cc == nullptr || cc->signal_cover_hashes.empty()) {
            return;
        }
        if (owned_count.find(s.seed_id) == owned_count.end()) {
            evict.push_back(s.seed_id);
            evict_bytes.push_back(static_cast<int64_t>(s.payload.size()));
        }
    });

    for (std::size_t i = 0; i < evict.size(); ++i) {
        if (store_.RemoveSeed(evict[i])) {
            running_payload_bytes_ -= evict_bytes[i];
            if (running_payload_bytes_ < 0) {
                running_payload_bytes_ = 0;
            }
            if (scheduler_handle_.HasValue()) {
                scheduler_handle_.Get().InvalidateSeed(evict[i]);
            }
            // [syz progsMap delete parity] un-blacklist the evicted program's content
            // hash so a future re-discovery is re-admitted (not permanently dropped).
            for (auto& filter : filter_registry_) {
                if (filter) {
                    filter->OnSeedRemoved(evict[i]);
                }
            }
        }
    }

    ownership_.Install(std::move(best));
}

bool CorpusManager::SweepIfGrowthExceeds(std::uint64_t growth_pct)
{
    // syz manager.go minimizeCorpusLocked parity: periodic caller decides the
    // 60s cadence; this method only mirrors `currSize > lastMinCorpus*(100+pct)/100`.
    if (!ownership_bootstrapped_) {
        EstablishInvariantFromStore();
        ownership_bootstrapped_ = true;
        last_swept_size_ = store_.Size();
    }
    const std::size_t sz = store_.Size();
    if (static_cast<std::uint64_t>(sz) * 100ULL <=
        static_cast<std::uint64_t>(last_swept_size_) * (100ULL + growth_pct)) {
        return false;
    }
    EstablishInvariantFromStore();
    last_swept_size_ = store_.Size();
    return true;
}

void CorpusManager::Tick()
{
    // [v2 SubT-D] 首次 Tick lazy bootstrap filter state — LoadAll 在 orchestrator
    // 早期跑,Tick 由 fuzzer_loop 触发,此时 store 已含所有 boot seed。
    if (!filters_bootstrapped_) {
        BootstrapFiltersFromStore();
    }
    // [coverage-ownership bound] 首次 Tick:对 boot/续跑加载进来的 corpus 跑一次批量
    // best-owner 选举,建立最小覆盖集并填充边-owner 快照。
    if (!ownership_bootstrapped_) {
        EstablishInvariantFromStore();
        ownership_bootstrapped_ = true;
        last_swept_size_ = store_.Size();
    }
    Seed candidate;
    const CorpusContext ctx{store_};
    for (int i = 0; i < max_drain_ && inbox_.TryPop(candidate); ++i) {
        TryAdmit(std::move(candidate), ctx);
    }
    PublishMetrics();
}

} // namespace refuzz::fuzzer
