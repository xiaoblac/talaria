#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "refuzz/proto_domain/types.hpp"
// [v2 batch 3 G6] SeedAdmissionState — std::uint8_t 已经 cstdint;string 给 inactive_reason

namespace refuzz::fuzzer {

struct TriageStableSignalMetadata {
    // Program-level stable hashes retained for backwards compatibility
    // and for extra/program-level signal where no single call can be
    // identified.
    std::vector<std::uint64_t> hashes;
    // Upstream syzkaller minimizes relative to the triaged call index.
    // -1 means extra/program-level signal.
    int guilty_call_index = -1;
    // Stable hashes attributed to guilty_call_index. Minimize uses this
    // narrower target when present; otherwise it falls back to hashes.
    std::vector<std::uint64_t> guilty_call_hashes;
    // Stable execution classification observed during triage.
    std::optional<refuzz::proto::ResultCode> exec_status;
    // Execution shape observed during triage. A successful call must not
    // minimize into a failing call, and the syscall id must stay the same.
    std::optional<std::int32_t>  guilty_errno_value;
    std::optional<std::uint32_t> guilty_syscall_id;
    // true when guilty_call_hashes are in the edge-signal domain rather than
    // raw-PC coverage_hashes. Minimize must match against the same unit.
    bool guilty_call_hashes_are_edges = false;
};

struct DiscoveryNewSignalMetadata {
    // DiffRaw hashes captured on the original discovery exec: brand-new signal
    // plus higher-prio upgrades. Triage uses this as syzkaller's `newSignal`
    // reference; re-execs happen after the global novelty store has already
    // merged these hashes, so the diff cannot be recomputed later.
    std::vector<std::uint64_t> hashes;
};

struct TriagePerCallCandidateMetadata {
    struct Candidate {
        int call_index = -1;
        std::vector<std::uint64_t> stable_signal_hashes;
        std::vector<std::uint64_t> new_stable_signal_hashes;
        std::vector<std::uint8_t>  new_stable_signal_prios;
        std::vector<std::uint64_t> cover_hashes;
        std::vector<std::uint8_t>  signal_cover_prios;
        std::optional<std::int32_t>  errno_value;
        std::optional<std::uint32_t> syscall_id;
        bool signal_hashes_are_edges = false;
    };

    std::vector<Candidate> candidates;
    std::optional<refuzz::proto::ResultCode> exec_status;
};

// [Task A] Full stable coverage of an admitted corpus program — the
// reFuzz analog of syzkaller's per-corpus-entry cover (inp.Cover), which
// feeds syz_corpus_cover. Distinct from TriageStableSignalMetadata.hashes
// (the saturation-filtered / guilty-narrowed signal used for triage &
// minimize decisions). Populated by minimize (final minimized program's
// exec cover) with a triage full-stable-cover fallback, then merged into
// the corpus-only coverage store at corpus admission. Runtime-only:
// merged at on_admit, never persisted (no serde).
struct CorpusCoverageMetadata {
    std::vector<std::uint64_t> cover_hashes;
    // [PR2 edge-consistent minimization] the seed's stable cover in the ADMISSION
    // signal unit (= triage / corpus_verify cross-run intersection). In edges-off
    // (raw-PC) mode this is the stable PC set; in cover_edges mode it's the stable
    // EDGE set. MaybeMinimizeCorpus minimizes on THIS (not cover_hashes/PC) when in
    // edge-mode, so the minimize unit == the admit unit (no PC-vs-edge mismatch).
    // Runtime-only, like cover_hashes (no serde).
    std::vector<std::uint64_t> signal_cover_hashes;
    // Explicit domain tag for signal_cover_hashes. corpus_edge must never
    // consume raw-PC-domain hashes when cover_edges is disabled.
    bool signal_hashes_are_edges = false;
    // [PR3 per-element edge prio] parallel to signal_cover_hashes: per-edge priority
    // (syz signalPrio success bit — 2 if the edge was hit by a successful call,
    // else 0). Edge-mode MaybeMinimizeCorpus keeps, per edge, the highest-prio owner
    // (port of syz signal.Minimize), concentrating ownership in successful-coverage
    // programs and dropping failing-coverage ones. Empty → treat all prios as 0.
    std::vector<std::uint8_t> signal_cover_prios;
};

// [seed-value signal B] 跨执行覆盖方差 —— race-proximity 信号(宪法
// docs/plans/seed-value-signals.md §2.2)。triage / corpus_verify 的 deflake
// finalize 用 per-run cover 计算并 stamp(与 CorpusCoverageMetadata 同点,因为
// per-run 数据只在 finalize 活着,事后无法重算)。
//   unstable_ratio = unstable_pc_count / union_pc_count(union_pc_count>0 时)
// 高 = 这个 seed 的覆盖足迹对调度 / 时序敏感(并发 / RCU / softirq 邻近),值得
// 投 threaded / collision 变异去撞并发 bug。Runtime-only,不 serde(同
// CorpusCoverageMetadata):session-local,reload 的 seed 重新经 corpus_verify 取值。
struct SeedStabilityMetadata {
    std::uint32_t unstable_pc_count = 0;  // 出现在 some-but-not-all run 的 PC 数
    std::uint32_t union_pc_count    = 0;  // 至少一次出现的 PC 数(分母)
    std::uint8_t  observed_runs     = 0;  // 算这个比率用了几次 deflake run(粒度标注)
};

// [seed-value Phase 1 / structure-aware minimize] State-space altitude of the
// program BEFORE minimize flattened its resource graph. minimize nulls consumer
// res() refs (→ post-minimize depth/consumers ≈ 0), so the LIVE altitude of an
// admitted seed under-reports the structure the program originally had. Stamped
// at minimize on the ORIGINAL (pre-minimize) program; paired with the live
// (post-minimize) altitude it measures how much resource-chain structure
// minimize destroys — the input to deciding whether high-altitude seeds should
// skip / lighten minimization. Runtime-only, no serde (like the other
// seed-value metadata). docs/plans/seed-value-signals.md.
struct SeedPreMinAltitudeMetadata {
    std::uint32_t resource_producers   = 0;
    std::uint32_t resource_consumers   = 0;
    std::uint32_t distinct_kinds       = 0;
    std::uint32_t max_dependency_depth = 0;
};

struct SeedAuditMetadata {
    std::string target;
    std::string origin;
    std::string crash_title;
    std::vector<std::uint64_t> coverage_hashes;
    std::vector<std::string> pseudo_trace;
    std::vector<std::string> unsupported_features;
};

// [v2 SubT-C] framework primitive — Seed 来源跟踪。
//   * kBootCorpus    : corpus_disk_io::LoadAll 加载的 seed(boot 路径)
//   * kMutation      : mutational consumer 通过 dispatcher 产生的新 seed
//   * kReplayHistory : 来自 crash repro history(批次 3 G6 启用,本批次预留 enum)
//   * kFaultHistory  : 来自 fault injection history(同上)
// 本批次 SubT-C 落地:挂入 corpus_disk_io / corpus_admit dispatcher / minimize_stage。
// 不消费(批次 3 G6 corpus_verify_stage 用)。详
// docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.C。
enum class SeedSource : std::uint8_t {
    kBootCorpus    = 0,
    kMutation      = 1,
    kReplayHistory = 2,
    kFaultHistory  = 3,
};

struct SeedSourceMetadata {
    SeedSource    source  = SeedSource::kBootCorpus;
    std::uint32_t attempt = 0;  // 留批次 3 G6 candidate retry 用
};

// [mab lineage Step A] Corpus-seed lineage for the MAB lineage-return credit
// model (docs/plans/mab-stage-selection.md §3). Records which task-arm produced
// the seed and, for mutations, the parent corpus seed it derives from — so a
// decision can later be credited with the coverage realized by its whole
// lineage subtree, not just its own immediate execution.
//
// Contract: control decides the origin (it owns the gen/mut arm semantics, which
// mirror mab::MabArm) and passes it to corpus at admission; corpus only STORES
// this record — it never infers the arm from raw data. Same split as
// SeedSourceMetadata.source (caller-decided, corpus-stamped).
//
// Runtime-only (deliberately NOT serialized): seed ids are session-local and
// the bandit state is not persisted, so a reloaded seed is a fresh root.
// Absence of this record == {kBoot, parent 0} (root). Distinct from
// SeedSourceMetadata (which drives verify retry policy and IS persisted).
enum class SeedOrigin : std::uint8_t {
    kBoot     = 0,  // boot corpus / reloaded / non gen-mut origin (default = root)
    kGenerate = 1,  // produced by the generate arm (no parent)
    kMutate   = 2,  // produced by the mutate arm (parent_seed_id set)
};

struct SeedLineageMetadata {
    SeedOrigin    origin         = SeedOrigin::kBoot;
    std::uint64_t parent_seed_id = 0;  // parent corpus seed for kMutate; 0 otherwise
};

// [v2 batch 3 G6] framework primitive — Seed 入 corpus 后的 admission state。
//   * kActive   : 默认状态;scheduler 正常调度(missing-key fallback 也走这里)
//   * kInactive : verify 达 retry 上限被判 unstable / 其它 deactivate 原因;
//                 disk 物理保留,但 scheduler 跳过(corpus_disk_io::LoadFromFiles
//                 不调 OnSeedAdded;运行时通过 ISchedulerEngine::InvalidateSeed
//                 让 PrioritySchedulerEngine 从各 pool erase)。
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.G6 D1。
//
// **不**加 kFlaky:G6 决策树里 kFlaky 跟 kInactive 行为无差异(都不进 scheduler);
// 表达"为什么 inactive" 走 inactive_reason 字符串字段(YAGNI,future 多 reason 时
// 不需要扩 enum)。
enum class SeedAdmissionState : std::uint8_t {
    kActive   = 0,
    kInactive = 1,
};

struct SeedAdmissionStateMetadata {
    SeedAdmissionState state           = SeedAdmissionState::kActive;
    // free-form reason text(eg. "flaky_retry_exhausted")。default 空字符串。
    std::string        inactive_reason = {};
    // 累积 verify retry 尝试次数;corpus_verify_consumer 每次 retry 前 bump。
    // 达 IRetryPolicy.MaxAttempts → 转 kInactive。
    std::uint32_t      verify_attempts = 0;
};

} // namespace refuzz::fuzzer
