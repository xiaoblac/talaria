// triage_deflake_test — Step 3 Slice A. The deflake analysis was extracted
// verbatim from triage_stage.cpp into refuzz::control::deflake so the legacy
// triage consumer AND the future core-path job share one implementation. Before
// the extraction these functions had NO direct unit test (only e2e coverage);
// this pins the behavior both callers rely on:
//   - SelectStableCall picks the call with the largest stable∩program signal
//   - k-of-n voting drops PCs seen in < k runs
//   - ComputeNewStableCallCandidates keeps only calls whose stable signal
//     intersects the discovery new-signal
//   - SelectStableExecStatus agrees only when all runs agree
//   - ComputeFullStableCover unions raw cover across runs (k=1)
// Pure functions — no executor / scheduler / StageDeps.

#include "refuzz/control/stage/triage_deflake.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>
#include <vector>

namespace deflake = refuzz::control::deflake;
using deflake::CallObservation;
using deflake::RunObservation;
using Hashes = std::vector<std::uint64_t>;

namespace {

int g_fail = 0;
#define CHECK(c, m)                                                             \
    do {                                                                        \
        if (!(c)) {                                                             \
            std::printf("FAIL: %s (%s:%d)\n", (m), __FILE__, __LINE__);         \
            ++g_fail;                                                           \
        }                                                                       \
    } while (0)

CallObservation Call(std::uint32_t syscall_id, std::int32_t errno_value, Hashes cov,
                      std::uint8_t priority = 0)
{
    CallObservation c;
    c.syscall_id      = syscall_id;
    c.errno_value     = errno_value;
    c.coverage_hashes = std::move(cov);
    c.signal_priority = priority;
    return c;
}

RunObservation Run(std::vector<CallObservation> calls,
                   refuzz::proto::ResultCode st = refuzz::proto::ResultCode::kOk)
{
    RunObservation r;
    r.per_call    = std::move(calls);
    r.exec_status = st;
    return r;
}

// [per-call novelty] a chased call = one syz job.calls[call] entry (call_index +
// per-call newSignal). Shape fields left default (candidate logic reads them from runs).
deflake::ChasedCall Chased(int call_index, Hashes new_signal)
{
    deflake::ChasedCall cc;
    cc.call_index        = call_index;
    cc.new_signal_hashes = std::move(new_signal);
    cc.new_signal_prios.assign(cc.new_signal_hashes.size(), 0);
    return cc;
}

deflake::ChasedCall ChasedWithPrio(int call_index, Hashes new_signal,
                                   std::uint8_t priority)
{
    auto cc = Chased(call_index, std::move(new_signal));
    cc.new_signal_prios.assign(cc.new_signal_hashes.size(), priority);
    return cc;
}

// Two identical runs: call0 syscall=100 cov {10,11}; call1 syscall=200 cov
// {20,21,22}. With k=2 voting every PC is stable (seen in both runs).
std::vector<RunObservation> TwoStableRuns()
{
    return {
        Run({Call(100, 0, {10, 11}), Call(200, 0, {20, 21, 22})}),
        Run({Call(100, 0, {10, 11}), Call(200, 0, {20, 21, 22})}),
    };
}

void TestSelectStableCallPicksLargest()
{
    const auto runs = TwoStableRuns();
    auto sel = deflake::SelectStableCall(runs, Hashes{10, 11, 20, 21, 22});
    CHECK(sel.has_value(), "SelectStableCall finds a guilty call");
    if (sel.has_value()) {
        CHECK(sel->call_index == 1, "guilty call is call1 (3 stable > 2)");
        CHECK(sel->syscall_id == 200u, "guilty syscall id carried");
        CHECK((sel->hashes == Hashes{20, 21, 22}), "guilty hashes = call1 stable");
        CHECK(!sel->hashes_are_edges, "raw-PC mode when no edges present");
    }
}

void TestSelectStableCallEmptyProgram()
{
    const auto runs = TwoStableRuns();
    CHECK(!deflake::SelectStableCall(runs, {}).has_value(),
          "empty program_stable → nullopt");
    CHECK(!deflake::SelectStableCall({}, Hashes{10}).has_value(),
          "empty runs → nullopt");
}

void TestSelectStableCallShapeInconsistentSkipped()
{
    // call0 syscall id differs across runs → shape-inconsistent → skipped; only
    // call1 (consistent) can be selected.
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {10, 11}), Call(200, 0, {20, 21, 22})}),
        Run({Call(999, 0, {10, 11}), Call(200, 0, {20, 21, 22})}),
    };
    auto sel = deflake::SelectStableCall(runs, Hashes{10, 11, 20, 21, 22});
    CHECK(sel.has_value(), "call1 still selectable");
    if (sel.has_value()) {
        CHECK(sel->call_index == 1, "shape-inconsistent call0 skipped");
    }
}

void TestNewStableCandidatesFilterByDiscovery()
{
    const auto runs = TwoStableRuns();
    const Hashes program_stable{10, 11, 20, 21, 22};

    // [per-call novelty] discovery attributed PC 11 to call0 and PC 22 to call1 (each
    //   call's own newSignal) → one candidate per call.
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{11}),
        Chased(1, Hashes{22}),
    };
    auto cands = deflake::ComputeNewStableCallCandidates(
        runs, program_stable, chased, /*min_votes=*/2);
    CHECK(cands.size() == 2, "two calls carry new-stable signal");
    if (cands.size() == 2) {
        CHECK(cands[0].call_index == 0, "candidate 0 = call0");
        CHECK((cands[0].stable_signal_hashes == Hashes{10, 11}), "call0 stable");
        CHECK((cands[0].new_stable_signal_hashes == Hashes{11}), "call0 new-stable");
        CHECK(cands[1].call_index == 1, "candidate 1 = call1");
        CHECK((cands[1].new_stable_signal_hashes == Hashes{22}), "call1 new-stable");
    }

    // per-call newSignal disjoint from that call's stable signal → no candidates.
    const std::vector<deflake::ChasedCall> chased_disjoint = {
        Chased(0, Hashes{999}),
        Chased(1, Hashes{999}),
    };
    CHECK(deflake::ComputeNewStableCallCandidates(
              runs, program_stable, chased_disjoint, 2)
              .empty(),
          "disjoint newSignal → no candidates");
    // no chased calls → no candidates.
    CHECK(deflake::ComputeNewStableCallCandidates(runs, program_stable, {}, 2).empty(),
          "no chased calls → no candidates");
}

void TestNewStableCandidatesVotingDrop()
{
    // call0: PC 31 only in run0 (vote 1 < k=2) → voting drops it; 30 kept.
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {30, 31})}),
        Run({Call(100, 0, {30})}),
    };
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{30, 31}),
    };
    auto cands = deflake::ComputeNewStableCallCandidates(
        runs, Hashes{30, 31}, chased, /*min_votes=*/2);
    CHECK(cands.size() == 1, "one call candidate");
    if (cands.size() == 1) {
        CHECK((cands[0].stable_signal_hashes == Hashes{30}),
              "k=2 voting drops single-run PC 31");
        CHECK((cands[0].new_stable_signal_hashes == Hashes{30}),
              "new-stable excludes voting-dropped PC");
    }
}

void TestPriorityAwareVoting()
{
    // A discovery hit with priority 2 must not become stable from lower-priority
    // re-executions. This is syzkaller signal.Intersection semantics.
    std::vector<RunObservation> low_reexec = {
        Run({Call(100, 0, {42}, 2)}),
        Run({Call(100, 0, {42}, 0)}),
        Run({Call(100, 0, {42}, 0)}),
    };
    const auto chased = std::vector<deflake::ChasedCall>{
        ChasedWithPrio(0, Hashes{42}, 2),
    };
    CHECK(deflake::ComputeNewStableCallCandidates(
              low_reexec, Hashes{42}, chased, 3)
              .empty(),
          "lower-priority replays do not satisfy stable priority");

    std::vector<RunObservation> high_reexec = {
        Run({Call(100, 0, {42}, 2)}),
        Run({Call(100, 0, {42}, 2)}),
        Run({Call(100, 0, {42}, 2)}),
    };
    auto candidates = deflake::ComputeNewStableCallCandidates(
        high_reexec, Hashes{42}, chased, 3);
    CHECK(candidates.size() == 1, "matching priorities produce a candidate");
    if (candidates.size() == 1) {
        CHECK(candidates[0].signal_cover_prios.size() == 1 &&
                  candidates[0].signal_cover_prios[0] == 2,
              "stable signal retains priority");
        CHECK(candidates[0].new_stable_signal_prios.size() == 1 &&
                  candidates[0].new_stable_signal_prios[0] == 2,
              "new stable signal retains required priority");
    }
}

void TestSelectStableExecStatus()
{
    using RC = refuzz::proto::ResultCode;
    std::vector<RunObservation> agree = {
        Run({Call(100, 0, {10})}, RC::kOk),
        Run({Call(100, 0, {10})}, RC::kOk),
    };
    auto s = deflake::SelectStableExecStatus(agree);
    CHECK(s.has_value() && *s == RC::kOk, "all-kOk → kOk");

    // 两个**有结果**的 run 状态真不一致 → 仍 nullopt(两 run 都有 per_call)。
    std::vector<RunObservation> disagree = {
        Run({Call(100, 0, {10})}, RC::kOk),
        Run({Call(100, 0, {10})}, RC::kCrashed),
    };
    CHECK(!deflake::SelectStableExecStatus(disagree).has_value(),
          "mixed exec status among result-bearing runs → nullopt");
    CHECK(!deflake::SelectStableExecStatus({}).has_value(),
          "empty runs → nullopt");

    // [List3] no-result run(per_call 空 = syz Info==nil)不参与共识、不否决:一批
    // kOk run 里混入一发零产出,仍应稳定在 kOk,而不是被判成"状态不一致"丢弃。
    std::vector<RunObservation> ok_with_noresult_outlier = {
        Run({Call(100, 0, {10})}, RC::kOk),
        Run({}, RC::kExecError),              // 空 per_call = no-result(kNoResult 形状)
        Run({Call(100, 0, {10})}, RC::kOk),
    };
    auto s2 = deflake::SelectStableExecStatus(ok_with_noresult_outlier);
    CHECK(s2.has_value() && *s2 == RC::kOk,
          "no-result outlier does not veto a stable kOk consensus");

    // 全是 no-result run → 没有可稳定的结果 → nullopt。
    std::vector<RunObservation> all_noresult = {
        Run({}, RC::kExecError),
        Run({}, RC::kExecError),
    };
    CHECK(!deflake::SelectStableExecStatus(all_noresult).has_value(),
          "all no-result runs → nullopt");
}

void TestComputeFullStableCover()
{
    // k=1 union across runs (syz inp.Cover): call0 {40}∪{41}={40,41}; call1
    // {50}∪{50}={50}; Extra {60}∪{61}={60,61}; program union =
    // {40,41,50,60,61}.
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {40}), Call(200, 0, {50})}),
        Run({Call(100, 0, {41}), Call(200, 0, {50})}),
    };
    runs[0].extra_cover = {60};
    runs[1].extra_cover = {61};
    auto cover = deflake::ComputeFullStableCover(runs);
    CHECK((cover == Hashes{40, 41, 50, 60, 61}),
          "full stable cover = k=1 union across runs plus Extra");
}

void TestDiscoverySignalOnlyNotCover()
{
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {40})}),
        Run({Call(100, 0, {41})}),
    };
    runs[0].extra_cover = {60};
    runs[0].contributes_cover = false;
    runs[1].extra_cover = {61};
    auto cover = deflake::ComputeFullStableCover(runs);
    CHECK((cover == Hashes{41, 61}),
          "discovery contributes signal votes but not corpus cover");
}

void TestDiscoveryDoesNotInflateCoverVariance()
{
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {10})}),
        Run({Call(100, 0, {20})}),
        Run({Call(100, 0, {20})}),
    };
    runs[0].contributes_cover = false;
    const auto stats = deflake::ComputeUnstableStats(runs);
    CHECK(stats.union_pc_count == 1,
          "discovery-only cover is excluded from variance union");
    CHECK(stats.unstable_pc_count == 0,
          "discovery sample is not an artificial empty cover vote");
}

void TestExtraOnlyEdgeSignalUsesEdgeDomain()
{
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {10})}),
        Run({Call(100, 0, {10})}),
    };
    for (auto& run : runs) {
        run.extra_signal_hashes = {70};
        run.extra_signal_hashes_are_edges = true;
    }
    auto extra = Chased(-1, Hashes{70});
    extra.signal_hashes_are_edges = true;
    auto candidates = deflake::ComputeNewStableCallCandidates(
        runs, Hashes{70}, {extra}, /*min_votes=*/2);
    CHECK(candidates.size() == 1 && candidates[0].call_index == -1,
          "Extra-only edge signal keeps the edge voting domain");
}

void TestLateDiscoveredCallVotesFromFirstObservation()
{
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {10})}),
        Run({Call(100, 0, {10}), Call(200, 0, {77})}),
        Run({Call(100, 0, {10}), Call(200, 0, {77})}),
    };
    auto late = Chased(1, Hashes{77});
    late.first_run_index = 1;
    late.syscall_id = 200;
    auto candidates = deflake::ComputeNewStableCallCandidates(
        runs, Hashes{77}, {late}, /*min_votes=*/2);
    CHECK(candidates.size() == 1 && candidates[0].call_index == 1,
          "call discovered during deflake ignores older run shape");
}

void TestShouldStopFuzzDeflakeUsesChasedCalls()
{
    // call1 has a stable program-level PC from the start, but the chased new
    // signal is call0:99. syz stopDeflake must continue because call0:99 is not
    // yet stable and still has a chance to become stable within max_runs.
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {99}), Call(200, 0, {10})}),
        Run({Call(100, 0, {}),   Call(200, 0, {10})}),
        Run({Call(100, 0, {}),   Call(200, 0, {10})}),
    };
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{99}),
    };
    CHECK(!deflake::ShouldStopFuzzDeflake(runs, chased,
                                          /*min_votes=*/3, /*max_runs=*/5),
          "program-level stable signal alone must not stop fuzz deflake");

    runs.push_back(Run({Call(100, 0, {99}), Call(200, 0, {10})}));
    runs.push_back(Run({Call(100, 0, {99}), Call(200, 0, {10})}));
    CHECK(deflake::ShouldStopFuzzDeflake(runs, chased,
                                         /*min_votes=*/3, /*max_runs=*/5),
          "stop once chased newSignal reaches the stable vote threshold");
}

void TestShouldStopFuzzDeflakeNoChance()
{
    // With min_votes=3/max_runs=5, a signal seen zero times after four runs can
    // no longer reach 3 votes in the single remaining run.
    std::vector<RunObservation> runs = {
        Run({Call(100, 0, {})}),
        Run({Call(100, 0, {})}),
        Run({Call(100, 0, {})}),
        Run({Call(100, 0, {})}),
    };
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{99}),
    };
    CHECK(deflake::ShouldStopFuzzDeflake(runs, chased,
                                         /*min_votes=*/3, /*max_runs=*/5),
          "stop when chased signal has no remaining chance to become stable");
}

void TestShouldStopCorpusDeflakeWindow()
{
    std::vector<RunObservation> stable_runs = {
        Run({Call(100, 0, {10})}), Run({Call(100, 0, {10})}),
        Run({Call(100, 0, {10})}), Run({Call(100, 0, {10})}),
    };
    const auto chased = std::vector<deflake::ChasedCall>{Chased(0, Hashes{10})};
    CHECK(deflake::ShouldStopCorpusDeflake(
              stable_runs, chased, 2, 4, 6, 20, true),
          "boot stable corpus stops at four total samples");

    std::vector<RunObservation> flaky_runs(6, Run({Call(100, 0, {})}));
    CHECK(deflake::ShouldStopCorpusDeflake(
              flaky_runs, chased, 2, 4, 6, 20, true),
          "boot no-signal corpus stops at six total samples");

    std::vector<RunObservation> growing_runs(20, Run({Call(100, 0, {})}));
    CHECK(deflake::ShouldStopCorpusDeflake(
              growing_runs, chased, 2, 4, 6, 20, false),
          "boot continuously growing corpus stops at hard limit twenty");
}

// ── DecideAndStampStableSeed (Slice C2) ──────────────────────────────────────

void TestDecideNoChasedCallsDrops()
{
    const auto runs = TwoStableRuns();
    const Hashes intersection{10, 11, 20, 21, 22};
    refuzz::fuzzer::Seed seed;
    auto decision = deflake::DecideAndStampStableSeed(
        seed, runs, intersection, refuzz::proto::ResultCode::kOk,
        /*min_votes=*/2, /*seed_value_shadow=*/false, /*chased_calls=*/{});
    CHECK(!decision.admit, "empty chased calls do not admit");
    CHECK(decision.admitted_units == 0, "empty chased calls admit 0 units");
    CHECK(decision.drop_reason == deflake::StableSeedDropReason::kNoChasedCalls,
          "empty chased calls return no-chased drop reason");
    CHECK(decision.per_call_candidates.empty(), "empty chased calls has no candidate list");
    CHECK(seed.metadata.Get<refuzz::fuzzer::TriageStableSignalMetadata>() == nullptr,
          "no whole-program stable metadata stamped");
    CHECK(seed.metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>() == nullptr,
          "no corpus coverage metadata stamped");
}

void TestDecidePerCallPathStamps()
{
    const auto runs = TwoStableRuns();
    refuzz::fuzzer::Seed seed;
    // [per-call novelty] per-call newSignal: call0 owns PC 11, call1 owns PC 22.
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{11}),
        Chased(1, Hashes{22}),
    };
    auto decision = deflake::DecideAndStampStableSeed(
        seed, runs, Hashes{10, 11, 20, 21, 22}, refuzz::proto::ResultCode::kOk,
        /*min_votes=*/2, /*seed_value_shadow=*/false, chased);
    CHECK(decision.admit, "per-call path admits");
    CHECK(decision.admitted_units == 2, "two per-call candidates");
    CHECK(decision.per_call_candidates.size() == 2, "returns the candidate list for the job");

    const auto* pcm = seed.metadata.Get<refuzz::fuzzer::TriagePerCallCandidateMetadata>();
    CHECK(pcm != nullptr, "TriagePerCallCandidateMetadata stamped");
    if (pcm != nullptr) {
        CHECK(pcm->candidates.size() == 2, "2 candidates on the seed");
    }
    CHECK(seed.metadata.Get<refuzz::fuzzer::TriageStableSignalMetadata>() == nullptr,
          "single-path meta NOT stamped in per-call mode");
}

void TestDecidePerCallEmptyDrops()
{
    const auto runs = TwoStableRuns();
    refuzz::fuzzer::Seed seed;
    // [per-call novelty] per-call newSignal disjoint from each call's stable signal.
    const std::vector<deflake::ChasedCall> chased = {
        Chased(0, Hashes{999}),
        Chased(1, Hashes{999}),
    };
    auto decision = deflake::DecideAndStampStableSeed(
        seed, runs, Hashes{10, 11, 20, 21, 22}, refuzz::proto::ResultCode::kOk,
        2, false, chased);
    CHECK(!decision.admit, "no admittable candidate → no admit");
    CHECK(decision.drop_reason == deflake::StableSeedDropReason::kNoPerCallCandidate,
          "flagged per-call-empty for drop accounting");
    CHECK(decision.per_call_candidates.empty(), "no candidates returned");
}

void TestDecideSeedValueShadowStamps()
{
    // 3 runs where PC 22 flickers (2 of 3) → non-zero cross-run variance.
    std::vector<RunObservation> runs = {
        Run({Call(200, 0, {20, 21, 22})}),
        Run({Call(200, 0, {20, 21, 22})}),
        Run({Call(200, 0, {20, 21})}),
    };
    refuzz::fuzzer::Seed seed;
    auto decision = deflake::DecideAndStampStableSeed(
        seed, runs, Hashes{20, 21}, refuzz::proto::ResultCode::kOk,
        2, /*seed_value_shadow=*/true, /*chased_calls=*/{});
    CHECK(!decision.admit, "stable without chased calls drops");
    CHECK(decision.drop_reason == deflake::StableSeedDropReason::kNoChasedCalls,
          "shadow path also reports no-chased drop reason");
    const auto* sb = seed.metadata.Get<refuzz::fuzzer::SeedStabilityMetadata>();
    CHECK(sb == nullptr, "SeedStabilityMetadata is not stamped for dropped seeds");
}

}  // namespace

int main()
{
    TestSelectStableCallPicksLargest();
    TestSelectStableCallEmptyProgram();
    TestSelectStableCallShapeInconsistentSkipped();
    TestNewStableCandidatesFilterByDiscovery();
    TestNewStableCandidatesVotingDrop();
    TestPriorityAwareVoting();
    TestSelectStableExecStatus();
    TestComputeFullStableCover();
    TestDiscoverySignalOnlyNotCover();
    TestDiscoveryDoesNotInflateCoverVariance();
    TestExtraOnlyEdgeSignalUsesEdgeDomain();
    TestLateDiscoveredCallVotesFromFirstObservation();
    TestShouldStopFuzzDeflakeUsesChasedCalls();
    TestShouldStopFuzzDeflakeNoChance();
    TestShouldStopCorpusDeflakeWindow();
    TestDecideNoChasedCallsDrops();
    TestDecidePerCallPathStamps();
    TestDecidePerCallEmptyDrops();
    TestDecideSeedValueShadowStamps();

    if (g_fail == 0) {
        std::printf("triage_deflake_test: all checks passed\n");
        return 0;
    }
    std::printf("triage_deflake_test: %d check(s) FAILED\n", g_fail);
    return 1;
}
