// mab_task_selector_test.cpp
//
// [mab-stage-selection — SyzVegas baseline] MabTaskSelector 单测:eligibility 过滤 + 完整
// produce→completion→reward 周期 + reward 归属到 bandit。详见 docs/plans/mab-stage-selection.md §4。
// 裸 assert harness(repo 约定,无 gtest)。

#include "refuzz/control/mab/mab_task_selector.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <random>

namespace {

using refuzz::control::mab::ArmEligibility;
using refuzz::control::mab::MabArm;
using refuzz::control::mab::MabTaskConfig;
using refuzz::control::mab::MabTaskSelector;

void TestEligibility()
{
    MabTaskSelector s{MabTaskConfig{.time_cap_s = 1.0}};
    std::mt19937_64 rng(1);

    // 仅 generate eligible → 永远 generate
    for (int i = 0; i < 500; ++i) {
        auto p = s.Select(ArmEligibility{.generate = true, .mutate = false, .triage = false}, rng);
        assert(p.has_value() && p->arm == MabArm::kGenerate);
        assert(p->pr > 0.0 && p->pr <= 1.0);
    }
    // 全不 eligible → nullopt
    auto none = s.Select(ArmEligibility{.generate = false, .mutate = false, .triage = false}, rng);
    assert(!none.has_value());

    // [审计后修正:2-arm] triage 不再是 MAB arm → 仅 triage eligible → nullopt(无 arm)。
    auto tri = s.Select(ArmEligibility{.generate = false, .mutate = false, .triage = true}, rng);
    assert(!tri.has_value());
    // 仅 mutate eligible → 永远 mutate
    for (int i = 0; i < 200; ++i) {
        auto p = s.Select(ArmEligibility{.generate = false, .mutate = true, .triage = false}, rng);
        assert(p.has_value() && p->arm == MabArm::kMutate);
    }
    std::fprintf(stdout, "  [ok] eligibility filtering (2-arm)\n");
}

void TestInflightTracking()
{
    MabTaskSelector s{MabTaskConfig{.time_cap_s = 1.0}};
    std::mt19937_64 rng(7);

    auto p = s.Select(ArmEligibility{.generate = true, .mutate = true, .triage = true}, rng);
    assert(p.has_value());
    s.RecordProduced(/*exec=*/100, *p);
    s.RecordProduced(/*exec=*/101, *p);
    s.RecordProduced(/*exec=*/102, *p);
    assert(s.InflightCount() == 3);

    // completion event → 消费 inflight + 结算 reward(每任务一次)→ 减一。
    s.OnEvent(/*exec=*/101, /*cov=*/3.0, /*t=*/1.0);
    assert(s.InflightCount() == 2);

    // 未跟踪的 exec_id → no-op(不崩、不动 inflight)
    s.OnEvent(/*exec=*/999, /*cov=*/3.0, /*t=*/1.0);
    assert(s.InflightCount() == 2);
    std::fprintf(stdout, "  [ok] inflight tracking + untracked-event no-op\n");
}

// completion-credit dominance:generate 每次 found 5 新边、mutate found 0(miss)→ generate
// 跑赢相对率、mutate 是 miss(g=−t·R<0)→ generate 的 Ĝ 主导、被选频率主导。
void TestCompletionCreditDominance()
{
    MabTaskSelector s{MabTaskConfig{.time_cap_s = 1.0}};
    std::mt19937_64 rng(2026);

    const ArmEligibility elig{.generate = true, .mutate = true, .triage = false};
    const int N = 6000;
    const int kTailStart = 4500;
    int gen_sel = 0, mut_sel = 0, gen_tail = 0, tail_total = 0;
    std::uint64_t exec = 1;

    for (int i = 0; i < N; ++i) {
        auto p = s.Select(elig, rng);
        assert(p.has_value());
        assert(p->arm != MabArm::kTriage);
        if (p->arm == MabArm::kGenerate) ++gen_sel; else ++mut_sel;

        const std::uint64_t id = exec++;
        s.RecordProduced(id, *p);
        // completion 结算:generate found 5、mutate found 0(miss → g=−t·R)。
        const double found = (p->arm == MabArm::kGenerate) ? 5.0 : 0.0;
        s.OnEvent(id, found, /*t=*/1.0);

        if (i >= kTailStart) { ++tail_total; if (p->arm == MabArm::kGenerate) ++gen_tail; }
    }

    assert(gen_tail * 2 > tail_total);  // 尾段 generate 占多数
    std::fprintf(stdout,
                 "  [ok] completion-credit dominance (gen/mut=%d/%d, tail gen %d/%d)\n",
                 gen_sel, mut_sel, gen_tail, tail_total);
}

// 一个总是 miss 的臂,其 Ĝ 被负 reward 拖到 < 0(share 自然消退)。这正是旧 anchored 非负增益
// 做不到、本设计恢复的 recession 机制(miss=−t·R → x<0 → Ĝ 回落)。
void TestMissErodesGhat()
{
    MabTaskSelector s{MabTaskConfig{.time_cap_s = 1.0}};
    std::mt19937_64 rng(11);
    std::uint64_t exec = 1;

    // 先用 generate 建立相对率 R + 非零 σ(found 交替 8/12 → R→10,σ≈2)。
    const ArmEligibility gen_only{.generate = true, .mutate = false, .triage = false};
    for (int i = 0; i < 300; ++i) {
        auto p = s.Select(gen_only, rng);
        assert(p.has_value());
        const std::uint64_t id = exec++;
        s.RecordProduced(id, *p);
        s.OnEvent(id, i % 2 == 0 ? 8.0 : 12.0, /*t=*/1.0);
    }
    // 强制 mutate-only 且连续 miss(少量,不触发 epoch 重置)→ Ĝ_mut 被负 reward 拖到 < 0。
    const ArmEligibility mut_only{.generate = false, .mutate = true, .triage = false};
    for (int i = 0; i < 4; ++i) {
        auto p = s.Select(mut_only, rng);
        assert(p.has_value() && p->arm == MabArm::kMutate);
        const std::uint64_t id = exec++;
        s.RecordProduced(id, *p);
        s.OnEvent(id, 0.0, /*t=*/1.0);  // miss → g = −t·R → x < 0
    }
    assert(s.Ghat(MabArm::kMutate) < 0.0);  // 回落到负(= recession;旧设计这里恒 ≥ 0)
    std::fprintf(stdout, "  [ok] miss erodes Ĝ (g_mut=%.3f < 0, SyzVegas recession)\n",
                 s.Ghat(MabArm::kMutate));
}

// 诊断:RecordAdmitDiagnostic 累计 per-arm admitted coverage,不触 bandit(Ĝ 不变)。
void TestAdmitDiagnosticOnly()
{
    MabTaskSelector s{MabTaskConfig{.time_cap_s = 1.0}};
    const double g_before = s.Ghat(MabArm::kGenerate);
    s.RecordAdmitDiagnostic(MabArm::kGenerate, 7.0);
    s.RecordAdmitDiagnostic(MabArm::kGenerate, 3.0);
    assert(s.AdmitEventCount(MabArm::kGenerate) == 2);
    assert(s.AdmitCovSum(MabArm::kGenerate) == 10.0);
    assert(s.Ghat(MabArm::kGenerate) == g_before);  // 诊断不触 bandit
    std::fprintf(stdout, "  [ok] RecordAdmitDiagnostic (counts only, no bandit update)\n");
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running mab_task_selector_test...\n");
    TestEligibility();
    TestInflightTracking();
    TestCompletionCreditDominance();
    TestMissErodesGhat();
    TestAdmitDiagnosticOnly();
    std::fprintf(stdout, "mab_task_selector_test: ALL PASS\n");
    return 0;
}
