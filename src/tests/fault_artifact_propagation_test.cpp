// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 6 PR-6-A — §3.10 fault path artifact propagation ctest.
//
// Covers (plan §6.1 #3, 4 harness cases):
//   1. TestArtifactPropagatedFromSnapshot
//      Fault 事件 candidate_window 末尾 snapshot.artifact 已被
//      channeldispatcher::AttachArtifactToEvent 反查填好 →
//      BuildCombinedFromFault → crash_origin_artifact == 该 artifact (shared_ptr 一致)。
//   2. TestEmptyCandidateWindowStaysNull
//      candidate_window 空 → crash_origin_artifact 留 nullptr (legacy fail-close
//      parity;非 fault-injection-induced 的 fault 路径,如 heartbeat / serial-eof
//      不一定有 task 关联,这条路径不该意外提供 artifact)。
//   3. TestNoInflightMatchStaysNull
//      candidate_window 非空但 snapshot.artifact 为 nullptr (模拟
//      AttachArtifactToEvent 没在 inflight_artifacts_ 找到对应 entry) →
//      crash_origin_artifact 留 nullptr,downstream StageMinimize 该 fail-close
//      就 fail-close (不强加 artifact)。
//   4. TestArtifactComesFromBackSnapshotNotFront (P1 review fix)
//      多 inflight 场景:候选窗口 [T1, T2, T3] (T3 为最近 submit 的"guilty
//      task")时,channel.cpp::EmitFaultEvent 已经把它们按 submit_ts_us 顺序
//      push 到 candidate_window;AttachArtifactToEvent 用 back().executor_id
//      反查 inflight artifact → 选 T3 的 artifact 而非 T1。
//      验证 BuildCombinedFromFault 也用 back() 而非 front() 读 artifact。
//
// 测试在 FaultSignal::Sample 层面验证 BuildCombinedFromFault 的 D-7 propagation
// 行为。Executor::AttachArtifactToEvent 的 Fault 分支(channeldispatcher.cpp 编辑)
// 是 private 成员;它的 wiring 通过 operator-driven smoke + visual review 覆盖
// (PR-6-C orchestration 层会再加 e2e 测试)。
//
// P1 review fix 上下文:本测试 + 实现还含两条 channel-side 必要修正,
// 不直接由本测试 cover 但 visual-review-and-smoke gate:
// (1) channel.cpp::HandleFault / HandleWorkerFault 把 EmitFaultEvent 移到
//     AbortPendingByScope 之前 — 否则 kKernelCrash 在 abort 之后再 emit,
//     candidate_window 总为空,§3.10 fix 永远走 Test 2 那条 fail-safe 路径。
// (2) channeldispatcher.cpp::AttachArtifactToEvent 的 Fault 分支 find+COPY
//     而非 find+ERASE — 让翻转后的 [Fault, Abnormal×N] 序列里 Tn 对应的
//     Abnormal 仍能找到 artifact 走自己 Completion pipeline。

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/signal/fault_signal.hpp"
#include "refuzz/program/artifact.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <utility>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace cc = refuzz::core::channel_contract;

cc::ChannelEvent MakeKernelCrashFaultEvent(
    std::shared_ptr<const refuzz::program::ProgramArtifact> artifact,
    bool include_snapshot)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kFault;
    cc::Fault fault{};
    fault.kind = cc::FaultKind::kKernelCrash;
    fault.incident_id = 4242;
    if (include_snapshot) {
        cc::ChannelTaskSnapshot task{};
        task.executor_id = 9;
        task.seed_id = 12;
        task.artifact = std::move(artifact);
        fault.scene.candidate_window.push_back(std::move(task));
    }
    ev.payload = std::move(fault);
    return ev;
}

void TestArtifactPropagatedFromSnapshot()
{
    auto artifact = std::make_shared<refuzz::program::ProgramArtifact>();
    auto event = MakeKernelCrashFaultEvent(artifact, /*include_snapshot=*/true);

    refuzz::fuzzer::FaultSignal signal;
    auto contribution = signal.Sample(event);

    CHECK(contribution.fired);
    CHECK(contribution.crash_payload.has_value());
    // 同一 shared_ptr (或 control block 一致) — Sample 通过 BuildCombinedFromFault
    // 把 snapshot 里的 artifact 透到 crash_origin_artifact。
    CHECK(contribution.crash_payload->crash_origin_artifact.get() == artifact.get());
}

void TestEmptyCandidateWindowStaysNull()
{
    auto event = MakeKernelCrashFaultEvent(/*artifact=*/nullptr,
                                           /*include_snapshot=*/false);
    refuzz::fuzzer::FaultSignal signal;
    auto contribution = signal.Sample(event);

    CHECK(contribution.fired);
    CHECK(contribution.crash_payload.has_value());
    CHECK(contribution.crash_payload->crash_origin_artifact == nullptr);
}

void TestNoInflightMatchStaysNull()
{
    // include snapshot with NULL artifact — simulate
    // AttachArtifactToEvent finding no matching inflight entry.
    auto event = MakeKernelCrashFaultEvent(/*artifact=*/nullptr,
                                           /*include_snapshot=*/true);
    refuzz::fuzzer::FaultSignal signal;
    auto contribution = signal.Sample(event);

    CHECK(contribution.fired);
    CHECK(contribution.crash_payload.has_value());
    CHECK(contribution.crash_payload->crash_origin_artifact == nullptr);
}

void TestArtifactComesFromBackSnapshotNotFront()
{
    // Multi-inflight scenario:channel.cpp::EmitFaultEvent 按 submit_ts_us 排序
    // 把 candidate_window 填好;back() 是最近 submit 的"guilty task"。
    // AttachArtifactToEvent 用 back().executor_id 反查 inflight,把 artifact 写
    // back().artifact;BuildCombinedFromFault 也读 back().artifact。
    // 这里同时给 front 和 back 不同的 artifact,验证 only back() 流到 crash_origin。
    auto front_artifact = std::make_shared<refuzz::program::ProgramArtifact>();
    auto back_artifact  = std::make_shared<refuzz::program::ProgramArtifact>();
    CHECK(front_artifact.get() != back_artifact.get());

    refuzz::core::channel_contract::ChannelEvent ev;
    ev.kind = refuzz::core::channel_contract::ChannelEvent::Kind::kFault;
    refuzz::core::channel_contract::Fault fault{};
    fault.kind = refuzz::core::channel_contract::FaultKind::kKernelCrash;
    fault.incident_id = 7777;

    {
        refuzz::core::channel_contract::ChannelTaskSnapshot t1{};
        t1.executor_id = 100;
        t1.seed_id     = 1;
        t1.artifact    = front_artifact;
        fault.scene.candidate_window.push_back(std::move(t1));
    }
    {
        refuzz::core::channel_contract::ChannelTaskSnapshot t2{};
        t2.executor_id = 200;
        t2.seed_id     = 2;
        // 中间不带 artifact — 模拟 AttachArtifactToEvent 只填 back()
        fault.scene.candidate_window.push_back(std::move(t2));
    }
    {
        refuzz::core::channel_contract::ChannelTaskSnapshot t3{};
        t3.executor_id = 300;  // most recent submit_ts_us → back()
        t3.seed_id     = 3;
        t3.artifact    = back_artifact;
        fault.scene.candidate_window.push_back(std::move(t3));
    }
    ev.payload = std::move(fault);

    refuzz::fuzzer::FaultSignal signal;
    auto contribution = signal.Sample(ev);

    CHECK(contribution.fired);
    CHECK(contribution.crash_payload.has_value());
    // crash_origin_artifact 必须是 back_artifact,绝不能是 front_artifact
    CHECK(contribution.crash_payload->crash_origin_artifact.get() == back_artifact.get());
    CHECK(contribution.crash_payload->crash_origin_artifact.get() != front_artifact.get());
}

void TestHistoryEntryArtifactPropagated()
{
    // [async-crash-reproduction Phase 1] a NON-crash (history) candidate_window
    // entry's artifact must propagate to combined.history[i].artifact, so a
    // history/bisect/concat extract can be minimized downstream. Previously only
    // back()/crash_origin_artifact carried a typed view; history entries stayed
    // null → StageMinimize fail-closed.
    auto hist_artifact  = std::make_shared<refuzz::program::ProgramArtifact>();
    auto crash_artifact = std::make_shared<refuzz::program::ProgramArtifact>();
    CHECK(hist_artifact.get() != crash_artifact.get());

    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kFault;
    cc::Fault fault{};
    fault.kind = cc::FaultKind::kKernelCrash;
    fault.incident_id = 5555;
    {
        cc::ChannelTaskSnapshot h{};
        h.executor_id = 11;
        h.seed_id     = 1;
        h.artifact    = hist_artifact;   // history entry carries its typed view
        fault.scene.candidate_window.push_back(std::move(h));
    }
    {
        cc::ChannelTaskSnapshot c{};
        c.executor_id = 22;              // back() = crash program
        c.seed_id     = 2;
        c.artifact    = crash_artifact;
        fault.scene.candidate_window.push_back(std::move(c));
    }
    ev.payload = std::move(fault);

    refuzz::fuzzer::FaultSignal signal;
    auto contribution = signal.Sample(ev);

    CHECK(contribution.fired);
    CHECK(contribution.crash_payload.has_value());
    const auto& combined = *contribution.crash_payload;
    // back() → crash_origin_artifact
    CHECK(combined.crash_origin_artifact.get() == crash_artifact.get());
    // the single history entry carries ITS OWN typed view (Phase 1)
    CHECK(combined.history.size() == 1);
    CHECK(combined.history[0].artifact.get() == hist_artifact.get());
    CHECK(combined.history[0].artifact.get() != crash_artifact.get());
}

}  // namespace

int main()
{
    RUN_TEST(TestArtifactPropagatedFromSnapshot);
    RUN_TEST(TestEmptyCandidateWindowStaysNull);
    RUN_TEST(TestNoInflightMatchStaysNull);
    RUN_TEST(TestArtifactComesFromBackSnapshotNotFront);
    RUN_TEST(TestHistoryEntryArtifactPropagated);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
