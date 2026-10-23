// stability_oracle.hpp —— SubT-A / framework primitive: signal stability oracle.
//
// 目的:抽出"N-run 重跑判 stable / flaky"的算法层,让不同 family 注入不同
// stability 语义:
//   - kernel:strict signal-set intersection(SignalSetIntersectionOracle)
//   - PyTorch (future):numerical tolerance
//   - 协议 (future):响应等价
//
// 设计:batch / stateless pure function。triage_stage 收集 N 次 raw signal
// hashes 后一次性 pass 给 oracle,oracle 决定 stable / flaky。
//
// Framework primitive injection pattern(批次 2 SubT-A 起点;SubT-B / SubT-E3 /
// 批次 3+ 后续 IXxx 沿用):
//   1. interface 在 feedback/include/refuzz/feedback/<name>.hpp
//   2. kernel impl 在 feedback/src/<name>/<impl>.cpp + 同 dir hpp
//   3. AssembledBundle 持 std::unique_ptr<IXxx>(unique 所有权);kernel profile
//      装配时构造并 move 进 bundle
//   4. StageDeps 持 IXxx*(raw ptr ref,assembled_bundle 长寿命保证)
//   5. stage Perform() 通过 deps.<name> 调用,nullptr 时降级或 fail-closed
//
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.A。

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace refuzz::fuzzer {

// IStabilityOracle —— 给定 N 个 run 的 raw signal hashes,判定 stable / flaky。
//
// 输入 runs[i]:第 i 个 run 收集到的 sorted + unique uint64 hash 集合。
//   - empty runs 视为 flaky(返 nullopt)
//   - 单 run(N=1)的 stable 判定由具体 impl 决定(SignalSetIntersectionOracle
//     视 single run 自身为 stable signal)
//
// min_votes —— 一个 hash 至少要出现在「多少个 run」里才算稳定信号(k-of-n 投票阈值)。
//   - 实现把它 clamp 到 [1, runs.size()];取值 <=0 或 >= runs.size() → 退化为严格交集
//     (所有 run 都得命中,即 SignalSetIntersectionOracle 的语义)。
//   - syzkaller 对应:corpus 候选 k=2(deflakeNeedCorpusRuns,2/6 容错),新 prog
//     k=needRuns=3(3/5,更严)。具体 k 由调用方从 IRetryPolicy.MinStableVotes(source)
//     取后传入 —— 本接口只收纯数值,不感知 SeedSource,保持模块边界干净。
//
// 输出:
//   - non-empty optional → stable;value 是 stable signal hashes(sorted + unique)
//   - nullopt → flaky;triage_stage / corpus_verify 据此 erase pending seed 不入 corpus
//
// Thread safety:**stateless / pure**;实现不应持 mutable state。
class IStabilityOracle {
public:
    virtual ~IStabilityOracle() = default;
    virtual std::optional<std::vector<std::uint64_t>> ExtractStable(
        const std::vector<std::vector<std::uint64_t>>& runs,
        int min_votes) const = 0;
};

}  // namespace refuzz::fuzzer
