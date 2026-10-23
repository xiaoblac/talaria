#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer {

// 共享调度状态（引用包装，仅在调用栈上存在）。
struct SchedulerContext {
    std::vector<uint64_t>& ready_queue;
    std::deque<uint64_t>& boosted;
    std::unordered_set<uint64_t>& cooled;
    size_t& cursor;

    // [value-weighted policies] 按需的 per-seed 权重输入 + rng。engine 每次构造
    // ctx 时填入这些指针;coverage-blind policy(priority / round_robin / uniform)
    // 忽略它们。任一为空时,加权 policy 应安全退化为 uniform(不崩)。
    //   - seed_cover : seed_id -> 该种子稳定 cover 的 PC 哈希列表
    //                  (size_weighted 用 .size();rarity_weighted 遍历它)
    //   - pc_count   : PC 哈希 -> 覆盖它的种子数(rarity_weighted 的 Σ 1/count)
    //   - rng        : 加权随机抽样源(engine 持有,确定性 seed,跨 run 可复现)
    const std::unordered_map<uint64_t, std::vector<uint64_t>>* seed_cover = nullptr;
    const std::unordered_map<uint64_t, std::uint32_t>*         pc_count   = nullptr;
    std::mt19937_64*                                           rng        = nullptr;

    // [mab-stage-selection] OUT-params: Next() 把本次抽样的 (pr, γ) 写回这里,engine 在
    // NextSeedId() 读出组成 SeedSelection。这样 policy 不留任何 per-seed 在途状态(无状态打分
    // 器),在途簿记归 control loop。非 MAB policy 不写 → 保持中性默认 (1, 0),其 OnSeedReward
    // 是 no-op 不消费。
    double sel_pr    = 1.0;
    double sel_gamma = 0.0;
};

} // namespace refuzz::fuzzer
