// priority_scheduler_invalidate_test.cpp
//
// [v2 batch 3 G6] PrioritySchedulerEngine::InvalidateSeed 单测:
//   1. InvalidateSeed 后该 seed_id 不再被 NextSeedId 选中
//   2. InvalidateSeed 不存在 id → no-op(不崩)
//   3. known_ erase 后,OnSeedAdded 同 id 又能 push 进 ready_queue(对称性)
//   4. 多个 seed,只 invalidate 一个,其它仍可调度
//   5. base ISchedulerEngine::InvalidateSeed default no-op(虚函数默认实现)

#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"
#include "refuzz/scheduler/scheduling_context.hpp"
#include "refuzz/scheduler/scheduling_policy.hpp"

#include <cassert>
#include <cstdio>
#include <memory>
#include <optional>
#include <unordered_set>

namespace {

using refuzz::fuzzer::ISchedulerEngine;
using refuzz::fuzzer::ISchedulingPolicy;
using refuzz::fuzzer::PrioritySchedulerEngine;
using refuzz::fuzzer::SchedulerContext;
using refuzz::fuzzer::SeedDisposition;

// 简单 round-robin policy:从 ready_queue_ 头部按 cursor 顺序拿。
// 等价 PrioritySchedulerEngine 默认 expected behavior(测试只关心 id 是否被排除)。
class StubRoundRobinPolicy final : public ISchedulingPolicy {
public:
    std::optional<std::uint64_t> Next(SchedulerContext& ctx) const override {
        if (ctx.ready_queue.empty()) return std::nullopt;
        if (ctx.cursor >= ctx.ready_queue.size()) ctx.cursor = 0;
        const auto id = ctx.ready_queue[ctx.cursor];
        ctx.cursor = (ctx.cursor + 1) % ctx.ready_queue.size();
        return id;
    }
    void OnFeedback(SchedulerContext&, std::uint64_t, SeedDisposition) const override {}
};

}  // namespace

int main()
{
    std::fprintf(stdout, "Running priority_scheduler_invalidate_test...\n");

    // ── Case 1: InvalidateSeed → NextSeedId 不返该 id ──────────────────────
    {
        PrioritySchedulerEngine eng;
        eng.RegisterPolicy("rr", std::make_unique<StubRoundRobinPolicy>());
        eng.OnSeedAdded(1);
        eng.OnSeedAdded(2);
        eng.OnSeedAdded(3);

        eng.InvalidateSeed(2);

        // 多次 NextSeedId,不应再返 id=2
        std::unordered_set<std::uint64_t> seen;
        for (int i = 0; i < 10; ++i) {
            auto id_opt = eng.NextSeedId();
            if (id_opt.has_value()) {
                assert(id_opt->seed_id != 2);
                seen.insert(id_opt->seed_id);
            }
        }
        assert(seen.count(1) > 0);
        assert(seen.count(3) > 0);
        assert(seen.count(2) == 0);
    }

    // ── Case 2: InvalidateSeed 不存在 id → no-op ───────────────────────────
    {
        PrioritySchedulerEngine eng;
        eng.RegisterPolicy("rr", std::make_unique<StubRoundRobinPolicy>());
        eng.OnSeedAdded(1);

        eng.InvalidateSeed(999);  // 不崩

        auto id_opt = eng.NextSeedId();
        assert(id_opt.has_value());
        assert(id_opt->seed_id == 1);
    }

    // ── Case 3: known_ erase 后,OnSeedAdded 同 id 又能 push ────────────────
    {
        PrioritySchedulerEngine eng;
        eng.RegisterPolicy("rr", std::make_unique<StubRoundRobinPolicy>());
        eng.OnSeedAdded(1);
        eng.InvalidateSeed(1);

        // 重新 OnSeedAdded(1) — 应该 push 进 ready 而不是被 known_ 去重
        eng.OnSeedAdded(1);
        auto id_opt = eng.NextSeedId();
        assert(id_opt.has_value());
        assert(id_opt->seed_id == 1);
    }

    // ── Case 4: 多 seed,只 invalidate 一个 ────────────────────────────────
    {
        PrioritySchedulerEngine eng;
        eng.RegisterPolicy("rr", std::make_unique<StubRoundRobinPolicy>());
        for (std::uint64_t id = 1; id <= 5; ++id) {
            eng.OnSeedAdded(id);
        }
        eng.InvalidateSeed(3);

        std::unordered_set<std::uint64_t> seen;
        for (int i = 0; i < 20; ++i) {
            auto id_opt = eng.NextSeedId();
            if (id_opt.has_value()) {
                assert(id_opt->seed_id != 3);
                seen.insert(id_opt->seed_id);
            }
        }
        assert(seen.size() == 4);  // 1, 2, 4, 5
        assert(seen.count(3) == 0);
    }

    // ── Case 5: base ISchedulerEngine::InvalidateSeed default no-op ────────
    // 通过 polymorphic call 验默认实现不崩。
    {
        // Stub scheduler 不 override InvalidateSeed → 默认 no-op。
        class StubScheduler final : public ISchedulerEngine {
        public:
            std::string Name() const override { return "stub"; }
            std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
            void OnFeedback(std::uint64_t, SeedDisposition) override {}
            void OnSeedAdded(std::uint64_t) override {}
            bool SwitchPolicyByName(std::string_view) override { return false; }
            std::string ActivePolicyName() const override { return "stub"; }
            // InvalidateSeed 不 override → 用基类 default no-op
        };

        StubScheduler s;
        s.InvalidateSeed(42);  // 不崩 → default no-op 工作
    }

    return 0;
}
