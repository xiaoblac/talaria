// scheduler_manager_layering_test.cpp
//
// 覆盖 SchedulerManager 新职责边界(与 MutatorManager 同构):
//   - Manager 只做 engine 注册 + active 选择(handle-based)
//   - 不执行调度,不感知 policy 两阶段切换
//
// 这份测试是 mutator_manager_layering_test.cpp 的镜像,
// 目的是在 engine 接口差异下对齐同一套不变式。

#include "refuzz/scheduler/manager/scheduler_manager.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using refuzz::fuzzer::ISchedulerEngine;
using refuzz::fuzzer::SchedulerManager;
using refuzz::fuzzer::SeedDisposition;

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                        \
    if (!(cond)) {                                                             \
        std::fprintf(stderr,                                                   \
                     "    CHECK failed: %s [line %d]\n",                      \
                     #cond, __LINE__);                                        \
        return false;                                                          \
    }                                                                          \
} while (0)

#define RUN_TEST(fn) do {                                                       \
    ++tests_run;                                                               \
    std::fprintf(stdout, "  %-60s ", #fn);                                    \
    std::fflush(stdout);                                                       \
    if (fn()) {                                                                \
        ++tests_passed;                                                        \
        std::fprintf(stdout, "PASS\n");                                        \
    } else {                                                                   \
        std::fprintf(stdout, "FAIL\n");                                        \
    }                                                                          \
} while (0)

class FakeSchedulerEngine final : public ISchedulerEngine {
public:
    FakeSchedulerEngine(std::string name, uint64_t marker)
        : name_(std::move(name))
        , marker_(marker)
    {}

    std::string Name() const override { return name_; }

    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override {
        return refuzz::fuzzer::SeedSelection{marker_};
    }
    void OnFeedback(uint64_t, SeedDisposition) override {}
    void OnSeedAdded(uint64_t) override {}

    bool SwitchPolicyByName(std::string_view /*name*/) override { return false; }
    std::string ActivePolicyName() const override { return {}; }

    uint64_t Marker() const { return marker_; }

private:
    std::string name_;
    uint64_t marker_ = 0;
};

bool TestFirstRegisteredEngineBecomesActive()
{
    SchedulerManager manager;
    CHECK(!manager.HasActive());
    CHECK(!manager.Handle().HasValue());

    auto* first = new FakeSchedulerEngine("first", 0x11);
    const int idx = manager.AddEngine(std::unique_ptr<ISchedulerEngine>(first));
    CHECK(idx == 0);
    CHECK(manager.HasActive());
    CHECK(manager.ActiveEngineName() == "first");
    CHECK(&manager.Handle().Get() == first);
    return true;
}

bool TestAddDuplicateNameReturnsExistingIndex()
{
    SchedulerManager manager;
    auto* first = new FakeSchedulerEngine("dup", 0x22);
    const int idx_a = manager.AddEngine(std::unique_ptr<ISchedulerEngine>(first));

    auto dup = std::make_unique<FakeSchedulerEngine>("dup", 0x33);
    const int idx_b = manager.AddEngine(std::move(dup));

    CHECK(idx_a == idx_b);
    CHECK(manager.EngineNames().size() == 1);
    // active 仍然是首个注册的实例
    CHECK(&manager.Handle().Get() == first);
    return true;
}

bool TestSwitchEngineAppliesImmediately()
{
    // SwitchEngineByName 同步写 handle,无两阶段 pending。
    SchedulerManager manager;
    auto* a = new FakeSchedulerEngine("a", 0xaa);
    auto* b = new FakeSchedulerEngine("b", 0xbb);
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(a));
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(b));

    CHECK(manager.ActiveEngineName() == "a");
    CHECK(&manager.Handle().Get() == a);

    CHECK(manager.SwitchEngineByName("b"));
    CHECK(manager.ActiveEngineName() == "b");
    CHECK(&manager.Handle().Get() == b);
    return true;
}

bool TestSwitchToUnknownNameReturnsFalseAndKeepsActive()
{
    SchedulerManager manager;
    auto* a = new FakeSchedulerEngine("a", 0xaa);
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(a));

    CHECK(!manager.SwitchEngineByName("missing"));
    CHECK(&manager.Handle().Get() == a);
    return true;
}

bool TestSwitchToSameEngineIsNoop()
{
    SchedulerManager manager;
    auto* a = new FakeSchedulerEngine("a", 0xaa);
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(a));

    CHECK(manager.SwitchEngineByName("a"));
    CHECK(&manager.Handle().Get() == a);
    return true;
}

bool TestEngineNamesListsInRegistrationOrder()
{
    SchedulerManager manager;
    manager.AddEngine(std::make_unique<FakeSchedulerEngine>("alpha", 0x01));
    manager.AddEngine(std::make_unique<FakeSchedulerEngine>("beta", 0x02));
    manager.AddEngine(std::make_unique<FakeSchedulerEngine>("gamma", 0x03));

    const auto names = manager.EngineNames();
    CHECK(names.size() == 3);
    CHECK(names[0] == "alpha");
    CHECK(names[1] == "beta");
    CHECK(names[2] == "gamma");
    return true;
}

// Handle 全生命周期不变式:未注册 -> 无值;首次注册 -> 指向首个;切换 -> 指向目标。
bool TestHandleThroughLifecycle()
{
    SchedulerManager manager;
    CHECK(!manager.Handle().HasValue());

    auto* a = new FakeSchedulerEngine("a", 0x01);
    auto* b = new FakeSchedulerEngine("b", 0x02);
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(a));
    manager.AddEngine(std::unique_ptr<ISchedulerEngine>(b));

    CHECK(manager.Handle().HasValue());
    CHECK(&manager.Handle().Get() == a);

    CHECK(manager.SwitchEngineByName("b"));
    CHECK(&manager.Handle().Get() == b);

    // 切回 a 也是同步生效
    CHECK(manager.SwitchEngineByName("a"));
    CHECK(&manager.Handle().Get() == a);
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running scheduler_manager_layering_test...\n");

    RUN_TEST(TestFirstRegisteredEngineBecomesActive);
    RUN_TEST(TestAddDuplicateNameReturnsExistingIndex);
    RUN_TEST(TestSwitchEngineAppliesImmediately);
    RUN_TEST(TestSwitchToUnknownNameReturnsFalseAndKeepsActive);
    RUN_TEST(TestSwitchToSameEngineIsNoop);
    RUN_TEST(TestEngineNamesListsInRegistrationOrder);
    RUN_TEST(TestHandleThroughLifecycle);

    std::fprintf(stdout, "\nPassed %d/%d tests\n", tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}
