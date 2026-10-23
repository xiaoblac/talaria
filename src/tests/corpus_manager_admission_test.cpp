// corpus_manager_admission_test.cpp
//
// 覆盖 CorpusManager 的 admission policy 控制面 + Tick 驱动 inbox 的行为:
//   - 构造后默认注册 2 filter + 2 policy,默认 active = 最近一次 Register 的 idx
//     (NoFilterPolicy 索引为 1,因此注册完 active_idx=0 => AllFilters)。
//     —— 这里用公开接口推断:默认 Policy 由构造器按注册顺序形成,切换后再校验
//        ActivePolicyName 与行为一致,避免依赖未文档化的初始 active 约定。
//   - SwitchAdmissionPolicyByName + MaybeApplyPendingSwitch 生效
//   - Unknown name 返回 false,不改变 active
//   - Tick 时从 inbox 依序消费,按当前 policy 过滤;on_admit 回调被触发
//   - NoFilterPolicy 下 empty payload seed 也能进库
//   - AllFiltersPolicy 下 empty payload seed 被拒

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/corpus/corpus_manager.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/corpus/inbox.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cstdlib>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using refuzz::core::EngineHandle;
using refuzz::fuzzer::CorpusInbox;
using refuzz::fuzzer::CorpusManager;
using refuzz::fuzzer::InMemoryCorpusStore;
using refuzz::fuzzer::ISchedulerEngine;
using refuzz::fuzzer::Seed;
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

// 记录 OnSeedAdded 回调,用来校验 CorpusManager 正确触达 scheduler handle。
class RecordingSchedulerEngine final : public ISchedulerEngine {
public:
    std::string Name() const override { return "recording"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
    void OnFeedback(uint64_t, SeedDisposition) override {}
    void OnSeedAdded(uint64_t seed_id) override { added_.push_back(seed_id); }
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return {}; }

    const std::vector<uint64_t>& Added() const { return added_; }

private:
    std::vector<uint64_t> added_;
};

class ScopedEnvVar {
public:
    ScopedEnvVar(const char* key, const char* value)
        : key_(key)
    {
        if (const char* old = std::getenv(key); old != nullptr) {
            had_old_ = true;
            old_ = old;
        }
        setenv(key, value, /*overwrite=*/1);
    }

    ~ScopedEnvVar()
    {
        if (had_old_) {
            setenv(key_, old_.c_str(), /*overwrite=*/1);
        } else {
            unsetenv(key_);
        }
    }

    ScopedEnvVar(const ScopedEnvVar&) = delete;
    ScopedEnvVar& operator=(const ScopedEnvVar&) = delete;

private:
    const char* key_ = nullptr;
    bool had_old_ = false;
    std::string old_;
};

struct ManagerFixture {
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    std::unique_ptr<RecordingSchedulerEngine> sched =
        std::make_unique<RecordingSchedulerEngine>();
    EngineHandle<ISchedulerEngine> handle;
    std::unique_ptr<CorpusManager> manager;

    ManagerFixture()
    {
        handle.Store(sched.get());
        manager = std::make_unique<CorpusManager>(
            store, handle, inbox, /*max_drain=*/32);
    }
};

Seed MakeSeed(uint64_t id, std::vector<uint8_t> payload)
{
    Seed s;
    s.seed_id = id;
    s.payload = std::move(payload);
    return s;
}

// [coverage-ownership bound] seed 带稳定 EDGE 覆盖(signal_cover_hashes)+ per-edge
// prio,触发 TryAdmit 的覆盖所有权终闸。所有边 prio 默认 2(success-hit)。
Seed MakeEdgeSeed(uint64_t id,
                  std::vector<uint8_t> payload,
                  std::vector<uint64_t> edges)
{
    Seed s = MakeSeed(id, std::move(payload));
    refuzz::fuzzer::CorpusCoverageMetadata cc;
    cc.signal_cover_prios.assign(edges.size(), static_cast<std::uint8_t>(2));
    cc.signal_cover_hashes = std::move(edges);
    s.metadata.Set(std::move(cc));
    return s;
}

Seed MakeCoveredSeed(uint64_t id,
                     std::vector<uint8_t> payload,
                     std::vector<uint64_t> cover,
                     std::vector<uint64_t> signal,
                     std::vector<std::uint8_t> prios)
{
    Seed s = MakeSeed(id, std::move(payload));
    refuzz::fuzzer::CorpusCoverageMetadata cc;
    cc.cover_hashes = std::move(cover);
    cc.signal_cover_hashes = std::move(signal);
    cc.signal_cover_prios = std::move(prios);
    s.metadata.Set(std::move(cc));
    return s;
}

bool TestDefaultPoliciesAndFiltersRegistered()
{
    ManagerFixture fx;
    // ActivePolicyName 必然落在注册过的两个名字之一。
    const std::string name = fx.manager->ActivePolicyName();
    CHECK(name == "all_filters" || name == "no_filter");
    return true;
}

bool TestSwitchToUnknownPolicyReturnsFalse()
{
    ManagerFixture fx;
    const std::string before = fx.manager->ActivePolicyName();
    CHECK(!fx.manager->SwitchAdmissionPolicyByName("nope"));
    // 未调 MaybeApplyPendingSwitch,所以 active 必然不变
    CHECK(fx.manager->ActivePolicyName() == before);
    return true;
}

bool TestSwitchPolicyRequiresMaybeApply()
{
    ManagerFixture fx;
    CHECK(fx.manager->SwitchAdmissionPolicyByName("no_filter"));
    // 切换是两阶段:register pending,需要 MaybeApplyPendingSwitch 才生效
    // (MutatorManager 是同步切换 handle,Corpus 保留两阶段语义)。
    fx.manager->SwitchAdmissionPolicyByName("no_filter");
    const bool applied = fx.manager->MaybeApplyPendingSwitch();
    // 可能之前已经是 no_filter(构造顺序 all_filters idx=0, no_filter idx=1),
    // 所以 applied 与 active 之前是否 no_filter 相关;关键:切完之后 name == no_filter。
    (void)applied;
    CHECK(fx.manager->ActivePolicyName() == "no_filter");
    return true;
}

bool TestTickAdmitsSeedsWithNoFilterPolicy()
{
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("no_filter");
    (void)fx.manager->MaybeApplyPendingSwitch();

    // no_filter 下 manager 侧不过滤,但 store 仍拒非法 payload(空 payload)。
    // 用两个非空 seed 验证"filter 跳过 + store 接受"的路径。
    CHECK(fx.inbox.TryPush(MakeSeed(1, {0x01})));
    CHECK(fx.inbox.TryPush(MakeSeed(2, {0xAB, 0xCD})));

    fx.manager->Tick();

    CHECK(fx.store.Size() == 2);
    // [6b-3 — 当前版本] LoopStats 已删除, 计数改由 FuzzerMetrics 承载
    // (本用例不跨 metrics, 仅校验 store/scheduler 行为即可)

    // scheduler 收到对应 seed_id
    const auto& added = fx.sched->Added();
    CHECK(added.size() == 2);
    CHECK(added[0] == 1);
    CHECK(added[1] == 2);
    return true;
}

bool TestTickRejectsEmptyPayloadUnderAllFilters()
{
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    CHECK(fx.inbox.TryPush(MakeSeed(1, {})));           // NonEmptyPayloadFilter 拒
    CHECK(fx.inbox.TryPush(MakeSeed(2, {0x01})));       // 放行

    fx.manager->Tick();

    CHECK(fx.store.Size() == 1);

    const auto& added = fx.sched->Added();
    CHECK(added.size() == 1);
    CHECK(added[0] == 2);
    return true;
}

bool TestOnAdmitCallbackInvokedForAdmittedOnly()
{
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    std::vector<uint64_t> admitted;
    fx.manager->SetOnAdmit([&admitted](const Seed& s) { admitted.push_back(s.seed_id); });

    CHECK(fx.inbox.TryPush(MakeSeed(10, {})));            // 被拒,不回调
    CHECK(fx.inbox.TryPush(MakeSeed(11, {0xDE, 0xAD})));  // 放行,回调
    CHECK(fx.inbox.TryPush(MakeSeed(12, {0xBE, 0xEF})));  // 放行,回调

    fx.manager->Tick();

    CHECK(admitted.size() == 2);
    CHECK(admitted[0] == 11);
    CHECK(admitted[1] == 12);

    CHECK(fx.store.Size() == 2);
    return true;
}

bool TestTickRespectsMaxDrainBudget()
{
    // max_drain=2, 但 inbox 放 4 个,每次 Tick 只处理 2 个。
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);
    CorpusManager mgr{store, handle, inbox, /*max_drain=*/2};
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    CHECK(inbox.TryPush(MakeSeed(1, {0x1})));
    CHECK(inbox.TryPush(MakeSeed(2, {0x2})));
    CHECK(inbox.TryPush(MakeSeed(3, {0x3})));
    CHECK(inbox.TryPush(MakeSeed(4, {0x4})));

    mgr.Tick();
    CHECK(store.Size() == 2);

    mgr.Tick();
    CHECK(store.Size() == 4);
    return true;
}

bool TestSwitchPolicyBetweenTicksTakesEffectOnce()
{
    // 验证 admission policy 切换在 Tick 边界生效一次,用 content_hash_dedup 当判别:
    //   - all_filters 选 content_hash_dedup → 重复 payload 被拒;
    //   - no_filter 不选任何 filter → 同一重复 payload 被放行。
    // (这些 seed 无 CorpusCoverageMetadata,judged=false,覆盖所有权终闸豁免,不干扰。)
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);
    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8};

    mgr.SwitchAdmissionPolicyByName("all_filters");
    (void)mgr.MaybeApplyPendingSwitch();

    CHECK(inbox.TryPush(MakeSeed(1, {0x11})));
    mgr.Tick();
    CHECK(store.Size() == 1);                            // 首个放行(dedup 记下 hash)

    CHECK(inbox.TryPush(MakeSeed(2, {0x11})));           // 同 payload
    mgr.Tick();
    CHECK(store.Size() == 1);                            // all_filters 下被 dedup 拒

    // 切到 no_filter 后,不再走 content_hash_dedup,同 payload 应进库
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    CHECK(inbox.TryPush(MakeSeed(3, {0x11})));
    mgr.Tick();
    CHECK(store.Size() == 2);                            // no_filter 放行
    return true;
}

// ── SubT-D / G8 ContentHashDedupFilter 测试 ────────────────────────────────

bool TestContentHashDedupRejectsDuplicatePayload()
{
    // 同一 payload 第二次 admit 应被 ContentHashDedupFilter drop。
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    CHECK(fx.inbox.TryPush(MakeSeed(1, {0xAA, 0xBB, 0xCC})));
    CHECK(fx.inbox.TryPush(MakeSeed(2, {0xAA, 0xBB, 0xCC})));  // 同 payload
    CHECK(fx.inbox.TryPush(MakeSeed(3, {0xAA, 0xBB, 0xCD})));  // 1-byte 差异

    fx.manager->Tick();

    // seed_id=1 admit;seed_id=2 hash 重复被 drop;seed_id=3 不同 hash 放行
    CHECK(fx.store.Size() == 2);
    const auto& added = fx.sched->Added();
    CHECK(added.size() == 2);
    CHECK(added[0] == 1);
    CHECK(added[1] == 3);
    return true;
}

bool TestDuplicatePayloadMergesCoverAndNotifiesCoverMerge()
{
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    std::vector<uint64_t> admitted;
    std::vector<uint64_t> merged;
    fx.manager->SetOnAdmit([&admitted](const Seed& s) {
        admitted.push_back(s.seed_id);
    });
    fx.manager->SetOnCoverMerge([&merged](const Seed& s) {
        merged.push_back(s.seed_id);
    });

    CHECK(fx.inbox.TryPush(MakeCoveredSeed(
        10, {0xAA}, {100}, {1000}, {1})));
    fx.manager->Tick();

    CHECK(fx.store.Size() == 1);
    CHECK(admitted.size() == 1);
    CHECK(admitted[0] == 10);
    CHECK(merged.empty());

    CHECK(fx.inbox.TryPush(MakeCoveredSeed(
        11, {0xAA}, {200}, {1000, 2000}, {3, 2})));
    fx.manager->Tick();

    CHECK(fx.store.Size() == 1);
    CHECK(admitted.size() == 1);
    CHECK(merged.size() == 1);
    CHECK(merged[0] == 11);

    auto seed = fx.store.GetSeed(10);
    CHECK(seed != nullptr);
    const auto* cc =
        seed->metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>();
    CHECK(cc != nullptr);
    CHECK((cc->cover_hashes == std::vector<uint64_t>{100, 200}));
    CHECK(cc->signal_cover_hashes.size() == 2);
    CHECK(cc->signal_cover_prios.size() == 2);
    for (std::size_t i = 0; i < cc->signal_cover_hashes.size(); ++i) {
        if (cc->signal_cover_hashes[i] == 1000) {
            CHECK(cc->signal_cover_prios[i] == 3);
        }
        if (cc->signal_cover_hashes[i] == 2000) {
            CHECK(cc->signal_cover_prios[i] == 2);
        }
    }
    return true;
}

bool TestContentHashDedupAllowsUniquePayload()
{
    // 不同 payload 不被 dedup,全部 admit。
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    CHECK(fx.inbox.TryPush(MakeSeed(1, {0x01})));
    CHECK(fx.inbox.TryPush(MakeSeed(2, {0x02})));
    CHECK(fx.inbox.TryPush(MakeSeed(3, {0x01, 0x02})));
    CHECK(fx.inbox.TryPush(MakeSeed(4, {0x02, 0x01})));

    fx.manager->Tick();

    CHECK(fx.store.Size() == 4);
    return true;
}

bool TestContentHashDedupBootstrapFromStore()
{
    // 模拟 LoadAll 后的场景:store 已含 seed,filter state 应在第一次 Tick
    // lazy bootstrap 同步;之后 admit 重复 payload 被 drop。
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    // 直接写 store(模拟 CorpusDiskIO::LoadAll 路径,绕过 CorpusManager)。
    Seed pre_loaded;
    pre_loaded.seed_id = 100;
    pre_loaded.payload = {0xDE, 0xAD, 0xBE, 0xEF};
    CHECK(fx.store.AddSeed(pre_loaded));
    CHECK(fx.store.Size() == 1);

    // 推一个跟 pre-loaded 同 payload 的 seed,期望被 dedup drop。
    CHECK(fx.inbox.TryPush(MakeSeed(101, {0xDE, 0xAD, 0xBE, 0xEF})));
    // 推一个不同 payload,期望放行。
    CHECK(fx.inbox.TryPush(MakeSeed(102, {0xDE, 0xAD, 0xBE, 0xEE})));

    fx.manager->Tick();

    // pre_loaded(100)+ unique(102)= 2;dup(101)被 drop
    CHECK(fx.store.Size() == 2);
    return true;
}

bool TestContentHashDedupExplicitBootstrap()
{
    // 测试 BootstrapFiltersFromStore() public method 显式调用。
    ManagerFixture fx;
    fx.manager->SwitchAdmissionPolicyByName("all_filters");
    (void)fx.manager->MaybeApplyPendingSwitch();

    Seed pre;
    pre.seed_id = 200;
    pre.payload = {0xCA, 0xFE};
    CHECK(fx.store.AddSeed(pre));

    // 显式 bootstrap(本来 Tick 也会 lazy 调,这里测显式 path)。
    fx.manager->BootstrapFiltersFromStore();

    // 之后即便 inbox 推同 payload 也应被 drop。
    CHECK(fx.inbox.TryPush(MakeSeed(201, {0xCA, 0xFE})));
    fx.manager->Tick();

    CHECK(fx.store.Size() == 1);  // 仅 pre-loaded
    return true;
}

bool TestContentHashDedupEmptyPayloadIgnored()
{
    // 直接 unit test ContentHashDedupFilter:空 payload 不污染 hash set,
    // 不会让后续空 payload 误判 dup。正常 payload OnSeedAdded 后第二次 Test
    // 应 reject。
    refuzz::fuzzer::ContentHashDedupFilter filter;
    InMemoryCorpusStore store;
    const refuzz::fuzzer::CorpusContext ctx{store};

    Seed empty_a = MakeSeed(1, {});
    Seed empty_b = MakeSeed(2, {});
    Seed normal = MakeSeed(3, {0xAB, 0xCD});

    // [syz corpus.go merge parity] ContentHashDedupFilter::Test() 现**恒放行**,dedup 改由
    // DuplicateOf() 报既有 owner_id 让 CorpusManager MERGE(见 content_hash_dedup_filter.cpp:5)。
    // 本用例改用 DuplicateOf 校验原意「空 payload 被忽略、不污染 set;正常重复被识别」。
    // 空 payload:DuplicateOf 恒 nullopt(交 NonEmptyPayloadFilter),OnSeedAdded 不入表。
    CHECK(!filter.DuplicateOf(empty_a, ctx).has_value());
    filter.OnSeedAdded(empty_a);  // 空 payload 不应污染 set
    CHECK(!filter.DuplicateOf(empty_b, ctx).has_value());

    // 正常 payload:第一次非 dup;OnSeedAdded 后同 payload 被识别为既有 owner。
    CHECK(!filter.DuplicateOf(normal, ctx).has_value());
    filter.OnSeedAdded(normal);
    Seed normal_dup = MakeSeed(4, {0xAB, 0xCD});
    auto dup = filter.DuplicateOf(normal_dup, ctx);
    CHECK(dup.has_value());
    CHECK(dup.value() == 3);  // normal = MakeSeed(3, {0xAB,0xCD}) 的 owner seed_id
    return true;
}

bool TestAdmitAllAdmitsCoverageSubsumedCandidate()
{
    // [coverage-ownership bound] admit-all:稳定边全被现有更优 owner 占的候选**也照样
    // 入库**(不再拒收、admit 时也不驱逐)—— 准入由上游判定,覆盖所有权不门准入。
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);

    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);

    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8, &metrics};
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    // seed1(1 字节)覆盖边 {10};seed2(2 字节,更差)只覆盖 {10} → 一条都夺不到,但
    // admit-all 下**仍然入库**,等周期 sweep 再处理。
    CHECK(inbox.TryPush(MakeEdgeSeed(1, {0x01}, {10})));
    CHECK(inbox.TryPush(MakeEdgeSeed(2, {0x02, 0x03}, {10})));

    mgr.Tick();

    CHECK(store.Size() == 2);                          // 两个都进(无拒收)
    CHECK(metrics.corpus_growth->Value() == 2);
    return true;
}

bool TestSweepEvictsSubsumedSeed()
{
    // [coverage-ownership bound] 周期 sweep(EstablishInvariantFromStore,= syz
    // signal.Minimize 纯内存)抛弃 owns-0 的 subsumed seed,把池子收回最小覆盖集。
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);

    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);

    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8, &metrics};
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    // seed1(2 字节)覆盖 {10,20};seed2(1 字节,更优)也覆盖 {10,20}。admit-all 先都入库。
    CHECK(inbox.TryPush(MakeEdgeSeed(1, {0x01, 0x02}, {10, 20})));
    CHECK(inbox.TryPush(MakeEdgeSeed(2, {0x03}, {10, 20})));
    mgr.Tick();
    CHECK(store.Size() == 2);                           // admit-all:两个都在

    // 触发一次 sweep:seed2 更优 → 夺走 {10,20},seed1 owns 0 → 抛弃。
    mgr.EstablishInvariantFromStore();
    mgr.PublishMetrics();

    CHECK(store.Size() == 1);                           // 仅 seed2 存活
    CHECK(store.GetSeed(2) != nullptr);
    CHECK(store.GetSeed(1) == nullptr);                 // seed1 被抛弃
    CHECK(metrics.corpus_owned_edges->Value() == 2);    // 边 {10,20} 仍覆盖
    return true;
}

bool TestTickDoesNotRunPeriodicSweep()
{
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);

    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);

    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8, &metrics};
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    CHECK(inbox.TryPush(MakeEdgeSeed(1, {0x01}, {10})));
    CHECK(inbox.TryPush(MakeEdgeSeed(2, {0x02, 0x03}, {10})));

    mgr.Tick();

    CHECK(store.Size() == 2);
    CHECK(metrics.corpus_growth->Value() == 2);
    return true;
}

bool TestSweepIfGrowthExceedsUsesSyzThreePercentGate()
{
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);

    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);

    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8, &metrics};
    mgr.SwitchAdmissionPolicyByName("no_filter");
    (void)mgr.MaybeApplyPendingSwitch();

    CHECK(inbox.TryPush(MakeEdgeSeed(1, {0x01}, {10})));
    CHECK(inbox.TryPush(MakeEdgeSeed(2, {0x02}, {20})));
    mgr.Tick();
    CHECK(store.Size() == 2);

    // First periodic sweep mirrors syz lastMinCorpus=0: a non-empty corpus runs once.
    CHECK(mgr.SweepIfGrowthExceeds(3));
    CHECK(store.Size() == 2);

    // With last_swept_size_=2, no growth over 3% means no sweep.
    CHECK(!mgr.SweepIfGrowthExceeds(3));
    CHECK(store.Size() == 2);

    CHECK(inbox.TryPush(MakeEdgeSeed(3, {0x03, 0x04}, {10})));
    mgr.Tick();
    CHECK(store.Size() == 3);

    CHECK(mgr.SweepIfGrowthExceeds(3));
    CHECK(store.Size() == 2);
    CHECK(store.GetSeed(1) != nullptr);
    CHECK(store.GetSeed(2) != nullptr);
    CHECK(store.GetSeed(3) == nullptr);
    return true;
}

bool TestPublishMetricsSyncsBootLoadedPayloadBytes()
{
    InMemoryCorpusStore store;
    CorpusInbox inbox{128};
    RecordingSchedulerEngine sched;
    EngineHandle<ISchedulerEngine> handle;
    handle.Store(&sched);

    CHECK(store.AddSeed(MakeSeed(100, {0xAA, 0xBB, 0xCC})));

    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);

    CorpusManager mgr{store, handle, inbox, /*max_drain=*/8, &metrics};
    mgr.PublishMetrics();

    CHECK(metrics.corpus_size->Value() == 1);
    CHECK(metrics.corpus_bytes->Value() == 3);
    return true;
}

// [mab lineage Step A] OfferVerdict STAMPS the caller-decided lineage verbatim
// (origin + parent) — it must not infer the gen-vs-mut arm itself (that is
// control's job, like SeedSourceMetadata.source). divert=true returns the built
// Seed so we can inspect it directly.
bool TestOfferVerdictStampsLineage()
{
    ManagerFixture fx;  // default admit_mode = kInteresting
    refuzz::fuzzer::Verdict v;
    v.interesting = true;
    uint64_t next_id = 1;

    using refuzz::fuzzer::SeedLineageMetadata;
    using refuzz::fuzzer::SeedOrigin;
    using refuzz::fuzzer::SeedSource;
    using refuzz::fuzzer::SeedAdmissionState;
    using refuzz::fuzzer::SeedAdmissionStateMetadata;

    // caller passes generate origin → stored verbatim {kGenerate, 0}.
    auto gen = fx.manager->OfferVerdict({0x01}, nullptr, v, SeedSource::kMutation,
                                        /*divert_to_caller=*/true, next_id,
                                        SeedOrigin::kGenerate, /*parent_seed_id=*/0);
    CHECK(gen.built_seed.has_value());
    const auto* glin = gen.built_seed->metadata.Get<SeedLineageMetadata>();
    CHECK(glin != nullptr);
    CHECK(glin->origin == SeedOrigin::kGenerate);
    CHECK(glin->parent_seed_id == 0);
    const auto* gadmit = gen.built_seed->metadata.Get<SeedAdmissionStateMetadata>();
    CHECK(gadmit != nullptr);
    CHECK(gadmit->state == SeedAdmissionState::kActive);

    // caller passes mutate origin + parent → stored verbatim {kMutate, 42}.
    auto mut = fx.manager->OfferVerdict({0x02}, nullptr, v, SeedSource::kMutation,
                                        /*divert_to_caller=*/true, next_id,
                                        SeedOrigin::kMutate, /*parent_seed_id=*/42);
    CHECK(mut.built_seed.has_value());
    const auto* mlin = mut.built_seed->metadata.Get<SeedLineageMetadata>();
    CHECK(mlin != nullptr);
    CHECK(mlin->origin == SeedOrigin::kMutate);
    CHECK(mlin->parent_seed_id == 42);

    // omitted lineage (existing 6-arg call sites / tests) → neutral root default.
    auto def = fx.manager->OfferVerdict({0x03}, nullptr, v, SeedSource::kMutation,
                                        /*divert_to_caller=*/true, next_id);
    CHECK(def.built_seed.has_value());
    const auto* dlin = def.built_seed->metadata.Get<SeedLineageMetadata>();
    CHECK(dlin != nullptr);
    CHECK(dlin->origin == SeedOrigin::kBoot);
    CHECK(dlin->parent_seed_id == 0);
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running corpus_manager_admission_test...\n");

    RUN_TEST(TestDefaultPoliciesAndFiltersRegistered);
    RUN_TEST(TestSwitchToUnknownPolicyReturnsFalse);
    RUN_TEST(TestSwitchPolicyRequiresMaybeApply);
    RUN_TEST(TestTickAdmitsSeedsWithNoFilterPolicy);
    RUN_TEST(TestTickRejectsEmptyPayloadUnderAllFilters);
    RUN_TEST(TestOnAdmitCallbackInvokedForAdmittedOnly);
    RUN_TEST(TestTickRespectsMaxDrainBudget);
    RUN_TEST(TestSwitchPolicyBetweenTicksTakesEffectOnce);
    // SubT-D / G8 ContentHashDedupFilter
    RUN_TEST(TestContentHashDedupRejectsDuplicatePayload);
    RUN_TEST(TestDuplicatePayloadMergesCoverAndNotifiesCoverMerge);
    RUN_TEST(TestContentHashDedupAllowsUniquePayload);
    RUN_TEST(TestContentHashDedupBootstrapFromStore);
    RUN_TEST(TestContentHashDedupExplicitBootstrap);
    RUN_TEST(TestContentHashDedupEmptyPayloadIgnored);
    RUN_TEST(TestAdmitAllAdmitsCoverageSubsumedCandidate);
    RUN_TEST(TestSweepEvictsSubsumedSeed);
    RUN_TEST(TestTickDoesNotRunPeriodicSweep);
    RUN_TEST(TestSweepIfGrowthExceedsUsesSyzThreePercentGate);
    RUN_TEST(TestPublishMetricsSyncsBootLoadedPayloadBytes);
    // [mab lineage Step A]
    RUN_TEST(TestOfferVerdictStampsLineage);

    std::fprintf(stdout, "\nPassed %d/%d tests\n", tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}
