// PR-3-C — ChoiceTable rebuild + COW publish on corpus admission.
//
// The engine keeps the concrete ChoiceTable private; the public
// observable contract is Target::default_choice_table(), which receives
// the same shared_ptr control block through RebuildChoiceTable().
// These tests use a tiny synthetic Target so rebuilds are cheap and
// deterministic.

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/program/syz/target.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <memory>
#include <thread>
#include <vector>

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

namespace syz = ::refuzz::program::syz;

syz::Target make_target() {
    syz::Target target("test", "choice");
    target.set_page_size(4096);
    target.set_num_pages(16);

    for (std::uint64_t i = 0; i < 3; ++i) {
        auto* sc = target.add_syscall();
        const std::string name = "choice_probe_" + std::to_string(i);
        sc->set_name(name);
        sc->set_call_name(name);
        sc->set_nr(1000 + i);
    }

    target.finalize();
    return target;
}

void check_snapshot_ready(
    const std::shared_ptr<const syz::Target::IChoiceTable>& snap) {
    CHECK(snap != nullptr);
    CHECK(snap->enabled_count() == 3);
    CHECK(snap->enabled_call(0));
    CHECK(snap->enabled_call(1));
    CHECK(snap->enabled_call(2));
    const auto picked = snap->choose(
        std::numeric_limits<std::uint64_t>::max(),
        0xBADC0FFEE0DDF00DULL);
    CHECK(picked < 3);
}

// [v2 syzkaller-parity throttle 验证用 MockCorpusStore]
//   只暴露 Size() 这一条 ChoiceTable rebuild 节流真正读的接口;ForEachSeed 返回空,
//   ChoiceTable.build 时 dynamic prio 全零(static prio 不变),不影响 instance 替换检测。
class MockCorpusStore final : public ::refuzz::fuzzer::ICorpusStore {
public:
    explicit MockCorpusStore(std::size_t initial = 0) : size_(initial) {}

    bool AddSeed(::refuzz::fuzzer::Seed) override { ++size_; return true; }
    ::refuzz::fuzzer::SeedHandle GetSeed(std::uint64_t) const override {
        return nullptr;
    }
    void ForEachSeed(const ::refuzz::fuzzer::SeedVisitor&) const override {}
    std::optional<std::uint64_t> SampleSeedId(std::mt19937_64&) const override {
        return std::nullopt;
    }
    void MarkInteresting(std::uint64_t) override {}
    std::size_t Size() const override { return size_; }

    void SetSize(std::size_t s) { size_ = s; }

private:
    std::size_t size_ = 0;
};

void test_first_mutate_builds_table() {
    auto target = make_target();
    CHECK(target.default_choice_table() == nullptr);

    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000001ULL,
        /*ncalls_lo=*/2, /*ncalls_hi=*/2);

    ::refuzz::fuzzer::Seed seed;
    auto prog = engine.MutateProgForTesting(seed);
    CHECK(prog != nullptr);
    CHECK(prog->calls().size() == 2);

    auto snap = target.default_choice_table();
    check_snapshot_ready(snap);
}


void test_swap_publishes_new_table() {
    auto target = make_target();
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000002ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto before = target.default_choice_table();
    check_snapshot_ready(before);

    engine.OnSeedAdmitted(seed);
    auto after = target.default_choice_table();
    check_snapshot_ready(after);
    CHECK(before != after);
}

void test_old_snapshot_stays_alive() {
    auto target = make_target();
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000003ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto old_snap = target.default_choice_table();
    check_snapshot_ready(old_snap);

    for (int i = 0; i < 8; ++i) {
        engine.OnSeedAdmitted(seed);
    }
    auto new_snap = target.default_choice_table();
    check_snapshot_ready(new_snap);
    CHECK(old_snap != new_snap);

    // ASan/UBSan catches a stale-publish bug here; logically the old
    // snapshot must remain fully readable while the new one is live.
    check_snapshot_ready(old_snap);
}

void test_reads_are_lock_free() {
    auto target = make_target();
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000004ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    check_snapshot_ready(target.default_choice_table());

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> reads{0};
    std::atomic<std::uint64_t> bad_reads{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&]() {
            while (!stop.load(std::memory_order_acquire)) {
                auto snap = target.default_choice_table();
                if (snap == nullptr || snap->enabled_count() != 3 ||
                    snap->choose(std::numeric_limits<std::uint64_t>::max(),
                                 0x1234000000000000ULL + reads.load()) >= 3) {
                    bad_reads.fetch_add(1, std::memory_order_relaxed);
                }
                reads.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 128; ++i) {
        engine.OnSeedAdmitted(seed);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;

    stop.store(true, std::memory_order_release);
    for (auto& th : threads) th.join();

    CHECK(reads.load(std::memory_order_relaxed) > 0);
    CHECK(bad_reads.load(std::memory_order_relaxed) == 0);

    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::fprintf(stderr, "  rebuilds=128 reads=%llu elapsed_ms=%lld\n",
                 static_cast<unsigned long long>(
                     reads.load(std::memory_order_relaxed)),
                 static_cast<long long>(millis));
}

// [v2 syzkaller-parity throttle 节流测试]
// 验证 SyzV2MutatorEngine::OnSeedAdmitted 严格按 syzkaller pkg/fuzzer/fuzzer.go:406-426
// 的 33/333 阈值节流,而非每次 admit 都 rebuild。

void test_throttle_below_33_no_rebuild() {
    auto target = make_target();
    MockCorpusStore store(0);
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, &store, /*master_seed=*/0xC3000005ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    // Lazy first build at corpus_size = 0 → ct_built_at_corpus_size_ = 0。
    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto initial = target.default_choice_table();
    check_snapshot_ready(initial);

    // Simulate corpus growth 1..33 with admit notifications.
    // syzkaller 上游严格条件 prev + thresh < cur:0+33 < 33 → false,均不触发。
    for (std::size_t cur = 1; cur <= 33; ++cur) {
        store.SetSize(cur);
        engine.OnSeedAdmitted(seed);
        CHECK(target.default_choice_table() == initial);
    }

    // 第 34 个 admit:0 + 33 < 34 → true,触发首次 rebuild。
    store.SetSize(34);
    engine.OnSeedAdmitted(seed);
    auto after_first_rebuild = target.default_choice_table();
    check_snapshot_ready(after_first_rebuild);
    CHECK(after_first_rebuild != initial);
}

void test_throttle_above_100_uses_333() {
    auto target = make_target();
    // 启动时 corpus 已经有 100 个(模拟从 disk load),lazy build 后 ct_built_at = 100。
    MockCorpusStore store(100);
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, &store, /*master_seed=*/0xC3000006ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto initial = target.default_choice_table();
    check_snapshot_ready(initial);

    // Below 100+333=433 boundary — no rebuild。
    store.SetSize(432);
    engine.OnSeedAdmitted(seed);
    CHECK(target.default_choice_table() == initial);

    store.SetSize(433);  // 100+333 < 433 → false (equal),不触发。
    engine.OnSeedAdmitted(seed);
    CHECK(target.default_choice_table() == initial);

    store.SetSize(434);  // 100+333 < 434 → true,触发。
    engine.OnSeedAdmitted(seed);
    CHECK(target.default_choice_table() != initial);
}

// [machine-check C4.6] SetEnabledCalls swaps the mask + rebuilds: the
// republished ChoiceTable reflects the new enabled set, and choose() only ever
// returns an enabled syscall.
void test_set_enabled_calls_rebuilds() {
    auto target = make_target();
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000008ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto before = target.default_choice_table();
    check_snapshot_ready(before);          // all 3 enabled initially
    CHECK(before->enabled_count() == 3);

    // Restrict to syscall id 0 only (mask indexed by SyscallMeta::id()).
    engine.SetEnabledCalls(std::vector<std::uint8_t>{1, 0, 0});
    auto after = target.default_choice_table();
    CHECK(after != nullptr);
    CHECK(after != before);                // rebuilt + republished
    CHECK(after->enabled_count() == 1);
    CHECK(after->enabled_call(0));
    CHECK(!after->enabled_call(1));
    CHECK(!after->enabled_call(2));
    for (std::uint64_t s = 0; s < 16; ++s) {
        CHECK(after->choose(std::numeric_limits<std::uint64_t>::max(),
                            0xA5A5000000000000ULL + s) == 0);
    }
}

void test_throttle_null_corpus_falls_back() {
    // corpus_store_ == nullptr 时退化为 v1 行为:每次 OnSeedAdmitted 都 rebuild。
    // 现有 test_swap_publishes_new_table / test_old_snapshot_stays_alive
    // 已经覆盖该路径,但单独再加一条显式断言更稳。
    auto target = make_target();
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xC3000007ULL,
        /*ncalls_lo=*/1, /*ncalls_hi=*/1);

    ::refuzz::fuzzer::Seed seed;
    CHECK(engine.MutateProgForTesting(seed) != nullptr);
    auto a = target.default_choice_table();
    engine.OnSeedAdmitted(seed);
    auto b = target.default_choice_table();
    CHECK(a != b);  // null corpus_store 路径仍每次 rebuild
}

} // namespace

int main() {
    RUN_TEST(test_first_mutate_builds_table);
    RUN_TEST(test_swap_publishes_new_table);
    RUN_TEST(test_old_snapshot_stays_alive);
    RUN_TEST(test_reads_are_lock_free);
    // [v2 syzkaller-parity throttle]
    RUN_TEST(test_throttle_below_33_no_rebuild);
    RUN_TEST(test_throttle_above_100_uses_333);
    RUN_TEST(test_throttle_null_corpus_falls_back);
    // [machine-check C4.6]
    RUN_TEST(test_set_enabled_calls_rebuilds);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
