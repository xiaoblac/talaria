// in_memory_corpus_concurrent_test.cpp
//
// [v2 admit-worker async] 验证 InMemoryCorpusStore 并发安全:
//   - ForEachSeed 走 snapshot 模式,visitor 内调 AddSeed 不死锁(无递归 mutex 也安全);
//   - 多线程并发 AddSeed + ForEachSeed 不崩、不丢 seed。

#include "refuzz/corpus/corpus_store.hpp"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

using refuzz::fuzzer::InMemoryCorpusStore;
using refuzz::fuzzer::Seed;

int tests_run = 0;
int tests_passed = 0;

#define EXPECT(cond)                                                           \
    do {                                                                       \
        ++tests_run;                                                           \
        if (cond) {                                                            \
            ++tests_passed;                                                    \
        } else {                                                               \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
        }                                                                      \
    } while (0)

Seed MakeSeed(uint64_t id, uint8_t b)
{
    Seed s;
    s.seed_id = id;
    s.payload = {b};
    return s;
}

void TestForEachSnapshotAllowsAddSeedFromVisitor()
{
    InMemoryCorpusStore store;
    for (uint64_t i = 1; i <= 8; ++i) {
        EXPECT(store.AddSeed(MakeSeed(i, static_cast<uint8_t>(i))));
    }

    // visitor 内调 AddSeed —— v1 (mutex 持锁 visit) 会死锁;
    // v2 snapshot 模式 visitor 在锁外执行,允许 reentrant。
    int visited = 0;
    bool reentrant_add_ok = false;
    store.ForEachSeed([&](const Seed&) {
        ++visited;
        if (visited == 1) {
            // 此时 visitor 在锁外 — AddSeed 持 unique_lock,不阻塞。
            reentrant_add_ok = store.AddSeed(MakeSeed(100, 0xff));
        }
    });
    // visit 数 = snapshot 起点 size = 8 (新加的 seed 不在 snapshot 内,这是预期)
    EXPECT(visited == 8);
    EXPECT(reentrant_add_ok);
    EXPECT(store.Size() == 9);
}

void TestConcurrentAddAndForEach()
{
    InMemoryCorpusStore store;
    constexpr int kN = 200;

    std::atomic<bool> stop{false};
    std::atomic<size_t> visit_runs{0};
    std::atomic<size_t> visit_seeds{0};

    std::thread reader([&] {
        while (!stop.load(std::memory_order_acquire)) {
            store.ForEachSeed([&](const Seed&) {
                visit_seeds.fetch_add(1, std::memory_order_relaxed);
            });
            visit_runs.fetch_add(1, std::memory_order_relaxed);
        }
    });

    for (uint64_t i = 1; i <= kN; ++i) {
        EXPECT(store.AddSeed(MakeSeed(i, static_cast<uint8_t>(i & 0xff))));
    }

    // [flaky fix] 高负载(并行 ctest)下 reader 线程可能在主线程加完 200 个种子并 stop 前
    // 一次都没被调度到 → visit_runs/visit_seeds 竞态为 0。种子已全部入库,reader 一旦跑
    // ForEachSeed 必然看到 ≥1 个种子;故加完后有界自旋等它至少完整遍历一次(看到种子)再
    // stop —— 快速收敛,把"reader 被调度过"从时序假设变成确定性前置,消除 race。
    for (int spin = 0;
         visit_seeds.load(std::memory_order_relaxed) == 0 && spin < 2'000'000;
         ++spin) {
        std::this_thread::yield();
    }

    stop.store(true, std::memory_order_release);
    reader.join();

    EXPECT(store.Size() == static_cast<size_t>(kN));
    // 至少跑过几轮 visit,且 visit 总条数 > 0。具体数值随调度,不强检。
    EXPECT(visit_runs.load() > 0);
    EXPECT(visit_seeds.load() > 0);
}

} // namespace

int main()
{
    TestForEachSnapshotAllowsAddSeedFromVisitor();
    TestConcurrentAddAndForEach();
    std::fprintf(stdout, "tests: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
