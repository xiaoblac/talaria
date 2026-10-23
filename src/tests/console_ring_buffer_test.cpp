// §3.11-B — ConsoleRingBuffer unit test.
//
// Verifies the data primitive used to bridge ConsoleSensor (writer) and
// HeartbeatSensor (reader) for Bug #2 (heartbeat 检测时主动抓 console
// 上下文）。覆盖：Push / Snapshot / SnapshotJoined / Size / Clear /
// 容量上限丢最老语义 / 多线程并发 push+snapshot 不撕裂。

#include "refuzz/channel/evidence/console_ring_buffer.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

namespace {

#define CHECK(expr)                                                          \
    do {                                                                    \
        if (!(expr)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #expr);                                             \
            std::abort();                                                    \
        }                                                                    \
    } while (0)

#define RUN_TEST(fn)                                                         \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                              \
        fn();                                                                \
        std::fprintf(stderr, "OK   %s\n", #fn);                              \
    } while (0)

namespace ev = refuzz::channel::evidence;

void TestPushSnapshotBasic() {
    ev::ConsoleRingBuffer rb(/*max_lines=*/10);
    CHECK(rb.Size() == 0);
    CHECK(rb.Snapshot(5).empty());

    rb.Push("[001] init");
    rb.Push("[002] BUG: KASAN");
    rb.Push("[003] Call Trace:");
    CHECK(rb.Size() == 3);

    auto snap = rb.Snapshot(2);
    CHECK(snap.size() == 2);
    CHECK(snap[0] == "[002] BUG: KASAN");      // 取最近 2 行
    CHECK(snap[1] == "[003] Call Trace:");

    auto all = rb.Snapshot(100);                // n > 实际数量 → 全返
    CHECK(all.size() == 3);
    CHECK(all[0] == "[001] init");
    CHECK(all[2] == "[003] Call Trace:");
}

void TestSnapshotJoined() {
    ev::ConsoleRingBuffer rb;
    rb.Push("a");
    rb.Push("b");
    rb.Push("c");
    auto joined = rb.SnapshotJoined(3);
    CHECK(joined == "a\nb\nc\n");

    auto last2 = rb.SnapshotJoined(2);
    CHECK(last2 == "b\nc\n");

    CHECK(rb.SnapshotJoined(0).empty());
}

void TestCapacityDropsOldest() {
    ev::ConsoleRingBuffer rb(/*max_lines=*/3);
    rb.Push("L1");
    rb.Push("L2");
    rb.Push("L3");
    rb.Push("L4");                              // ← L1 被丢
    rb.Push("L5");                              // ← L2 被丢
    CHECK(rb.Size() == 3);

    auto snap = rb.Snapshot(10);
    CHECK(snap.size() == 3);
    CHECK(snap[0] == "L3");
    CHECK(snap[1] == "L4");
    CHECK(snap[2] == "L5");
}

void TestZeroAndOneCap() {
    // max_lines=0 应被规范化为 1（避免无效）
    ev::ConsoleRingBuffer rb_zero(0);
    rb_zero.Push("only");
    rb_zero.Push("last");                       // 之前的被丢
    auto snap = rb_zero.Snapshot(5);
    CHECK(snap.size() == 1);
    CHECK(snap[0] == "last");

    ev::ConsoleRingBuffer rb_one(1);
    rb_one.Push("a");
    rb_one.Push("b");
    CHECK(rb_one.Size() == 1);
    CHECK(rb_one.Snapshot(1)[0] == "b");
}

void TestClear() {
    ev::ConsoleRingBuffer rb;
    rb.Push("x");
    rb.Push("y");
    CHECK(rb.Size() == 2);
    rb.Clear();
    CHECK(rb.Size() == 0);
    CHECK(rb.Snapshot(5).empty());
}

void TestConcurrentPushSnapshot() {
    // 4 个 producer 线程并发 push + 1 个 consumer 线程并发 snapshot；
    // 验证 mutex 保护下不会撕裂、不会崩。
    ev::ConsoleRingBuffer rb(/*max_lines=*/64);
    constexpr int kPerThread = 500;
    constexpr int kProducers = 4;

    std::vector<std::thread> producers;
    for (int t = 0; t < kProducers; ++t) {
        producers.emplace_back([&rb, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                rb.Push("t" + std::to_string(t) + ":" + std::to_string(i));
            }
        });
    }

    bool stop = false;
    std::thread consumer([&rb, &stop]() {
        while (!stop) {
            auto snap = rb.Snapshot(32);
            // Snapshot 至少应该是合法 vector（不撕裂）；空也合法（早期）。
            // 每个元素是有效 string（已经构造）。
            for (const auto& s : snap) {
                (void)s.size();
            }
        }
    });

    for (auto& th : producers) th.join();
    stop = true;
    consumer.join();

    // push 总量 = 2000 行；buffer cap 64 → 应满。
    CHECK(rb.Size() == 64);
    auto final_snap = rb.Snapshot(64);
    CHECK(final_snap.size() == 64);
}

} // namespace

int main() {
    RUN_TEST(TestPushSnapshotBasic);
    RUN_TEST(TestSnapshotJoined);
    RUN_TEST(TestCapacityDropsOldest);
    RUN_TEST(TestZeroAndOneCap);
    RUN_TEST(TestClear);
    RUN_TEST(TestConcurrentPushSnapshot);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
