// async_admit_worker_test.cpp
//
// [v2 admit-worker async; persist-at-shutdown] 验证 AsyncAdmitWorker:
//   - worker 现在**只**做异步 OnSeedAdmitted(RebuildChoiceTable),**不再**在 admit
//     热路径落盘(corpus 持久化移到 FuzzerLoop 析构的 CorpusDiskIO::SaveAll)→ 断言
//     worker 处理后磁盘**无** seed 文件;
//   - 同一 batch 内多 seed 共享同一 engine* 时,OnSeedAdmitted 合并为少数几次;
//   - 不同 engine* 各通知一次;
//   - StopAndDrain 后 PendingSize == 0。

#include "refuzz/control/async_admit_worker.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/mutator/mutator_engine.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace {

using refuzz::control::AsyncAdmitWorker;
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

class FakeMutatorEngine final : public refuzz::fuzzer::IMutatorEngine {
public:
    std::string Name() const override { return "fake"; }
    std::vector<uint8_t> Mutate(const Seed&) override { return {}; }
    bool SwitchPolicyByName(std::string_view) override { return true; }
    std::string ActivePolicyName() const override { return ""; }
    void OnSeedAdmitted(const Seed& /*s*/) override {
        notify_count.fetch_add(1, std::memory_order_relaxed);
    }
    std::atomic<int> notify_count{0};
};

Seed MakeSeed(uint64_t id, uint8_t b)
{
    Seed s;
    s.seed_id = id;
    s.payload = {b};
    return s;
}

std::string MakeTmpDir(const char* tag)
{
    namespace fs = std::filesystem;
    auto base = fs::temp_directory_path() / (std::string("refuzz_admit_test_") + tag);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base.string();
}

void TestBatchSavesAllAndCoalescesNotify()
{
    namespace fs = std::filesystem;
    const std::string dir = MakeTmpDir("batch_coalesce");

    AsyncAdmitWorker worker(dir, /*metrics=*/nullptr);
    worker.Start();

    FakeMutatorEngine engine;

    constexpr int kN = 16;
    for (int i = 1; i <= kN; ++i) {
        worker.Enqueue(MakeSeed(static_cast<uint64_t>(i), static_cast<uint8_t>(i)),
                       &engine);
    }
    worker.StopAndDrain();

    // [persist-at-shutdown] worker 不再在 admit 热路径落盘 —— 持久化已移到 FuzzerLoop
    // 析构的 CorpusDiskIO::SaveAll。所以 worker 处理完后磁盘应**无**任何 seed 文件。
    int saved = 0;
    for (auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_directory() &&
            fs::exists(entry.path() / "payload.bin")) {
            ++saved;
        }
    }
    EXPECT(saved == 0);

    // Batch 合并:整批同一 engine 指针 ⇒ 触发次数应该远小于 kN(理想 1,但若 worker
    // 早醒分批处理,可能 ≤ 几次)。强检 < kN/2 + 1 即足以证明合并发生。
    const int notified = engine.notify_count.load();
    EXPECT(notified >= 1);
    EXPECT(notified <= kN / 2 + 1);

    EXPECT(worker.PendingSize() == 0);

    fs::remove_all(dir);
}

void TestDifferentEnginesEachNotified()
{
    namespace fs = std::filesystem;
    const std::string dir = MakeTmpDir("two_engines");

    AsyncAdmitWorker worker(dir, /*metrics=*/nullptr);
    worker.Start();

    FakeMutatorEngine eng_a;
    FakeMutatorEngine eng_b;

    // 单 batch 内交错 enqueue,确保 worker 在一次 swap 内拿到两个 engine。
    // 注:worker 在 enqueue 后 cv.notify_one,可能在第一条就醒;为提高 batch
    // 概率,先全部 enqueue 完再 StopAndDrain,worker 拿到的是当前队列快照。
    for (int i = 0; i < 4; ++i) {
        worker.Enqueue(MakeSeed(static_cast<uint64_t>(100 + i),
                                static_cast<uint8_t>(i)),
                       &eng_a);
        worker.Enqueue(MakeSeed(static_cast<uint64_t>(200 + i),
                                static_cast<uint8_t>(i + 16)),
                       &eng_b);
    }
    worker.StopAndDrain();

    // 不论 batch 怎么切,两个 engine 都应至少被通知一次。
    EXPECT(eng_a.notify_count.load() >= 1);
    EXPECT(eng_b.notify_count.load() >= 1);

    fs::remove_all(dir);
}

void TestNullEngineSkipsNotify()
{
    namespace fs = std::filesystem;
    const std::string dir = MakeTmpDir("null_engine");

    AsyncAdmitWorker worker(dir, /*metrics=*/nullptr);
    worker.Start();

    for (int i = 0; i < 3; ++i) {
        worker.Enqueue(MakeSeed(static_cast<uint64_t>(300 + i),
                                static_cast<uint8_t>(i)),
                       /*engine=*/nullptr);
    }
    worker.StopAndDrain();

    // [persist-at-shutdown] worker 不落盘(持久化移到 shutdown);null engine 下也无
    // OnSeedAdmitted 回调可调。无 crash + 磁盘无文件即过。
    int saved = 0;
    for (auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_directory() &&
            fs::exists(entry.path() / "payload.bin")) {
            ++saved;
        }
    }
    EXPECT(saved == 0);

    fs::remove_all(dir);
}

void TestEmptyPersistDirSkipsSave()
{
    AsyncAdmitWorker worker(/*persist_dir=*/"", /*metrics=*/nullptr);
    worker.Start();

    FakeMutatorEngine engine;
    for (int i = 0; i < 5; ++i) {
        worker.Enqueue(MakeSeed(static_cast<uint64_t>(400 + i),
                                static_cast<uint8_t>(i)),
                       &engine);
    }
    worker.StopAndDrain();

    // [persist-at-shutdown] persist_dir 现已被 worker 忽略(它不再落盘);OnSeedAdmitted
    // 仍正常触发(>= 1),PendingSize 归零。
    EXPECT(engine.notify_count.load() >= 1);
    EXPECT(worker.PendingSize() == 0);
}

} // namespace

int main()
{
    TestBatchSavesAllAndCoalescesNotify();
    TestDifferentEnginesEachNotified();
    TestNullEngineSkipsNotify();
    TestEmptyPersistDirSkipsSave();
    std::fprintf(stdout, "tests: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
