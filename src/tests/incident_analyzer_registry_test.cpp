// §3.11-E — IIncidentAnalyzer registry + IIncidentCorrelator smoke
// test. 验证：
//   1) RegisterBuiltinIncidentAnalyzers() 把 KernelSyzCrashAnalyzer
//      注册到 (kSyzProg, kCrash) key；
//   2) Classify(incident) 行为对 console-pattern incident 给出非空
//      title + 非空 stack；
//   3) BucketHash + ShouldMerge 在同样 incident 上等价，反之不等；
//   4) SingleWorkerTimeWindowCorrelator 按 (worker_id, ts window) 关联。

#include "refuzz/crash/incident/evidence_fragment.hpp"
#include "refuzz/crash/incident/incident.hpp"
#include "refuzz/crash/incident/incident_analyzer.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
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

namespace ic = refuzz::crash::incident;

ic::CrashIncident MakeKernelPanicIncident(uint64_t worker_id,
                                            uint64_t ts_us,
                                            uint64_t incident_id) {
    ic::CrashIncident inc;
    inc.incident_id          = incident_id;
    inc.program_format       = refuzz::fuzzer::ProgFormat::kSyzProg;
    inc.first_fragment_ts_us = ts_us;
    inc.last_fragment_ts_us  = ts_us;
    inc.correlation_keys     = {worker_id};

    // 一条 console fragment（high confidence）+ 一条 heartbeat（low）
    {
        ic::CrashEvidenceFragment cf;
        cf.source         = ic::Source::kKernelConsole;
        cf.program_format = refuzz::fuzzer::ProgFormat::kSyzProg;
        cf.worker_id      = worker_id;
        cf.captured_ts_us = ts_us;
        cf.confidence     = ic::Confidence::kHigh;
        cf.payload = ic::ConsoleLines{
            { "[  100.000] BUG: KASAN: out-of-bounds in foo+0x10/0x20",
              "[  100.001] Call Trace:",
              "[  100.002]  ? do_thing+0x42/0x100",
              "[  100.003]  ? top_caller+0x10/0x40" }, false };
        inc.fragments.push_back(std::move(cf));
    }
    {
        ic::CrashEvidenceFragment hb;
        hb.source         = ic::Source::kHeartbeat;
        hb.program_format = refuzz::fuzzer::ProgFormat::kSyzProg;
        hb.worker_id      = worker_id;
        hb.captured_ts_us = ts_us + 1000;
        hb.confidence     = ic::Confidence::kLow;
        hb.payload        = ic::HeartbeatGap{ts_us, 3000, 3};
        inc.fragments.push_back(std::move(hb));
    }
    return inc;
}

void TestRegistryFindRegistered() {
    ic::IncidentAnalyzerRegistry::Instance().ResetForTest();
    ic::RegisterBuiltinIncidentAnalyzers();

    auto* a = ic::IncidentAnalyzerRegistry::Instance().Find(
        refuzz::fuzzer::ProgFormat::kSyzProg, ic::IncidentKind::kCrash);
    CHECK(a != nullptr);
    CHECK(a->program_format() == refuzz::fuzzer::ProgFormat::kSyzProg);
    CHECK(a->incident_kind() == ic::IncidentKind::kCrash);
}

void TestRegistryFindUnregistered() {
    ic::IncidentAnalyzerRegistry::Instance().ResetForTest();
    ic::RegisterBuiltinIncidentAnalyzers();

    auto* a = ic::IncidentAnalyzerRegistry::Instance().Find(
        refuzz::fuzzer::ProgFormat::kAflRaw, ic::IncidentKind::kCrash);
    CHECK(a == nullptr);  // AFL adapter 还没接入
}

void TestKernelSyzAnalyzerClassify() {
    ic::IncidentAnalyzerRegistry::Instance().ResetForTest();
    ic::RegisterBuiltinIncidentAnalyzers();

    auto* analyzer = ic::IncidentAnalyzerRegistry::Instance().Find(
        refuzz::fuzzer::ProgFormat::kSyzProg, ic::IncidentKind::kCrash);
    CHECK(analyzer != nullptr);

    auto incident = MakeKernelPanicIncident(/*worker_id=*/3, /*ts=*/1'000'000,
                                              /*incident_id=*/42);
    auto cls = analyzer->Classify(incident);
    CHECK(cls.kind == ic::IncidentKind::kCrash);
    CHECK(!cls.title.empty());
    CHECK(cls.confidence == ic::Confidence::kHigh);  // 取自 console fragment
    CHECK(!cls.signature.empty());
    std::fprintf(stderr,
                 "  classified title='%s' stack_top=%zu sig='%s'\n",
                 cls.title.c_str(), cls.stack_top.size(),
                 cls.signature.c_str());
}

void TestBucketHashAndMerge() {
    ic::IncidentAnalyzerRegistry::Instance().ResetForTest();
    ic::RegisterBuiltinIncidentAnalyzers();

    auto* analyzer = ic::IncidentAnalyzerRegistry::Instance().Find(
        refuzz::fuzzer::ProgFormat::kSyzProg, ic::IncidentKind::kCrash);
    CHECK(analyzer != nullptr);

    auto inc1 = MakeKernelPanicIncident(1, 1'000'000, 100);
    auto inc2 = MakeKernelPanicIncident(2, 2'000'000, 101);  // 同 console，不同 worker / id

    auto cls1 = analyzer->Classify(inc1);
    auto cls2 = analyzer->Classify(inc2);

    auto h1 = analyzer->BucketHash(cls1);
    auto h2 = analyzer->BucketHash(cls2);
    CHECK(h1 != 0);
    CHECK(h1 == h2);  // 同 console 内容 → 同 hash（合并到同 bucket）
    CHECK(analyzer->ShouldMerge(cls1, cls2));

    // 修改 inc2 的 console 让它产生不同 title → hash 应该不同
    {
        auto& cf = inc2.fragments[0];
        std::get<ic::ConsoleLines>(cf.payload).lines[0] =
            "[  200.000] BUG: KASAN: use-after-free in bar+0x99/0xff";
    }
    auto cls2b = analyzer->Classify(inc2);
    auto h2b   = analyzer->BucketHash(cls2b);
    CHECK(h1 != h2b);
    CHECK(!analyzer->ShouldMerge(cls1, cls2b));
}

void TestCorrelatorAttachWithinWindow() {
    ic::SingleWorkerTimeWindowCorrelator corr(/*window_us=*/5'000'000);

    std::vector<ic::CrashIncident> open;
    open.push_back(MakeKernelPanicIncident(/*worker_id=*/3,
                                            /*ts=*/1'000'000,
                                            /*incident_id=*/77));

    // 同 worker，3s 内 → attach
    ic::CrashEvidenceFragment frag;
    frag.source         = ic::Source::kHeartbeat;
    frag.worker_id      = 3;
    frag.captured_ts_us = 4'000'000;  // 3s 后
    auto attach = corr.FindOrAttach(frag, open);
    CHECK(attach.has_value());
    CHECK(*attach == 77);

    // 不同 worker → 不 attach
    frag.worker_id = 5;
    CHECK(!corr.FindOrAttach(frag, open).has_value());

    // 同 worker，超出窗口 → 不 attach
    frag.worker_id      = 3;
    frag.captured_ts_us = 1'000'000 + 6'000'000;  // 6s after first
    CHECK(!corr.FindOrAttach(frag, open).has_value());
}

void TestCorrelatorShouldClose() {
    ic::SingleWorkerTimeWindowCorrelator corr(/*window_us=*/5'000'000);
    auto inc = MakeKernelPanicIncident(3, 1'000'000, 88);
    inc.last_fragment_ts_us = 2'000'000;

    CHECK(!corr.ShouldClose(inc, 3'000'000));      // 1s after last → keep open
    CHECK(corr.ShouldClose(inc, 8'000'000));       // 6s after last → close
}

} // namespace

int main() {
    RUN_TEST(TestRegistryFindRegistered);
    RUN_TEST(TestRegistryFindUnregistered);
    RUN_TEST(TestKernelSyzAnalyzerClassify);
    RUN_TEST(TestBucketHashAndMerge);
    RUN_TEST(TestCorrelatorAttachWithinWindow);
    RUN_TEST(TestCorrelatorShouldClose);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
