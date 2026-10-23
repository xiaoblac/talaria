// fuzzer_loop_harness_fatal_continue_test.cpp
//
// 跨层回归测试（历史 bug 的缺口）：
//   worker 本地重建失败 → COMP_STATUS_HARNESS_FATAL + error 14 → channel 同时
//   输出 AbnormalKind::kHarnessFatal 并启动恢复策略。旧实现里 FuzzerLoop 收到
//   第一条 kHarnessFatal 就永久置 latch，Orchestrator 循环条件
//   !HarnessFatalLatched() 让整轮 Stop()，即使 channel 的 reboot_vm 恢复仍可能
//   成功（v7.1-r2 现场：latch 后 54s，reboot_vm success=1）。
//
//   本测试验证修复后的契约：
//   1. FuzzerLoop 收到 kHarnessFatal 事件后**继续运行**，事件走正常 abnormal
//      结算（结果必须送达 job/catch-all，请求窗口才会释放）；
//   2. harness_fatal 计数/日志只发一次（首次去重仍然保留）；
//   3. 后续普通 completion 仍能被消费 —— loop 没有被任何 latch 卡死。
//
//   全局终止现在只由 channel 真正进入 kFailed 驱动（Orchestrator::ChannelFailed），
//   不在本测试范围内（那是 Orchestrator/Channel 装配级行为）。

#include "refuzz/control/fuzzer_loop.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/engine_handle.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/task_queue.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <utility>

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

namespace cc = refuzz::core::channel_contract;
namespace metrics = refuzz::core::metrics;

void harness_fatal_does_not_stop_loop()
{
    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    refuzz::fuzzer::InMemoryCorpusStore corpus;
    refuzz::core::EngineHandle<refuzz::fuzzer::IMutatorEngine> mutator;
    refuzz::core::EngineHandle<refuzz::fuzzer::ISchedulerEngine> scheduler;
    refuzz::core::EngineHandle<refuzz::fuzzer::IFeedbackEngine> feedback;
    metrics::MetricRegistry reg;

    refuzz::control::FuzzerLoopConfig cfg;
    // 本测试只验证事件消费路径，不启动 ExploreJob（它需要真实 mutator/scheduler）。
    cfg.suppress_default_producer = true;

    refuzz::control::FuzzerLoop loop(
        task_queue, event_queue, corpus, mutator, scheduler, feedback,
        refuzz::logging::HostLogger::Instance(), cfg, &reg);

    // 1. 第一条 kHarnessFatal 异常事件（对应 wire 上的 COMP_STATUS_HARNESS_FATAL
    //    + error 14，executor_id 必须是已提交任务，结果要回投 job）。
    {
        cc::ChannelEvent evt;
        evt.kind = cc::ChannelEvent::Kind::kAbnormal;
        evt.event_id = 1;
        evt.channel_id = 1;
        cc::AbnormalCompletion abnormal;
        abnormal.kind = cc::AbnormalKind::kHarnessFatal;
        abnormal.ctx.executor_id = 42;
        abnormal.ctx.worker_id = 1;
        abnormal.diagnostics.error_code = 14;  // ERR_DOMAIN_REPLACEMENT_START_FAILED
        evt.payload = std::move(abnormal);
        CHECK(event_queue.Push(std::move(evt)));
    }

    // 2. 紧随其后的普通 completion（模拟恢复期间/之后其它 worker 仍在出结果）。
    {
        cc::ChannelEvent evt;
        evt.kind = cc::ChannelEvent::Kind::kCompletion;
        evt.event_id = 2;
        evt.channel_id = 1;
        cc::Completion completion;
        completion.kind = cc::CompletionKind::kNormal;
        completion.ctx.executor_id = 43;
        completion.ctx.worker_id = 1;
        evt.payload = std::move(completion);
        CHECK(event_queue.Push(std::move(evt)));
    }

    // 3. 消费 kHarnessFatal：RunOnce 必须返回 true（有进展），且不能因此卡死。
    CHECK(loop.RunOnce(std::chrono::milliseconds(0)));
    CHECK(reg.CounterOf("fuzzer.results", {{"kind", "harness_fatal"}}).Value() == 1);

    // 4. 再消费普通 completion：证明 loop 在 harness_fatal 之后仍在运行。
    CHECK(loop.RunOnce(std::chrono::milliseconds(0)));
    CHECK(reg.CounterOf("fuzzer.results", {{"kind", "completion"}}).Value() == 1);

    // 5. 事件队列应已排空。
    CHECK(event_queue.PendingSize() == 0);
}

} // namespace

int main()
{
    RUN_TEST(harness_fatal_does_not_stop_loop);
    return 0;
}
