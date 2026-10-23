// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 7 PR-11 B1 — submit boundary fail-closed regression test.
//
// 验证 channeldispatcher 的 submit 边界:当 MaterializeExecWire 失败时,
//   1. **不**调 channel Submit (worker 收不到空 payload 的 task)
//   2. event_queue 收到合成的 host-side AbnormalCompletion(kExecError)
//   3. materialize_exec_wire_failed 计数器递增
//
// 测试构造:
//   1. 用 TextDecoder 解一段简单 prog (write syscall)
//   2. 把 DataArg 用 set_out_size 改成 "data.empty() && size()>0" — 触发
//      write_arg 的 kData silent-no-op 路径 (PR-10 已修为 return false)
//   3. 包成 ProgramArtifact 投入 task queue
//   4. 跑 ProcessOnce
//   5. 断言 FakeChannel.submissions.empty()(没投 worker)+ event_queue
//      有一条 AbnormalCompletion
//
// 这是 PR-10 + PR-11 联合验证:encoder fail-closed → submit boundary
// fail-closed → worker 从此不再收到 empty payload exec_error。

#include "channeldispatcher.hpp"
#include "refuzz/channel/channel.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/task_queue.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

namespace {

namespace cc  = refuzz::core::channel_contract;
namespace syz = refuzz::program::syz;
namespace pr  = refuzz::program;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            std::abort();                                                        \
        }                                                                        \
    } while (0)

// minimal FakeChannel (copy from executor_hot_path_test pattern,但只用
// Submit 计数)。
class FakeChannel final : public refuzz::channel::IChannel {
public:
    explicit FakeChannel(uint32_t channel_id) : channel_id_(channel_id) {}
    refuzz::channel::Result<void> Boot() override
    {
        return refuzz::channel::Result<void>::Ok();
    }
    void Close() override {}
    cc::ChannelSubmitResult Submit(const cc::ChannelDispatchRequest& request,
                                   std::chrono::microseconds) override
    {
        submissions.push_back(request);
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kAccepted, generation};
    }
    bool DrainEvents(refuzz::channel::EventList& events,
                     std::chrono::microseconds) override
    {
        if (queued_events.empty()) return false;
        while (!queued_events.empty()) {
            events.push_back(std::move(queued_events.front()));
            queued_events.pop_front();
        }
        return true;
    }
    void AttachObservabilityPublishers(
        refuzz::core::BroadcastBus<cc::ChannelSnapshot>*,
        refuzz::core::BroadcastBus<cc::ChannelObserveEvent>*,
        refuzz::core::metrics::ChannelMetrics* = nullptr,
        refuzz::core::metrics::MetricRegistry* = nullptr) override {}
    cc::ChannelSnapshot ObserveSnapshot() const override
    {
        cc::ChannelSnapshot s;
        s.channel_id = channel_id_;
        s.generation = generation;
        s.lifecycle_state = cc::ChannelLifecycleState::kRunning;
        return s;
    }
    bool DrainObserveEvents(cc::ChannelObserveEventList&,
                            std::chrono::microseconds) override { return false; }
    uint32_t generation = 1;
    std::vector<cc::ChannelDispatchRequest> submissions;
    std::deque<cc::ChannelEvent> queued_events;
private:
    uint32_t channel_id_;
};

// 构造一个**会让 MaterializeExecWire 失败**的 artifact:
// DataArg 的 size>0 但 data 为空 (set_out_size 后),触发 write_arg kData
// silent-no-op 路径(PR-10 改成 return false → serialize_for_exec 返 ExecError)。
std::shared_ptr<const syz::Prog> MakeBrokenProg()
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(
        "write(0xffffffffffffffff, &(0x7f0000000000)=\"deadbeef\"/8, 0x8)\n");
    CHECK(prog_or.has_value());
    CHECK(*prog_or != nullptr);
    auto prog = std::move(*prog_or);

    // 找第一个 DataArg, 把 data 清空但 out_size 设大,触发 silent-no-op。
    syz::DataArg* da = nullptr;
    for (auto& cup : prog->calls()) {
        if (da != nullptr) break;
        syz::foreach_arg(cup.get(), [&](syz::Arg* a, syz::ArgCtx*) {
            if (da != nullptr) return;
            if (a->arg_kind() == syz::ArgKind::kData) {
                da = static_cast<syz::DataArg*>(a);
            }
        });
    }
    CHECK(da != nullptr);
    da->set_out_size(8);
    CHECK(da->data().empty());
    CHECK(da->size() == 8);

    return std::move(prog);
}

refuzz::queue::HostFuzzTask MakeBadTask(uint64_t executor_id)
{
    pr::RegisterBuiltinArtifactMaterializers();
    auto prog = MakeBrokenProg();
    refuzz::queue::HostFuzzTask task;
    task.executor_id    = executor_id;
    task.seed_id        = 9001;
    task.origin_seed_id = 9001;
    task.opts.timeout_ms = 1000;
    // **空 payload + valid artifact** → 进 MaterializeExecWire 分支
    task.artifact = syz::MakeArtifactFromTypedProg(std::move(prog));
    CHECK(task.artifact.valid());
    return task;
}

int TestMaterializeFailDoesNotSubmit()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(7);
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    CHECK(task_queue.Push(MakeBadTask(12345)));

    // 跑一次 ProcessOnce
    const bool processed = executor.ProcessOnce(
        task_queue, event_queue,
        std::chrono::milliseconds{0},
        std::chrono::microseconds{0});
    CHECK(processed);

    // 关键断言:channel Submit **未**被调用 (broken task 没流到 worker)
    if (!channel.submissions.empty()) {
        std::fprintf(stderr,
            "FAIL: channel.Submit 被调了 %zu 次,期望 0 次 "
            "(broken IR 不该流到 worker)\n", channel.submissions.size());
        std::abort();
    }

    // event_queue 应有一条 AbnormalCompletion (kExecError) 给上游 stage
    auto evt_opt = event_queue.Pop(std::chrono::milliseconds{0});
    if (!evt_opt.has_value()) {
        std::fprintf(stderr,
            "FAIL: event_queue 期望有合成 AbnormalCompletion,实际空\n");
        std::abort();
    }
    const auto& evt = *evt_opt;
    CHECK(evt.kind == cc::ChannelEvent::Kind::kAbnormal);
    const auto* abn = evt.AsAbnormal();
    CHECK(abn != nullptr);
    // [语义拆分] MaterializeExecWire 失败 = host 侧 wiring/基础设施问题,程序无罪
    // → kInfraFault(不再是笼统的 exec_error)。
    CHECK(abn->kind == cc::AbnormalKind::kInfraFault);
    CHECK(abn->ctx.executor_id == 12345);
    CHECK(abn->ctx.seed_id == 9001);
    CHECK(abn->ctx.worker_id == 0);  // host-rejected,无 worker
    CHECK(abn->output.empty());      // 无 dispatch output

    std::fprintf(stderr, "  (synth event id=%llu executor_id=%llu)\n",
                 (unsigned long long)evt.event_id,
                 (unsigned long long)abn->ctx.executor_id);
    return 0;
}

int TestNormalTaskStillSubmits()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(8);
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;

    // payload 直接给字节,绕过 materialize → 走 ps.request.payload = task.payload 路径
    refuzz::queue::HostFuzzTask task;
    task.executor_id    = 67890;
    task.seed_id        = 1111;
    task.origin_seed_id = 1111;
    task.opts.timeout_ms = 1000;
    task.payload = {0x01, 0x02, 0x03, 0x04};
    CHECK(task_queue.Push(std::move(task)));

    CHECK(executor.ProcessOnce(task_queue, event_queue,
                                std::chrono::milliseconds{0},
                                std::chrono::microseconds{0}));
    // 这次应该真去 Submit
    CHECK(channel.submissions.size() == 1);
    CHECK(channel.submissions[0].executor_id == 67890);
    return 0;
}

}  // namespace

int main()
{
    std::fprintf(stderr, "RUN  TestMaterializeFailDoesNotSubmit\n");
    if (TestMaterializeFailDoesNotSubmit() != 0) return 1;
    std::fprintf(stderr, "OK   TestMaterializeFailDoesNotSubmit\n");
    std::fprintf(stderr, "RUN  TestNormalTaskStillSubmits\n");
    if (TestNormalTaskStillSubmits() != 0) return 1;
    std::fprintf(stderr, "OK   TestNormalTaskStillSubmits\n");
    std::fprintf(stderr, "dispatcher_materialize_fail_closed_test: ALL OK\n");
    return 0;
}
