#pragma once

// 内存任务队列(无多态):Executor Pop、FuzzerLoop Push 的唯一实现类型。
// Close 语义与 result/event/crash 队列一致:closed 后 Push 失败;Pop 可 drain 至空。
//
// [严格 Order + Alternate —— job-loop Step 5]
// 5 档 tier(见 task_tier.hpp),Pop **镜像 syzkaller 的 source Order**(fuzzer.go:106):
//   Order(triageCandidate ① , candidate ② , triage ③ , Alternate(smash ④ , 3), genFuzz ⑤ )
// —— ①②③ 严格优先(高档非空必先给),④ Smash 用 Alternate(3):④⑤ 都有时每 3 次让 1 次给
// ⑤(镜像 `Alternate.Next` 每 nth 次返回 nil → 落下一档),防 smash 永久压住 gen/mut;只有
// 一档非空时直接给该档(不空转)。**优先级实现在 Pop(pull)侧**;push 只按生产者语义打档,
// push 顺序不影响优先级。只用单一档(如 flag-off 全默认 Triage)时退化为该档 FIFO,与旧纯
// FIFO 逐字节等价。同档内 FIFO(对齐 syz 同 source 层)。
//
//   task.important 字段保留在 HostFuzzTask 上但不参与本队列排序(见 syzkaller 语义:important
//   是 crash-retry robustness flag,不是排序优先级);source 分层优先由上面的 tier + Order 实现。
//
// §3.10 step 5 (plan D7): InMemoryTaskQueue is retyped from
// `proto::Task` to `HostFuzzTask` so the host pipeline carries
// `ProgramArtifact` end-to-end; the on-wire `proto::Task` shape is
// constructed only at the executor's channel-dispatch boundary.

#include "refuzz/proto_domain/types.hpp"
#include "refuzz/queue/host_fuzz_task.hpp"   // §3.10 D7 — HostFuzzTask
#include "refuzz/queue/task_tier.hpp"        // [Step 5] TaskTier / kTaskTierCount

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::queue {

class InMemoryTaskQueue final {
public:
    InMemoryTaskQueue() = default;

    // FuzzerLoop/stages 的唯一入口;按 tier 尾部入队(同档 FIFO)。tier 默认 Triage(③)
    // (所有既有直接 Push 调用点不带 tier → 单档 FIFO,flag-off 逐字节等价);生产者/arbiter
    // 据自身语义打对应档。executor_id==0 或 closed 时返回 false。
    bool Push(HostFuzzTask task, TaskTier tier = TaskTier::Triage);

    // Executor 的唯一出口;严格 Order + Alternate(smash,3) 取(见头部)。所有档皆空且未
    // closed 时阻塞至 timeout。签名不变 → Executor 侧无需改动。
    std::optional<HostFuzzTask> Pop(std::chrono::milliseconds timeout);

    size_t PendingSize();   // 所有档合计;观测/诊断用,不作为 request-window credit
    void Close();

private:
    static constexpr std::uint64_t kAlternateNth = 3;  // Smash 每 3 次让 1 次 Explore(= syz Alternate(_,3))

    HostFuzzTask PopFront(std::size_t idx);  // caller holds mu_;pop 该档队首 + 盖 pop 时戳

    std::mutex              mu_;
    std::condition_variable cv_;
    std::array<std::deque<HostFuzzTask>, kTaskTierCount> tiers_;  // 按 TaskTier 索引;0 最高优先
    std::uint64_t           alternate_counter_ = 0;  // 仅 ④⑤ 都非空时推进(smash/explore 的选择点)
    bool                    closed_ = false;
};

} // namespace refuzz::queue
