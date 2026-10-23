#pragma once

// AsyncAdmitWorker
//
// [v2 admit-worker async — 后端落盘 + ChoiceTable rebuild]
//
// 背景:syzkaller 上游把 ChoiceTable rebuild 跑在独立 goroutine,且节流 33/333 个
//   admission 才触发一次。reFuzz 之前在 corpus_manager_.SetOnAdmit 回调里同步跑
//   CorpusDiskIO::SaveSeed + SyzV2MutatorEngine::OnSeedAdmitted(整个 corpus 全量
//   rebuild ChoiceTable),阻塞主 fuzz 线程。每次 admit 都跑一遍 → 在 13 个 admit 上
//   就出 p99 33s 的 executor_forward_to_feedback 长尾。
//
// 该 worker 把这两件事搬到独立线程,并在 batch 末尾对每个**捕获到的 mutator engine 指针**
// 调一次 OnSeedAdmitted,而不是每个 seed 一次。
//
// 设计要点:
//   - Enqueue(seed, engine_at_admit) 在主 fuzz 线程上调用;O(1) push,只持短锁。
//   - 不丢弃 seed:已经 admit 进 corpus 的 seed 必须确保 disk 落盘 + ChoiceTable rebuild
//     最终发生。pending 数量天然受 corpus capacity 间接约束。
//   - worker 醒来后 swap(queue, local_batch),锁外处理。
//   - SaveSeed 失败只 inc corpus_save_error 计数,不 retry,不阻塞后续 seed。
//   - batch 末尾对每个不同 engine 调一次 OnSeedAdmitted。捕获 engine* 而不是
//     "worker 处理时再读 handle",保留 syzkaller 的"admit-time active engine 被通知"语义。
//   - 析构调 StopAndDrain(),保证 pending seed 全部落盘 + 触发最后一次 rebuild。
//     语义提醒:进程被 SIGKILL/abort 时,刚 admit 但 worker 没保存的 seed 可能丢盘。
//     这是异步化的代价。
//
// 线程模型:
//   - 拥有方(FuzzerLoop)单线程 ctor → Start();主线程 Enqueue;dtor 前 StopAndDrain();
//   - worker 线程内只读 engine_at_admit 指针(非 Handle),engine lifetime 由 Manager 保证 >
//     FuzzerLoop lifetime,FuzzerLoop StopAndDrain → join 在 Manager 析构之前发生。

#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/program/seed.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace refuzz::fuzzer {
class IMutatorEngine;
}

namespace refuzz::control {

class AsyncAdmitWorker {
public:
    // persist_dir 空 → 跳过 SaveSeed(测试模式);只跑 OnSeedAdmitted。
    // metrics 可空(主路径不空,测试可空)。生命周期必须 ≥ worker。
    AsyncAdmitWorker(std::string persist_dir,
                     refuzz::fuzzer::metrics::FuzzerMetrics* metrics);
    ~AsyncAdmitWorker();

    AsyncAdmitWorker(const AsyncAdmitWorker&)            = delete;
    AsyncAdmitWorker& operator=(const AsyncAdmitWorker&) = delete;
    AsyncAdmitWorker(AsyncAdmitWorker&&)                 = delete;
    AsyncAdmitWorker& operator=(AsyncAdmitWorker&&)      = delete;

    // 启动 worker 线程。幂等(重复 Start 第二次起 no-op)。
    void Start();

    // 主线程 admit 路径调用。立即返回,seed 拷贝进队列。
    // engine_at_admit 是当时 active 的 mutator engine 指针(可空,空则跳过 rebuild)。
    void Enqueue(refuzz::fuzzer::Seed seed,
                 refuzz::fuzzer::IMutatorEngine* engine_at_admit);

    // 通知 worker 停止 + drain 当前队列 + join。析构会自动调,FuzzerLoop dtor 显式调一次。
    // 幂等。
    void StopAndDrain();

    // 当前队列里待处理的 seed 数(供 PendingCount 统计用)。
    std::size_t PendingSize() const;

private:
    struct Item {
        refuzz::fuzzer::Seed             seed;
        refuzz::fuzzer::IMutatorEngine*  engine_at_admit = nullptr;
    };

    void RunLoop();
    void ProcessBatch(std::deque<Item>& batch);

    std::string                                  persist_dir_;
    refuzz::fuzzer::metrics::FuzzerMetrics*      metrics_ = nullptr;

    mutable std::mutex                           mu_;
    std::condition_variable                      cv_;
    std::deque<Item>                             queue_;
    std::atomic<bool>                            running_{false};
    bool                                         started_  = false;
    bool                                         stopped_  = false;
    std::thread                                  thread_;
};

} // namespace refuzz::control
