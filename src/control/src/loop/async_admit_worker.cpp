#include "refuzz/control/async_admit_worker.hpp"
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include <unordered_set>
#include <utility>

namespace refuzz::control {

AsyncAdmitWorker::AsyncAdmitWorker(std::string persist_dir,
                                   refuzz::fuzzer::metrics::FuzzerMetrics* metrics)
    : persist_dir_(std::move(persist_dir))
    , metrics_(metrics)
{}

AsyncAdmitWorker::~AsyncAdmitWorker()
{
    // 幂等;若 owner 已显式 StopAndDrain,这里直接返回。
    StopAndDrain();
}

void AsyncAdmitWorker::Start()
{
    std::lock_guard<std::mutex> lk(mu_);
    if (started_) {
        return;
    }
    started_ = true;
    running_.store(true, std::memory_order_release);
    thread_ = std::thread([this] { RunLoop(); });
}

void AsyncAdmitWorker::Enqueue(refuzz::fuzzer::Seed seed,
                               refuzz::fuzzer::IMutatorEngine* engine_at_admit)
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        queue_.push_back(Item{std::move(seed), engine_at_admit});
    }
    cv_.notify_one();
}

void AsyncAdmitWorker::StopAndDrain()
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!started_ || stopped_) {
            stopped_ = true;
            return;
        }
        stopped_ = true;
        running_.store(false, std::memory_order_release);
    }
    cv_.notify_all();
    if (thread_.joinable()) {
        thread_.join();
    }
    // 防御:join 后再处理一次 — 极小概率 enqueue 在 join 后没醒过 worker,
    // 但前面 stopped_=true 已禁后续 enqueue 也无实际触发,这里只是收尾对账。
    std::deque<Item> tail;
    {
        std::lock_guard<std::mutex> lk(mu_);
        tail.swap(queue_);
    }
    if (!tail.empty()) {
        ProcessBatch(tail);
    }
}

std::size_t AsyncAdmitWorker::PendingSize() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return queue_.size();
}

void AsyncAdmitWorker::RunLoop()
{
    while (true) {
        std::deque<Item> batch;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [this] {
                return !queue_.empty() ||
                       !running_.load(std::memory_order_acquire);
            });
            batch.swap(queue_);
            if (batch.empty() &&
                !running_.load(std::memory_order_acquire)) {
                return;
            }
        }
        ProcessBatch(batch);
    }
}

void AsyncAdmitWorker::ProcessBatch(std::deque<Item>& batch)
{
    // [persist-at-shutdown] 不再在 admit 热路径逐 seed 落盘 —— corpus 持久化改为
    // FuzzerLoop 析构时对**最终(已 minimize)**的 in-memory corpus 一次性
    // CorpusDiskIO::SaveAll。好处:(a) admit 路径零磁盘 I/O;(b) 磁盘只存最终最小集
    // (被 MaybeMinimizeCorpus 丢掉的 seed 从不落盘),无需逐-drop 删盘。本 worker
    // 现在只做异步 RebuildChoiceTable(O(corpus) 的 scheduler/mutator 状态,必须运行期
    // 完成)。persist_dir_ / metrics_ 字段保留(ctor 兼容),此路径已不再使用。

    // 每个 batch 内出现过的 engine 各通知一次,而不是每 seed 通知一次。
    //    捕获的是 admit-time engine 指针,所以即便切换发生 worker 仍通知"当时 active"。
    //    多数情况下整 batch 同一 engine,这一步只有一次 Rebuild。
    std::unordered_set<refuzz::fuzzer::IMutatorEngine*> notified;
    notified.reserve(2);
    // OnSeedAdmitted 实际不读 seed 内容(SyzV2MutatorEngine::OnSeedAdmitted 仅 RebuildChoiceTable),
    // 但接口签名要 const Seed&,选 batch 末尾(最新)那条做参数。
    for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
        if (it->engine_at_admit == nullptr) {
            continue;
        }
        if (notified.insert(it->engine_at_admit).second) {
            it->engine_at_admit->OnSeedAdmitted(it->seed);
        }
    }
}

} // namespace refuzz::control
