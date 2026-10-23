#pragma once

// RequestLifecycleEvent 桥接队列(无多态):Executor submit 线程 Push、FuzzerLoop
// 控制线程 DrainAll。与 InMemoryEventQueue 同构(mutex + deque + closed_),但**非阻塞**:
// 控制环每 tick 机会式排干,不需要 blocking Pop / condition_variable。
//
// 用途:承载 pull/window 生命周期(accepted/rejected),与 event_queue 承载的
// result/routing 生命周期(Completion/Abnormal/Fault)严格分开 —— 见
// core/include/refuzz/core/request_lifecycle.hpp。

#include "refuzz/core/request_lifecycle.hpp"

#include <cstddef>
#include <deque>
#include <mutex>
#include <vector>

namespace refuzz::queue {

class InMemoryLifecycleQueue final {
public:
    // executor 线程:入队一个派发生命周期事件。Close 之后丢弃(返回 false)。
    bool Push(refuzz::core::channel_contract::RequestLifecycleEvent ev);
    // 控制线程:一次取走当前所有事件(swap-out,O(1) 转移)。空则返回空 vector。
    std::vector<refuzz::core::channel_contract::RequestLifecycleEvent> DrainAll();
    size_t PendingSize() const;
    void Close();

private:
    mutable std::mutex mu_;
    std::deque<refuzz::core::channel_contract::RequestLifecycleEvent> queue_;
    bool closed_ = false;
};

} // namespace refuzz::queue
