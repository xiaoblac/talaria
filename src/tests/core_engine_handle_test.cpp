// 覆盖 EngineHandle<T> 的三个关键行为:
//   1. Store/Get 基础语义:写入后读到同一指针,不读到旧值;
//   2. 多线程交错下 Store/Get 不崩:消费者循环读,生产者循环切换,
//      每次 Get 得到的指针必在 {A,B} 之一且非空,即 "tear-free";
//   3. TryGet/HasValue 在未初始化 handle 上返回 null/false,初始化后一致。
//
// 设计底线测试:如果后面有人把 EngineHandle 改成非原子、改成 setter 回调
// 等"简单但错误"的方案,多线程用例会以显著概率失败;而 Engine 数量极少,
// 这里的纯读写正确性是热路径零锁的保障。

#include "refuzz/core/engine_handle.hpp"

#include <atomic>
#include <chrono>
#include <thread>

namespace {

struct Dummy {
    int id = 0;
};

int BasicStoreGet()
{
    refuzz::core::EngineHandle<Dummy> h;
    if (h.HasValue()) return 1;
    if (h.TryGet() != nullptr) return 1;

    Dummy a{1};
    Dummy b{2};

    h.Store(&a);
    if (!h.HasValue()) return 1;
    if (h.TryGet() != &a) return 1;
    if (&h.Get() != &a) return 1;
    if (h.Get().id != 1) return 1;

    h.Store(&b);
    if (&h.Get() != &b) return 1;
    if (h.Get().id != 2) return 1;

    h.Store(nullptr);
    if (h.HasValue()) return 1;
    if (h.TryGet() != nullptr) return 1;
    return 0;
}

int MultiThreadedSwitch()
{
    refuzz::core::EngineHandle<Dummy> h;
    Dummy a{100};
    Dummy b{200};
    h.Store(&a);

    std::atomic<bool> stop{false};
    std::atomic<int>  observed_a{0};
    std::atomic<int>  observed_b{0};
    std::atomic<int>  observed_bad{0};

    std::thread reader([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            Dummy* p = h.TryGet();
            if (p == &a) {
                observed_a.fetch_add(1, std::memory_order_relaxed);
            } else if (p == &b) {
                observed_b.fetch_add(1, std::memory_order_relaxed);
            } else {
                observed_bad.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    std::thread writer([&]() {
        for (int i = 0; i < 2000; ++i) {
            h.Store((i & 1) ? &b : &a);
        }
    });

    writer.join();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    stop.store(true, std::memory_order_relaxed);
    reader.join();

    if (observed_bad.load() != 0) return 1;
    if (observed_a.load() == 0)   return 1;
    if (observed_b.load() == 0)   return 1;
    return 0;
}

} // namespace

int main()
{
    if (int rc = BasicStoreGet(); rc != 0) return rc;
    if (int rc = MultiThreadedSwitch(); rc != 0) return rc;
    return 0;
}
