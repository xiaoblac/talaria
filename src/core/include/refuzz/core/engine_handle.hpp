// Copyright 2026 reFuzz project author -------youngkk.
//
// EngineHandle<T>
//
// 一个"能力引用点":原子指针 + acquire/release 语义,供 FuzzerLoop 等
// 热路径消费者在**不感知切换者**的前提下获取当前活跃的能力实现。
//
// 设计意图:
//   1. FuzzerLoop 只消费能力(Mutate/Schedule/ProcessFeedback),不应当持有
//      Manager&,更不应当在热路径上调用 manager.Active();
//   2. Manager 负责持有 engine 的所有权(unique_ptr)并提供切换控制面,
//      切换时通过 Handle 原子写入新指针;
//   3. Telemetry/PolicyEngine 根据 snapshot/event 评估后,向 Manager 发
//      SwitchEngineByName 指令;Manager 写 Handle,FuzzerLoop 下一次
//      Get() 自动拿到新 engine。热路径零分支、零锁。
//
// 生命周期约定:
//   * EngineHandle 本身不拥有 T,仅保存裸指针;
//   * 所有 engine 实例由 Manager 的 registry(id -> unique_ptr<T>)拥有,
//     且**永不析构**到 Manager 本身销毁——切换只改 Handle 指向,不释放旧
//     engine,天然避免 RCU/引用计数的复杂性;
//   * Handle 的寿命 >= 持有它的 FuzzerLoop 等消费者。
//
// 线程语义:
//   * Store 使用 memory_order_release;
//   * Get/TryGet 使用 memory_order_acquire;
//   * 因此:调用 Store 的线程对 engine 内部状态所做的"初始化写"对
//     所有后续 Get 可见(happens-before)。消费者不需要额外同步。

#pragma once

#include <atomic>
#include <cassert>
#include <type_traits>

namespace refuzz::core {

// EngineHandle<T>:T 通常是接口基类(如 IMutatorEngine、ISchedulerEngine)。
// T 不需要可复制/可移动;这里只保存指针。
template <typename T>
class EngineHandle {
public:
    EngineHandle() noexcept = default;

    explicit EngineHandle(T* initial) noexcept : ptr_(initial) {}

    EngineHandle(const EngineHandle&)            = delete;
    EngineHandle& operator=(const EngineHandle&) = delete;
    EngineHandle(EngineHandle&&)                 = delete;
    EngineHandle& operator=(EngineHandle&&)      = delete;

    // 替换当前指向。
    // 通常仅 Manager 调用;消费者(FuzzerLoop 等)不应持有可写引用。
    void Store(T* next) noexcept
    {
        ptr_.store(next, std::memory_order_release);
    }

    // 读取当前活跃 engine,并断言非空。
    // 在热路径(FuzzerLoop 每个 tick)上使用。调用前必须确保装配期已 Store 了
    // 至少一次有效指针——这在 Assembler 流程里是天然保证。
    T& Get() const noexcept
    {
        T* p = ptr_.load(std::memory_order_acquire);
        assert(p != nullptr && "EngineHandle::Get() on uninitialized handle");
        return *p;
    }

    // 安全读取:允许返回 nullptr。仅在探测/诊断代码里使用,主路径用 Get。
    T* TryGet() const noexcept
    {
        return ptr_.load(std::memory_order_acquire);
    }

    bool HasValue() const noexcept
    {
        return ptr_.load(std::memory_order_acquire) != nullptr;
    }

private:
    std::atomic<T*> ptr_{nullptr};
};

// 非 engine 组件(crash/repro/channel/corpus_store 等)在将来也可能需要运行时
// 切换(例如 Telemetry 侧判定当前 crash detector 误报率高 → 切到另一种),
// 因此复用同一模板即可;当前阶段它们可能仍是"装配期固定",等到引入切换需求时
// 再让 Manager 层持有对应 Handle,无需改模板。
template <typename T>
using ComponentHandle = EngineHandle<T>;

} // namespace refuzz::core
