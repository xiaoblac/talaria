#pragma once

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/mutator/mutator_engine.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

// MutatorManager
//
// 职责：engine 所有权持有 + 注册表 + active engine 切换控制面。
// 非职责：不执行 Mutate；不感知 FuzzerLoop tick；不代理 engine 内部 policy 切换。
//
// 访问模型（handle-based）：
//   * FuzzerLoop / CorpusManager / IPolicyControl 等消费者仅持
//     `const EngineHandle<IMutatorEngine>&`（通过 Handle() 获取），
//     每次 `handle.Get()` 做 acquire 读取当前 active engine。
//   * engine 切换由 Telemetry / PolicyEngine 等决策方调 SwitchEngineByName()，
//     Manager 以 release 原子写更新 handle；engine 实例常驻 engines_
//     （keep_alive），即使正在被读也安全。
//   * engine 内部 policy 切换由 engine 自治，Manager 不干预。
//
// 线程模型：
//   * AddEngine           装配期单线程；同名返回已有索引（不改 handle）。
//   * SwitchEngineByName  任意线程；原子写 handle。
//   * Handle / HasActive / ActiveEngineName / EngineNames  任意线程只读。
class MutatorManager {
public:
    MutatorManager() = default;

    // 装配期：注册 engine。同名返回已有索引（不新插）。
    //
    // activate 语义：
    //   * true（默认）：若尚无 active engine，则把本次注册的 engine 设为 active
    //                   （handle 首次指向它）；已有 active 时不动 handle。
    //   * false：永不改动 handle。Assembler 一次性装齐多个 engine、之后再显式
    //            SwitchEngineByName 时使用，避免遍历顺序决定 active 的抖动。
    int AddEngine(std::unique_ptr<IMutatorEngine> engine);
    int AddEngine(std::unique_ptr<IMutatorEngine> engine, bool activate);

    // 任意线程：原子切换到指定 engine。name 未注册 → false 且 handle 不变。
    bool SwitchEngineByName(std::string_view name);

    // [machine-check C4.6] Apply the machine-checked enabled-calls mask to EVERY
    // registered engine (each rebuilds its derived state, e.g. the ChoiceTable),
    // so whichever engine is/becomes active emits only the supported set.
    // Startup-only (called before the fuzz loop), so iterating engines_ needs no
    // extra synchronization.
    void SetEnabledCalls(const std::vector<std::uint8_t>& enabled_mask);

    // 消费者唯一访问入口；返回 const 引用，消费者不得写 handle。
    const core::EngineHandle<IMutatorEngine>& Handle() const noexcept { return engine_handle_; }

    // 诊断：当前 active engine 名字；无 engine 返回空串。
    std::string ActiveEngineName() const;

    // 诊断 / 交互前端：按注册顺序返回所有 engine 名字。
    std::vector<std::string> EngineNames() const;

    // 是否至少有一个 engine 已注册且 handle 已初始化。
    bool HasActive() const noexcept { return engine_handle_.HasValue(); }

private:
    std::vector<std::unique_ptr<IMutatorEngine>> engines_;
    std::unordered_map<std::string, int> engine_name_index_;

    core::EngineHandle<IMutatorEngine> engine_handle_;
};

} // namespace refuzz::fuzzer
