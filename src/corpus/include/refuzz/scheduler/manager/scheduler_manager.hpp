#pragma once

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

// SchedulerManager
//
// 与 MutatorManager 职责同构：engine 注册 + active 切换控制面（handle-based）。
// 详细线程模型与访问模型参见 mutator_manager.hpp 的头注释。
class SchedulerManager {
public:
    SchedulerManager() = default;

    int AddEngine(std::unique_ptr<ISchedulerEngine> engine);
    bool SwitchEngineByName(std::string_view name);

    const core::EngineHandle<ISchedulerEngine>& Handle() const noexcept { return engine_handle_; }

    bool HasActive() const noexcept { return engine_handle_.HasValue(); }
    std::string ActiveEngineName() const;
    std::vector<std::string> EngineNames() const;

private:
    std::vector<std::unique_ptr<ISchedulerEngine>> engines_;
    std::unordered_map<std::string, int> engine_name_index_;

    core::EngineHandle<ISchedulerEngine> engine_handle_;
};

} // namespace refuzz::fuzzer
