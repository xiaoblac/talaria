#include "refuzz/scheduler/manager/scheduler_manager.hpp"

#include <cassert>

namespace refuzz::fuzzer {

int SchedulerManager::AddEngine(std::unique_ptr<ISchedulerEngine> engine)
{
    if (!engine) {
        assert(false && "SchedulerManager::AddEngine received null engine");
        return -1;
    }

    const std::string name = engine->Name();
    if (name.empty()) {
        assert(false && "SchedulerManager::AddEngine received unnamed engine");
        return -1;
    }

    const auto existing = engine_name_index_.find(name);
    if (existing != engine_name_index_.end()) {
        return existing->second;
    }

    const int idx = static_cast<int>(engines_.size());
    engine_name_index_.emplace(name, idx);
    engines_.push_back(std::move(engine));
    if (!engine_handle_.HasValue()) {
        engine_handle_.Store(engines_[idx].get());
    }
    return idx;
}

bool SchedulerManager::SwitchEngineByName(std::string_view name)
{
    const auto it = engine_name_index_.find(std::string(name));
    if (it == engine_name_index_.end()) {
        return false;
    }
    engine_handle_.Store(engines_[it->second].get());
    return true;
}

std::string SchedulerManager::ActiveEngineName() const
{
    if (auto* e = engine_handle_.TryGet(); e != nullptr) {
        return e->Name();
    }
    return {};
}

std::vector<std::string> SchedulerManager::EngineNames() const
{
    std::vector<std::string> names;
    names.reserve(engines_.size());
    for (const auto& engine : engines_) {
        if (engine) {
            names.push_back(engine->Name());
        }
    }
    return names;
}

} // namespace refuzz::fuzzer
