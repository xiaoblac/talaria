#include "refuzz/mutator/mutator_manager.hpp"

#include <cassert>

namespace refuzz::fuzzer {

int MutatorManager::AddEngine(std::unique_ptr<IMutatorEngine> engine)
{
    return AddEngine(std::move(engine), /*activate=*/true);
}

int MutatorManager::AddEngine(std::unique_ptr<IMutatorEngine> engine, bool activate)
{
    if (!engine) {
        assert(false && "MutatorManager::AddEngine received null engine");
        return -1;
    }

    const std::string name = engine->Name();
    if (name.empty()) {
        assert(false && "MutatorManager::AddEngine received unnamed engine");
        return -1;
    }

    const auto existing = engine_name_index_.find(name);
    if (existing != engine_name_index_.end()) {
        return existing->second;
    }

    const int idx = static_cast<int>(engines_.size());
    engine_name_index_.emplace(name, idx);
    engines_.push_back(std::move(engine));
    if (activate && !engine_handle_.HasValue()) {
        engine_handle_.Store(engines_[idx].get());
    }
    return idx;
}

bool MutatorManager::SwitchEngineByName(std::string_view name)
{
    // 同步直写 handle：release 原子写。engine 实例常驻 engines_，
    // 并发读者在切换瞬间读到旧指针也安全；切换点之后的读都看到新 engine。
    const auto it = engine_name_index_.find(std::string(name));
    if (it == engine_name_index_.end()) {
        return false;
    }
    engine_handle_.Store(engines_[it->second].get());
    return true;
}

void MutatorManager::SetEnabledCalls(const std::vector<std::uint8_t>& enabled_mask)
{
    // Forward to every registered engine (each copies the mask + rebuilds).
    // Startup-only: no engine switching is in flight here.
    for (const auto& engine : engines_) {
        if (engine) {
            engine->SetEnabledCalls(enabled_mask);
        }
    }
}

std::string MutatorManager::ActiveEngineName() const
{
    // 通过 handle 读取当前 engine；无 active 时返回空串。
    if (auto* e = engine_handle_.TryGet(); e != nullptr) {
        return e->Name();
    }
    return {};
}

std::vector<std::string> MutatorManager::EngineNames() const
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
