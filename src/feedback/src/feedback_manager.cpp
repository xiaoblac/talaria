#include "refuzz/feedback/feedback_engine.hpp"

#include <cassert>

namespace refuzz::fuzzer {

int FeedbackManager::AddEngine(std::unique_ptr<IFeedbackEngine> engine)
{
    if (!engine) {
        assert(false && "FeedbackManager::AddEngine received null engine");
        return -1;
    }

    const std::string name = engine->Name();
    if (name.empty()) {
        assert(false && "FeedbackManager::AddEngine received unnamed engine");
        return -1;
    }

    // 同名 engine 返回已有索引：避免旧 engine 被 name_index_ 遮蔽但仍占槽位
    // 造成的内存泄漏 + 状态错乱。与 MutatorManager / SchedulerManager 对齐。
    const auto existing = name_index_.find(name);
    if (existing != name_index_.end()) {
        return existing->second;
    }

    const int idx = static_cast<int>(engines_.size());
    name_index_.emplace(name, idx);
    engines_.push_back(std::move(engine));
    if (!engine_handle_.HasValue()) {
        engine_handle_.Store(engines_[idx].get());
    }
    return idx;
}

bool FeedbackManager::SwitchEngineByName(std::string_view name)
{
    const auto it = name_index_.find(std::string(name));
    if (it == name_index_.end()) {
        return false;
    }
    engine_handle_.Store(engines_[it->second].get());
    return true;
}

std::string FeedbackManager::ActiveEngineName() const
{
    if (auto* e = engine_handle_.TryGet(); e != nullptr) {
        return e->Name();
    }
    return {};
}

std::vector<std::string> FeedbackManager::EngineNames() const
{
    std::vector<std::string> out;
    out.reserve(engines_.size());
    for (const auto& e : engines_) {
        out.push_back(e ? e->Name() : std::string{});
    }
    return out;
}

} // namespace refuzz::fuzzer
