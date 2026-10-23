// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/orchestrator/profile_registry.hpp"

namespace refuzz::orchestrator {

ProfileRegistry& ProfileRegistry::Instance()
{
    static ProfileRegistry instance;
    return instance;
}

void ProfileRegistry::Register(profile::ProfileDefaults defaults)
{
    const std::string name = defaults.name;
    profiles_[name] = std::move(defaults);
}

const profile::ProfileDefaults* ProfileRegistry::Find(const std::string& name) const
{
    auto it = profiles_.find(name);
    if (it == profiles_.end()) {
        return nullptr;
    }
    return &it->second;
}

} // namespace refuzz::orchestrator
