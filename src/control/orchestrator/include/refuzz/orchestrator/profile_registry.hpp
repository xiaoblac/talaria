// Copyright 2026 reFuzz project author -------youngkk.
//
// ProfileRegistry
//
// 内置 profile(ProfileDefaults)的名字 → 结构体的查找表。
//
// 与旧实现的区别:
//   * 不再使用 REGISTER_PROFILE 静态初始化宏。
//   * 不再需要链接时的 `-Wl,--whole-archive` 保留翻译单元副作用。
//   * 所有内置 profile 通过 profile::RegisterBuiltinProfiles(registry)
//     在 Orchestrator::Build() 入口显式注入。
//
// 设计原则:ProfileRegistry 只认 ProfileDefaults(由 profile 模块定义),
// orchestrator 模块对"具体 target 是什么"不再耦合。

#pragma once

#include "refuzz/profile/profile_defaults.hpp"

#include <string>
#include <unordered_map>

namespace refuzz::orchestrator {

class ProfileRegistry {
public:
    ProfileRegistry() = default;

    // 全局默认实例。单元测试可直接实例化一个本地 ProfileRegistry,
    // 无需依赖全局状态。
    static ProfileRegistry& Instance();

    // 注册一个 profile。重复注册同名 profile 会覆盖(方便测试覆盖 mock)。
    void Register(profile::ProfileDefaults defaults);

    // 按名称查找 profile,未找到返回 nullptr。
    const profile::ProfileDefaults* Find(const std::string& name) const;

private:
    std::unordered_map<std::string, profile::ProfileDefaults> profiles_;
};

} // namespace refuzz::orchestrator
