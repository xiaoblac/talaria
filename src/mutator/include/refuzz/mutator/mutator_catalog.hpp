// Copyright 2026 reFuzz project author -------youngkk.
//
// MutatorEngineCatalog — 变异 engine 的注册表。
//
// 对应 control 模块 LaunchPlan/Resolver/Assembler 注册模式中"按 id 查表装配"
// 的 mutator 这一环：
//   LaunchPlan.mutator_engine (id)
//       → ProfileDefaults 填空
//       → Assembler 遍历 catalog.All() 构造所有 engine 注入 MutatorManager
//       → Assembler 调用 manager->SwitchEngineByName(resolved.mutator_engine)
//
// 仅注册到"engine 粒度"：engine 内部 policy 依据 DESIGN.md §1 §2 的
// "engine 自治管理 policy 生命周期" 原则，不进入 catalog。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

class ICorpusStore;

struct MutatorEngineTraits {
    using Product = IMutatorEngine;

    struct BuildContext {
        ICorpusStore* corpus_store = nullptr;
        // [syscall-enable-whitelist + syscall-support-detection] The resolved
        // per-id enabled mask (whitelist ∩ supported), computed host-side by
        // control/support and threaded in by the assembler. Empty = no filter.
        std::vector<std::uint8_t> enabled_calls_mask;
    };
};

using MutatorEngineCatalog = refuzz::catalog::TypedCatalog<MutatorEngineTraits>;

// 注册内置 engine 到 catalog。
//
// 注册 id 必须与对应 engine 类 Name() 返回值严格一致，以保证
// MutatorManager::SwitchEngineByName(resolved_id) 能路由到正确 engine：
//   "syz"        ↔ SyzV2MutatorEngine::Name()
void RegisterBuiltinMutatorEngines(MutatorEngineCatalog& catalog);

} // namespace refuzz::fuzzer
