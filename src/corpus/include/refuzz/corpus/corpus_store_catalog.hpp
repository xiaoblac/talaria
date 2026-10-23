// Copyright 2026 reFuzz project author -------youngkk.
//
// CorpusStoreCatalog — 语料库存储后端的注册表。
//
// 对应 LaunchPlan/Resolver/Assembler 的 corpus_store 这一环：
//   LaunchPlan.corpus_store (id)
//       → ProfileDefaults 填空
//       → Assembler 按 id 构造 ICorpusStore 实例并注入 FuzzerLoop / 其他依赖方
//
// 当前只有一个 "in_memory" 后端；把它 catalog 化是为了将来可加
// "mmap_file" / "sqlite" 等持久化实现时，装配层零改动只需加一个 Entry。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/fuzzer/interfaces.hpp"

namespace refuzz::fuzzer {

struct CorpusStoreTraits {
    using Product = ICorpusStore;

    // 当前 in_memory 实现零外部依赖；预留 BuildContext 以支持将来
    // "disk 后端需要持久化路径"、"mmap 后端需要容量" 等参数。
    struct BuildContext {};
};

using CorpusStoreCatalog = refuzz::catalog::TypedCatalog<CorpusStoreTraits>;

// 注册内置 corpus store 后端。
//   "in_memory" — InMemoryCorpusStore
void RegisterBuiltinCorpusStores(CorpusStoreCatalog& catalog);

} // namespace refuzz::fuzzer
