// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/corpus/corpus_store_catalog.hpp"

#include "refuzz/corpus/corpus_store.hpp"

#include <memory>

namespace refuzz::fuzzer {

void RegisterBuiltinCorpusStores(CorpusStoreCatalog& catalog)
{
    CorpusStoreCatalog::Entry entry;
    entry.meta = {
        "in_memory",
        "In-Memory Corpus",
        "Hash-indexed in-memory seed store (non-persistent)",
    };
    entry.build = [](const CorpusStoreTraits::BuildContext& /*ctx*/)
        -> core::Result<std::unique_ptr<ICorpusStore>> {
        return std::make_unique<InMemoryCorpusStore>();
    };
    catalog.Register(std::move(entry));
}

} // namespace refuzz::fuzzer
