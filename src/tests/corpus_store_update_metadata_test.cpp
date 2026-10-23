// corpus_store_update_metadata_test.cpp
//
// [v2 batch 3 G6] InMemoryCorpusStore::UpdateSeedMetadata 单测:
//   1. UpdateSeedMetadata copy-on-write — mutate 后旧 SeedHandle 不见新值,
//      新 GetSeed 拿到新值
//   2. seed_id 不存在 → return false
//   3. callback null → return false
//   4. 多次 update 累积语义(verify_attempts bump)
//   5. metadata 拷贝时其它字段(payload / artifact)指针/内容不变

#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/seed_metadata.hpp"

#include <cassert>
#include <cstdio>
#include <memory>
#include <vector>

namespace {

using refuzz::core::MetadataMap;
using refuzz::fuzzer::InMemoryCorpusStore;
using refuzz::fuzzer::Seed;
using refuzz::fuzzer::SeedAdmissionState;
using refuzz::fuzzer::SeedAdmissionStateMetadata;

Seed MakeSeed(std::uint64_t id, std::vector<std::uint8_t> payload = {0xAA})
{
    Seed s;
    s.seed_id = id;
    s.payload = std::move(payload);
    return s;
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running corpus_store_update_metadata_test...\n");

    // ── Case 1: copy-on-write — old handle 不变,new GetSeed 看到新值 ───────
    {
        InMemoryCorpusStore store;
        assert(store.AddSeed(MakeSeed(1)));

        // 拿 old handle(指向 mutate 前的 Seed 对象)
        auto old_handle = store.GetSeed(1);
        assert(old_handle != nullptr);
        assert(old_handle->metadata.Get<SeedAdmissionStateMetadata>() == nullptr);

        // mutate metadata
        const bool ok = store.UpdateSeedMetadata(1, [](MetadataMap& meta) {
            SeedAdmissionStateMetadata admit;
            admit.state           = SeedAdmissionState::kInactive;
            admit.inactive_reason = "test_reason";
            admit.verify_attempts = 5;
            meta.Set(std::move(admit));
        });
        assert(ok);

        // old handle 仍指向旧 Seed —— metadata 还是空(copy-on-write)
        assert(old_handle->metadata.Get<SeedAdmissionStateMetadata>() == nullptr);

        // new GetSeed 拿到新 Seed —— metadata 已设
        auto new_handle = store.GetSeed(1);
        assert(new_handle != nullptr);
        assert(new_handle.get() != old_handle.get());  // 不同 shared_ptr 实体
        const auto* admit = new_handle->metadata.Get<SeedAdmissionStateMetadata>();
        assert(admit != nullptr);
        assert(admit->state == SeedAdmissionState::kInactive);
        assert(admit->inactive_reason == "test_reason");
        assert(admit->verify_attempts == 5);
    }

    // ── Case 2: seed_id 不存在 → return false ──────────────────────────────
    {
        InMemoryCorpusStore store;
        const bool ok = store.UpdateSeedMetadata(999, [](MetadataMap&) {});
        assert(!ok);
    }

    // ── Case 3: callback null → return false ───────────────────────────────
    {
        InMemoryCorpusStore store;
        assert(store.AddSeed(MakeSeed(1)));
        const bool ok = store.UpdateSeedMetadata(1, nullptr);
        assert(!ok);
    }

    // ── Case 4: 多次 update 累积(bump verify_attempts)─────────────────────
    {
        InMemoryCorpusStore store;
        assert(store.AddSeed(MakeSeed(1)));

        for (std::uint32_t expected = 1; expected <= 3; ++expected) {
            const bool ok = store.UpdateSeedMetadata(1, [expected](MetadataMap& meta) {
                SeedAdmissionStateMetadata admit;
                if (const auto* old = meta.Get<SeedAdmissionStateMetadata>()) {
                    admit = *old;
                }
                admit.verify_attempts = expected;
                meta.Set(std::move(admit));
            });
            assert(ok);

            auto handle = store.GetSeed(1);
            assert(handle != nullptr);
            const auto* admit = handle->metadata.Get<SeedAdmissionStateMetadata>();
            assert(admit != nullptr);
            assert(admit->verify_attempts == expected);
        }
    }

    // ── Case 5: 其它字段(payload / artifact)在 update 后保留 ───────────────
    {
        InMemoryCorpusStore store;
        std::vector<std::uint8_t> initial_payload = {0x11, 0x22, 0x33};
        Seed s = MakeSeed(1, initial_payload);
        s.priority         = 7;
        s.interesting_hits = 13;
        assert(store.AddSeed(std::move(s)));

        store.UpdateSeedMetadata(1, [](MetadataMap& meta) {
            SeedAdmissionStateMetadata admit;
            admit.state = SeedAdmissionState::kInactive;
            meta.Set(std::move(admit));
        });

        auto handle = store.GetSeed(1);
        assert(handle != nullptr);
        assert(handle->payload == initial_payload);
        assert(handle->priority         == 7);
        assert(handle->interesting_hits == 13);
        const auto* admit = handle->metadata.Get<SeedAdmissionStateMetadata>();
        assert(admit != nullptr);
        assert(admit->state == SeedAdmissionState::kInactive);
    }

    return 0;
}
