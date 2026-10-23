// seed_metadata_serde_registry_test.cpp
//
// [v2 batch 3 PR-W3] SeedMetadataSerdeRegistry 单测:
//   - Register 幂等 + replace-in-place + new key append
//   - Ordered iteration (vector 顺序)
//   - WriteAll / ReadAll 调用所有 entry
//   - ResetForTest + 重新触发 RegisterBuiltinSeedMetadataSerdes
//   - 自定义 fake metadata 类型 round-trip
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-W3。

#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/seed_metadata_serde.hpp"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

// 自定义 fake metadata 类型 — 验证 registry 不依赖 builtin。
struct FakeMetadata {
    int         a = 0;
    std::string b;
};

void WriteFake(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* f = meta.Get<FakeMetadata>()) {
        nlohmann::json j;
        j["a"] = f->a;
        j["b"] = f->b;
        root["fake"] = std::move(j);
    }
}

void ReadFake(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("fake") || !root["fake"].is_object()) {
        return;
    }
    const auto& j = root["fake"];
    FakeMetadata f;
    if (j.contains("a") && j["a"].is_number_integer()) f.a = j["a"].get<int>();
    if (j.contains("b") && j["b"].is_string())          f.b = j["b"].get<std::string>();
    meta.Set(std::move(f));
}

// 第二版 writer/reader,验证 replace-in-place(覆盖前一个)。
void WriteFakeV2(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* f = meta.Get<FakeMetadata>()) {
        // V2 写一个 "tag" 字段做区分。
        nlohmann::json j;
        j["tag"] = "v2";
        j["a"]   = f->a + 1000;  // V2 故意 transform value
        root["fake"] = std::move(j);
    }
}

void ReadFakeV2(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("fake")) return;
    const auto& j = root["fake"];
    FakeMetadata f;
    if (j.contains("a") && j["a"].is_number_integer()) f.a = j["a"].get<int>();
    meta.Set(std::move(f));
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running seed_metadata_serde_registry_test...\n");

    using Registry = refuzz::fuzzer::SeedMetadataSerdeRegistry;

    // ── Case 1: Register / WriteAll / ReadAll round-trip with fake metadata ─
    {
        Registry::Instance().ResetForTest();
        assert(Registry::Instance().Size() == 0);

        Registry::Instance().Register("fake", &WriteFake, &ReadFake);
        assert(Registry::Instance().Size() == 1);

        refuzz::core::MetadataMap m;
        m.Set(FakeMetadata{42, "hello"});

        nlohmann::json root;
        Registry::Instance().WriteAll(m, root);
        assert(root.is_object());
        assert(root.contains("fake"));
        assert(root["fake"]["a"] == 42);
        assert(root["fake"]["b"] == "hello");

        refuzz::core::MetadataMap loaded;
        Registry::Instance().ReadAll(root, loaded);
        const auto* f = loaded.Get<FakeMetadata>();
        assert(f != nullptr);
        assert(f->a == 42);
        assert(f->b == "hello");
    }

    // ── Case 2: Register replace-in-place(同 json_key 覆盖)──────────────
    {
        Registry::Instance().ResetForTest();
        Registry::Instance().Register("fake", &WriteFake,   &ReadFake);
        Registry::Instance().Register("fake", &WriteFakeV2, &ReadFakeV2);  // 覆盖
        assert(Registry::Instance().Size() == 1);  // 不是 2 — replace-in-place

        refuzz::core::MetadataMap m;
        m.Set(FakeMetadata{10, "ignored_by_v2"});

        nlohmann::json root;
        Registry::Instance().WriteAll(m, root);
        // V2 writer 应被调用,带 tag + transform a。
        assert(root["fake"]["tag"] == "v2");
        assert(root["fake"]["a"] == 1010);  // V2 加 1000

        refuzz::core::MetadataMap loaded;
        Registry::Instance().ReadAll(root, loaded);
        const auto* f = loaded.Get<FakeMetadata>();
        assert(f != nullptr);
        assert(f->a == 1010);  // V2 reader 读到 V2 写的值
    }

    // ── Case 3: 多 entry append + ordered iteration ──────────────────────
    {
        Registry::Instance().ResetForTest();
        std::vector<std::string> visited;
        auto write_a = [&visited](const refuzz::core::MetadataMap&,
                                  nlohmann::json& root) {
            visited.push_back("a");
            root["fake_a"] = 1;
        };
        auto write_b = [&visited](const refuzz::core::MetadataMap&,
                                  nlohmann::json& root) {
            visited.push_back("b");
            root["fake_b"] = 2;
        };
        auto write_c = [&visited](const refuzz::core::MetadataMap&,
                                  nlohmann::json& root) {
            visited.push_back("c");
            root["fake_c"] = 3;
        };
        auto read_noop = [](const nlohmann::json&, refuzz::core::MetadataMap&) {};

        Registry::Instance().Register("fake_a", write_a, read_noop);
        Registry::Instance().Register("fake_b", write_b, read_noop);
        Registry::Instance().Register("fake_c", write_c, read_noop);
        assert(Registry::Instance().Size() == 3);

        // 这里靠 writer side-effect 观测真实遍历顺序；不能用 JSON key 顺序证明，
        // 因为 nlohmann::json object 默认按 key 排序。
        refuzz::core::MetadataMap m;
        nlohmann::json root;
        Registry::Instance().WriteAll(m, root);
        assert((visited == std::vector<std::string>{"a", "b", "c"}));
        assert(root["fake_a"] == 1);
        assert(root["fake_b"] == 2);
        assert(root["fake_c"] == 3);
    }

    // ── Case 4: ResetForTest + 重新触发 RegisterBuiltinSeedMetadataSerdes ─
    {
        Registry::Instance().ResetForTest();
        assert(Registry::Instance().Size() == 0);

        refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();
        // [v2 batch 3 G6] 4 个 builtin + [Task A/F2] corpus_coverage = 5 个:
        // triage_stable_signal / audit / seed_source / seed_admission_state / corpus_coverage
        // (corpus_coverage 持久化 corpus-admitted full cover,见 seed_metadata_serde.cpp:409)。
        assert(Registry::Instance().Size() == 5);

        // 再调一次 — 幂等(replace-in-place,size 不变)。
        refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();
        assert(Registry::Instance().Size() == 5);

        // builtin reader 应正确读回写。
        refuzz::core::MetadataMap m;
        m.Set(refuzz::fuzzer::SeedSourceMetadata{
            refuzz::fuzzer::SeedSource::kFaultHistory, /*attempt=*/5});
        refuzz::fuzzer::TriageStableSignalMetadata stable;
        stable.hashes = {0xAA, 0xBB};
        stable.guilty_call_index = 1;
        stable.guilty_call_hashes = {0xBB};
        stable.exec_status = refuzz::proto::ResultCode::kOk;
        stable.guilty_errno_value = 0;
        stable.guilty_syscall_id = 123;
        m.Set(std::move(stable));

        nlohmann::json root;
        Registry::Instance().WriteAll(m, root);
        assert(root["seed_source"]["source"] == "fault_history");
        assert(root["seed_source"]["attempt"] == 5u);
        assert(root["triage_stable_signal"]["hashes"].is_array());
        assert(root["triage_stable_signal"]["guilty_call_index"] == 1);
        assert(root["triage_stable_signal"]["guilty_call_hashes"].is_array());
        assert(root["triage_stable_signal"]["exec_status"] == 0);
        assert(root["triage_stable_signal"]["guilty_errno_value"] == 0);
        assert(root["triage_stable_signal"]["guilty_syscall_id"] == 123u);

        refuzz::core::MetadataMap loaded;
        Registry::Instance().ReadAll(root, loaded);
        const auto* s = loaded.Get<refuzz::fuzzer::SeedSourceMetadata>();
        assert(s != nullptr);
        assert(s->source == refuzz::fuzzer::SeedSource::kFaultHistory);
        assert(s->attempt == 5);
        const auto* loaded_stable =
            loaded.Get<refuzz::fuzzer::TriageStableSignalMetadata>();
        assert(loaded_stable != nullptr);
        assert(loaded_stable->guilty_call_index == 1);
        assert((loaded_stable->guilty_call_hashes == std::vector<std::uint64_t>{0xBB}));
        assert(loaded_stable->exec_status.has_value());
        assert(*loaded_stable->exec_status == refuzz::proto::ResultCode::kOk);
        assert(loaded_stable->guilty_errno_value.has_value());
        assert(*loaded_stable->guilty_errno_value == 0);
        assert(loaded_stable->guilty_syscall_id.has_value());
        assert(*loaded_stable->guilty_syscall_id == 123);
    }

    // ── Case 5: missing seed_source 不再由 serde 隐式补默认值 ───────────
    {
        Registry::Instance().ResetForTest();
        refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();

        nlohmann::json root;  // 空 — 没任何 metadata 字段
        root["something_unrelated"] = 42;

        refuzz::core::MetadataMap meta;
        Registry::Instance().ReadAll(root, meta);

        assert(meta.Get<refuzz::fuzzer::SeedSourceMetadata>() == nullptr);
        assert(meta.Get<refuzz::fuzzer::SeedAdmissionStateMetadata>() == nullptr);
        assert(meta.Get<refuzz::fuzzer::TriageStableSignalMetadata>() == nullptr);
        assert(meta.Get<refuzz::fuzzer::SeedAuditMetadata>() == nullptr);
    }

    // ── Case 6: null root 不能静默合成 runtime metadata ────────────────
    {
        Registry::Instance().ResetForTest();
        refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();

        nlohmann::json null_root;  // default-init = json::null
        refuzz::core::MetadataMap meta;
        Registry::Instance().ReadAll(null_root, meta);

        assert(meta.Get<refuzz::fuzzer::SeedSourceMetadata>() == nullptr);
        assert(meta.Get<refuzz::fuzzer::SeedAdmissionStateMetadata>() == nullptr);
    }

    // ── Case 7: unknown enum string 不映射到默认值 ─────────────────────
    {
        Registry::Instance().ResetForTest();
        refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();

        nlohmann::json root;
        root["seed_source"] = {{"source", "bad_source"}, {"attempt", 7}};
        root["seed_admission_state"] = {
            {"state", "bad_state"},
            {"inactive_reason", ""},
            {"verify_attempts", 0},
        };

        refuzz::core::MetadataMap meta;
        Registry::Instance().ReadAll(root, meta);

        assert(meta.Get<refuzz::fuzzer::SeedSourceMetadata>() == nullptr);
        assert(meta.Get<refuzz::fuzzer::SeedAdmissionStateMetadata>() == nullptr);
    }

    // ── 收尾:还原 builtin,让后续 test 不受 ResetForTest 影响 ─────────────
    Registry::Instance().ResetForTest();
    refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();

    return 0;
}
