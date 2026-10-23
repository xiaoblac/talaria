// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedMetadataSerdeRegistry —— durable Seed.metadata 类型的 JSON serde registry。
//
// 用途:`corpus_disk_io.cpp` `WriteMetadataSidecar` / `ReadMetadataSidecar` 通过
// 此 registry 走 metadata 部分的序列化,**不直接 include 具体 metadata 类型**。
// 每个 durable seed-state 类型在 builtin register 函数里挂自己的 Write/Read
// free function;后续 family / batch 加新 metadata 类型时 append 到同一 registry。
//
// 跟 transient `ExecutionObservation`(`feedback/observation/`) 区分:
//   - SeedMetadataSerdeRegistry = **durable seed state**,持久化到 metadata.json
//     跨 conversation(eg. SeedSourceMetadata / TriageStableSignalMetadata /
//     SeedAuditMetadata)。
//   - ExecutionObservation       = transient per-event observation,event 处理完
//     即消亡(详 feedback/include/refuzz/feedback/observation/execution_observation.hpp)。
//   两者**不**共享 registry — durable vs transient lifetime 完全不同。
//
// 设计要点:
//   - `Instance()` Meyers' singleton(避免 static-init 顺序坑)
//   - `Register(json_key, write_fn, read_fn)` **幂等**:同 json_key replace-in-place,
//     新 key append。这样 `RegisterBuiltinSeedMetadataSerdes()` 多次调用安全
//     (lazy 触发 + ResetForTest 后 lazy 重新触发都不冲突)。
//   - storage 用 ordered `std::vector<Entry>` 让 registry 自身遍历顺序确定;
//     **注意**:JSON object dump 输出顺序由 nlohmann 决定,不严格按插入顺序 —
//     "byte-equal" invariant 靠 schema(字段名 / 值格式 / enum 字符串)不变,
//     而非 vector 顺序本身。vector 选择是为 registry 自身 ordering 确定性。
//   - **不**用 static-init 自注册:静态库链接下未引用 TU 可能不进 binary,blocker。
//     改 explicit `RegisterBuiltinSeedMetadataSerdes()`,corpus_disk_io 内部
//     `WriteMetadataSidecar` / `ReadMetadataSidecar` 首句 lazy idempotent 调用。
//   - **不**用 `std::call_once` —— `ResetForTest()` 后 lazy 注册需要能恢复 builtin。
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-W3。

#pragma once

#include "refuzz/core/metadata.hpp"
#include "util/json.hpp"

#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

class SeedMetadataSerdeRegistry {
public:
    // Reader semantics:即便 root 不含本 entry 的 json_key,reader 仍被调用,
    // 让需要 fallback 的类型(eg. SeedSourceMetadata)写入默认值。reader 自己
    // 决定:跳过(typical)or 写 fallback(SeedSourceMetadata 唯一例外)。
    using WriteFn = std::function<void(const refuzz::core::MetadataMap&,
                                        nlohmann::json&)>;
    using ReadFn  = std::function<void(const nlohmann::json&,
                                        refuzz::core::MetadataMap&)>;

    static SeedMetadataSerdeRegistry& Instance();

    // 幂等:同 `json_key` replace-in-place(覆盖 write/read fn),新 key append。
    void Register(std::string json_key, WriteFn write_fn, ReadFn read_fn);

    // 按注册顺序调每个 entry 的 write_fn,把 meta 中 known 类型的字段写进 root。
    void WriteAll(const refuzz::core::MetadataMap& meta,
                  nlohmann::json&                  root) const;

    // 按注册顺序调每个 entry 的 read_fn — **每个 reader 必被调一次**,即便
    // root 缺失对应 json_key,让 reader 自己决定 fallback / skip。
    // root 允许是 null(missing-sidecar 场景),reader 自己 is_object() 判断。
    void ReadAll(const nlohmann::json&       root,
                 refuzz::core::MetadataMap&  meta) const;

    // 测试用:清空所有 entries,后续 Register 重新加。
    void ResetForTest();

    // 测试用:registry size。
    std::size_t Size() const;

    // builtin registry 的 reset-safe 显式装载入口。
    void EnsureBuiltinSeedMetadataSerdes();

private:
    struct Entry {
        std::string json_key;
        WriteFn     write_fn;
        ReadFn      read_fn;
    };

    void RegisterOrReplaceUnlocked(std::string json_key,
                                   WriteFn     write_fn,
                                   ReadFn      read_fn);

    mutable std::mutex mu_;
    std::vector<Entry> entries_;
    bool               builtins_registered_ = false;
};

// 把 builtin 3 种 durable seed metadata 类型(`TriageStableSignalMetadata` /
// `SeedAuditMetadata` / `SeedSourceMetadata`)注册进 SeedMetadataSerdeRegistry。
//
// 幂等:Register 同 json_key replace-in-place,多次调用安全(lazy 触发 +
// ResetForTest 后重新触发都 OK)。
//
// 触发时机:`corpus_disk_io.cpp` 的 `WriteMetadataSidecar` /
// `ReadMetadataSidecar` 首句调用(production 透明 init);test 需 reset 时
// 显式 `Instance().ResetForTest()`,后续 Write/Read 触发 lazy 重新注册。
void RegisterBuiltinSeedMetadataSerdes();

}  // namespace refuzz::fuzzer
