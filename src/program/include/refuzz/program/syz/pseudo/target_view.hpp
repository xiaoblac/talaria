#pragma once

// Worker-facing pseudo target view: PseudoMeta / SyzTargetTables +
// resolution helpers, consumed by executor/channel/worker/ for
// syz_*/pseudo dispatch.
//
// `kSyzMaxArgs` / `kCompatFlatMaxArgs` are split into
// `pseudo/limits.hpp` so callers that only need the bare numeric
// limits avoid pulling in the full PseudoMeta / SyzTargetTables
// surface; this header transitively re-exports them.
//
// V2 typed schema lives in
// `program/include/refuzz/program/syz/target.hpp` and pins the same
// pseudo metadata table via Target::finalize() invariants.

#include "refuzz/program/syz/pseudo/limits.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace refuzz::fuzzer::syz {

enum class PseudoDomain : uint8_t {
    kUnknown = 0,
    kCore    = 1,
    kFs      = 2,
    kNet     = 3,
    kKvm     = 4,
    kUsb     = 5,
    kFuse    = 6,
    kFile    = 7,
    kDevice  = 8,
    kBpf     = 9,
    kIo      = 10,
    kCrypto  = 11,
    kInputUi = 12,
    // [PR-D1 — 加 kMount,Tier 3 mount-image family 走独立 subdir
    // pseudo/mount/ (per plan §5.2). 与 kFs 区分:kFs 处理
    // syz_read_part_table 等单点 fs pseudo;kMount 是带 loop device +
    // mount lifecycle state machine 的 mount-image 家族。]
    kMount   = 13,
    kCount,
};

enum class PseudoConcurrency : uint8_t {
    kNotConcurrentSafe = 0,
    kConcurrentSafe    = 1,
};

struct PseudoMeta {
    uint64_t          nr;
    const char*       name;
    uint32_t          arg_count;
    PseudoDomain      domain;
    uint32_t          args_type_idx[kSyzMaxArgs];
    PseudoConcurrency concurrency = PseudoConcurrency::kNotConcurrentSafe;
};

struct PseudoMetaTable {
    uint64_t          base;
    const PseudoMeta* entries;
    size_t            size;
};

struct SyzTargetId {
    const char* os;
    const char* arch;
};

struct SyzTargetTables {
    SyzTargetId          id;
    uint64_t             pseudo_nr_base;
    uint64_t             max_real_nr;
    PseudoMetaTable      pseudos;
};

enum class ResolvedCallKind : uint8_t {
    kMissing = 0,
    kPseudo  = 1,
};

struct ResolvedCall {
    ResolvedCallKind  kind   = ResolvedCallKind::kMissing;
    const PseudoMeta* pseudo = nullptr;
};

extern const PseudoMeta   kLinuxAmd64PseudoMeta[];
extern const size_t       kLinuxAmd64PseudoMetaSize;
extern const uint64_t     kLinuxAmd64PseudoNrBase;

extern const SyzTargetTables kLinuxAmd64Target;
extern const SyzTargetTables kDefaultSyzTarget;

inline const PseudoMeta* FindPseudoByName(const PseudoMetaTable& table, const char* name)
{
    if (name == nullptr || table.entries == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < table.size; ++i) {
        if (table.entries[i].name != nullptr && std::strcmp(table.entries[i].name, name) == 0) {
            return &table.entries[i];
        }
    }
    return nullptr;
}

inline const PseudoMeta* FindPseudoByNr(const PseudoMetaTable& table, uint64_t nr)
{
    if (nr < table.base || table.entries == nullptr) {
        return nullptr;
    }
    const uint64_t idx = nr - table.base;
    if (idx >= table.size) {
        return nullptr;
    }
    const PseudoMeta& meta = table.entries[idx];
    return meta.nr == nr ? &meta : nullptr;
}

inline ResolvedCall ResolveSyzCallByName(const SyzTargetTables& target, const char* name)
{
    if (const PseudoMeta* pseudo = FindPseudoByName(target.pseudos, name)) {
        return {ResolvedCallKind::kPseudo, pseudo};
    }
    return {};
}

inline ResolvedCall ResolveSyzCallByNr(const SyzTargetTables& target, uint64_t nr)
{
    if (const PseudoMeta* pseudo = FindPseudoByNr(target.pseudos, nr)) {
        return {ResolvedCallKind::kPseudo, pseudo};
    }
    return {};
}

} // namespace refuzz::fuzzer::syz
