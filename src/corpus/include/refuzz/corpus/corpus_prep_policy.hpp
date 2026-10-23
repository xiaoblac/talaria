// Copyright 2026 reFuzz project author -------youngkk.
//
// CorpusPrepPolicy — corpus 加载/bootstrap 策略原语。
//
// 对应 multi-target-extension §4 第 7 项 smoothing 的"corpus prepare"层：
// 把 orchestrator 里硬编码的"decode 失败 → 保留 bytes-only seed"假设
// 显式化为 per-profile 策略。
//
// 边界规则（不可破）：
//   - enum 住 refuzz::fuzzer 命名空间（corpus 模块）
//   - ProfileDefaults（control/profile）可以 include 本头并引用 enum
//   - corpus 模块**不能**反向 include profile 头（否则形成循环依赖）
//
// 当前 PR1 范围：仅 CorpusLoadPolicy + CountArtifactSeeds。
// PR2 在 control/profile 侧扩展 BootstrapTrigger / CorpusPrepConfig，
// 不再来动本头。

#pragma once

#include <cstddef>

namespace refuzz::fuzzer {

class ICorpusStore;  // forward decl 避免拉 interfaces.hpp 进 profile 编译图

// 决定 CorpusDiskIO::LoadAll / LoadCrashRepros 在 decode 失败时的行为。
//
// 语义：
//   StrictTyped   — 要求 caller 提供 materializer，且 materializer 必须
//                   返回非空 artifact；否则该 seed 整个 drop（不分配
//                   seed_id、不调 OnSeedAdded、不入 store）。
//                   适用于：syz/v2、SQL parse、compiler source 等"必须能
//                   decode 才算合法 corpus"的 profile。
//
//   LenientBytes  — decode 失败（含 materializer 缺失）时退化为 bytes-only
//                   seed，照常入 store；保留 v1 行为。
//                   适用于：AFL 风格 opaque bytes、raw_bytes_artifact target。
enum class CorpusLoadPolicy : unsigned char {
    StrictTyped,
    LenientBytes,
};

// 数 store 中 seed.artifact != nullptr 的个数。
//
// 用于 orch bootstrap 谓词："typed/raw materialized 形态的 seed 是否为零"。
// 替换原先 ICorpusStore::Size() == 0 的判定，避免 bytes-only 僵尸 seed
// 阻断 bootstrap。命名取 "Artifact" 而非 "Typed"——raw_bytes_artifact 也
// 持 artifact，"typed" 会让 AFL/raw 场景语义混。
size_t CountArtifactSeeds(const ICorpusStore& store);

} // namespace refuzz::fuzzer
