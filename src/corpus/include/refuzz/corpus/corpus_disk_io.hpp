#pragma once

#include "refuzz/corpus/corpus_prep_policy.hpp"        // [v2 PR1] CorpusLoadPolicy
#include "refuzz/corpus/seed_id_allocator.hpp"
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/program/artifact_materializer.hpp"   // ArtifactMaterializerFn
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

class CorpusDiskIO {
public:
    // 将单个 seed 写入 <corpus_dir>/<hex16(seed_id)>/payload.bin。
    // 幂等：文件存在直接跳过。SaveSeed 与格式无关：当 seed.artifact 非
    // 空时通过 MaterializeCanonicalText（artifact 自带 lazy provider）
    // 取 bytes；否则使用 seed.payload。
    static bool SaveSeed(const Seed& seed, const std::string& corpus_dir);

    // [v2 batch 3 G6] **强制重写** seed 的 metadata.json sidecar(不动 payload)。
    // SaveSeed 的 idempotent 语义("payload+metadata 都存在 → 早返 true")在
    // G6 corpus_verify_consumer 写 SeedAdmissionState=kInactive 路径下会**漏写**;
    // 此函数显式 force-rewrite,跑 atomic .tmp + rename。
    // 调用方:`corpus_verify_consumer` 在 metadata mutation 后持久化;不要在
    // 普通 admit 路径用(SaveSeed 已处理)。
    // 返 false:目录不存在/写失败;调用方应 log warn 但不 fatal。
    static bool SaveSeedMetadata(const Seed& seed, const std::string& corpus_dir);

    // [persist-at-shutdown / P4] Flush the whole in-memory corpus to disk in one
    // pass (ForEachSeed → SaveSeed). Called once at FuzzerLoop shutdown rather
    // than per-admit on the hot path; disk then holds exactly the final
    // (post-minimization) corpus. Returns the number of seeds that failed to save.
    static size_t SaveAll(const ICorpusStore& store, const std::string& corpus_dir);

    // 扫描 <corpus_dir>/*/payload.bin 并加载到 corpus store，并向 scheduler 注册 seed。
    //
    // §3.10 follow-up — corpus 不再硬编码格式。可选 `materializer` 把
    // bytes 物化成 ProgramArtifact；为空时仅装载 bytes，seed.artifact
    // 留 null（v1 兼容路径）。生产路径由 orchestrator 按 profile 声明的
    // (format, target) 通过 `MakeRegistryMaterializer(...)` 构造。
    //
    // [v2 PR1 — Corpus Prep Smoothing] 新增 `load_policy` 参数：
    //   - StrictTyped  — materializer 缺失或返回 null 时整 seed 丢弃，不
    //                    分配 seed_id、不通知 scheduler；syz/v2 等 profile 用
    //   - LenientBytes — 默认；decode 失败退化为 bytes-only seed（v1 行为）
    static size_t LoadAll(ICorpusStore&                              store,
                          ISchedulerEngine&                          scheduler,
                          const std::string&                         corpus_dir,
                          SeedIdAllocator&                           id_alloc,
                          ::refuzz::program::ArtifactMaterializerFn  materializer = {},
                          CorpusLoadPolicy                           load_policy  = CorpusLoadPolicy::LenientBytes);

    // [candidate-model] 像 LoadAll 一样扫描 <corpus_dir>/*/payload.bin 并物化成
    // Seed 列表,但 **不** 插入 store / scheduler —— 返回构造好的 candidate 交由
    // 调用方(control 层)路由进 PendingSeedMap。实现 syzkaller 的
    // candidate-triage-on-load:boot corpus 先当 candidate,经 verify→minimize→
    // admit 才正式入 corpus(corpus 从 ~0 长起,与 syz 同构;不再"加载即全留")。
    // 不在 corpus/ 层 Put 进 pending 是因为 PendingSeedMap 住在 control/ 层。
    // load_policy 语义同 LoadAll。
    static std::vector<Seed> LoadAllAsSeeds(
        const std::string&                         corpus_dir,
        SeedIdAllocator&                           id_alloc,
        ::refuzz::program::ArtifactMaterializerFn  materializer = {},
        CorpusLoadPolicy                           load_policy  = CorpusLoadPolicy::LenientBytes);

    // 扫描 <diagnostics_dir>/*/prog0.bin 并作为 seed 加载。
    // load_policy 语义同 LoadAll；syz/v2 profile 应显式传 StrictTyped 与
    // LoadAll 对称，避免 crash repro 变成新的 bytes-only 僵尸入口。
    static size_t LoadCrashRepros(ICorpusStore&                              store,
                                  ISchedulerEngine&                          scheduler,
                                  const std::string&                         diagnostics_dir,
                                  SeedIdAllocator&                           id_alloc,
                                  ::refuzz::program::ArtifactMaterializerFn  materializer = {},
                                  CorpusLoadPolicy                           load_policy  = CorpusLoadPolicy::LenientBytes);
};

} // namespace refuzz::fuzzer
