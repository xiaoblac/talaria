// Copyright 2026 reFuzz project author -------youngkk.
//
// ProfileDefaults
//
// 替代旧的 orchestrator::TargetProfile。在新架构下,profile 提供 "这个 target
// 下要怎样把 Catalog 组合到一起" + 持有 framework primitive factory:
//
//   1. defaults                     — 该 profile 下"每个组件选哪个 id"的默认建议。
//                                      用户 LaunchPlan 里没显式选的字段,Resolver 按此填空。
//   2. configure                    — target-specific 的 OrchestratorConfig 注入,
//                                      如 kernel profile 按 sanitizer 模式给 kernel cmdline 追加参数。
//   3. validate                     — target-specific 校验(如 kernel profile 要求
//                                      execution_mode=kKernelSyscall、channel_backend 为 QEMU 形态)。
//   4. derive_repro_channel_cfg     — 按 profile 语义派生 per-VM repro channel 配置,
//                                      用于独立 repro VM。签名里没有 catalog 可以承担这层
//                                      "组合级策略"——shm/doorbell 后缀、vm_id 派生、资源降配
//                                      都是 target 知识,不是 Channel backend 知识。
//   5. make_stability_oracle / make_retry_policy(K5 + batch 3 PR-W1 fail-loud)
//                                  — framework primitive factory:profile 自报怎么造
//                                      `IStabilityOracle` / `IRetryPolicy` 等 framework primitive。
//                                      Assembler 装配时调 factory 构造对应 primitive,profile
//                                      missing factory → ComponentError(P7 fail-loud,不 silent
//                                      fallback)。详父 plan §2 P7 + framework primitive injection
//                                      canon + [`300_batch3_*.md`](../../../../docs/admit-pipeline-alignment/
//                                      300_batch3_kernel_profile_stages.md) §3.Phase A.PR-W1。
//                                      未来 SubT-PR-Y / 批次 3+ 后续所有 IXxx primitive 沿用此 pattern。
//
// channel / crash / repro / seed 等组件构造已下沉到各领域 Catalog;profile 通过
// `defaults.<id>` 间接选用,不是直接持工厂。framework primitive(stability_oracle /
// retry_policy / 后续 priority_calculator / saturation_filter 等)是 profile 自报
// "该 family 怎么解释信号 / 重试 / 优先级" 的策略层,跟 Catalog 组件不同档,所以
// profile 直接持 factory(see 上面 5)。
//
// ProfileDefaults 由 MakeXxxProfile() 纯函数构造,profile::RegisterBuiltinProfiles()
// 汇总注册到 orchestrator::ProfileRegistry——普通函数调用,不再使用静态初始化宏,
// 也不需要 -Wl,--whole-archive 链接黑魔法。

#pragma once

#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/factory/channel_assembler.hpp"       // ChannelConfig
#include "refuzz/channel/factory/channel_backend_profile.hpp" // IChannelBackendProfile
#include "refuzz/core/error.hpp"
#include "refuzz/corpus/corpus_prep_policy.hpp"               // [v2 PR2] CorpusLoadPolicy
#include "refuzz/orchestrator/orchestrator_config.hpp"
#include "refuzz/program/artifact_materializer.hpp"           // [v2 PR2] ArtifactMaterializerFn
#include "refuzz/startup/launch_plan.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

// [v2 SubT-A K5 / SubT-B + batch 3 PR-Y / G5] forward decl framework primitives —
// profile factory pattern 让 profile 自报怎么造,Assembler 走 dispatch + fail-loud(P7)。
namespace refuzz::fuzzer {
class IStabilityOracle;
class IRetryPolicy;
class IPriorityCalculator;  // [v2 batch 3 PR-Y]
class ISaturationFilter;    // [v2 batch 3 G5]
}

namespace refuzz::profile {

// [v2 PR2 — Corpus Generation Adaptation]
// Profile 自报的 "corpus 加载层" 配置——不含 bootstrap 概念（syzkaller
// 也无 bootstrap，corpus 空由 ExploreJob 接管——见 control/src/job/explore_job.cpp
// 的 genFuzz never-empty supply）。
//
// 字段：
//   - build_decoder：由 profile 根据 OrchestratorConfig 构造 ArtifactMaterializerFn
//     用于 CorpusDiskIO::LoadAll / LoadCrashRepros。返回空 std::function 表示
//     BytesOnly 路径（无 decoder），此时 load_policy 必须是 LenientBytes。
//   - load_policy：corpus 加载策略，详见 corpus/include/refuzz/corpus/corpus_prep_policy.hpp。
//
// kernel-syz/v2 自报：build_decoder = MakeRegistryMaterializer(kSyzProg, linux-amd64),
//                    load_policy   = StrictTyped。
//
// 未来 cli-afl 自报：build_decoder = nullptr 或 identity, load_policy = LenientBytes。
struct CorpusPrepConfig {
    using BuildDecoderFn = std::function<
        ::refuzz::program::ArtifactMaterializerFn(
            const orchestrator::OrchestratorConfig&)>;
    BuildDecoderFn                    build_decoder;
    refuzz::fuzzer::CorpusLoadPolicy  load_policy =
        refuzz::fuzzer::CorpusLoadPolicy::LenientBytes;
    // [candidate-model gate] boot corpus 是走 candidate(pending → verify →
    // minimize → admit,corpus 从 ~0 长起,与 syz 同构)还是直接 admit 进 active
    // corpus。**仅当 profile 的 stage 链真的有 corpus_verify/minimize 时设 true。**
    // 没有 verify 链的 profile(如 xiuos)必须保持 false:否则 boot 种子被塞进
    // PendingSeedMap 却无任何 stage 去取走 → 永远不 admit → active corpus 恒 0 →
    // producer 零产出(mut_p 无 corpus 可变异)。默认 false = 直接 admit(安全)。
    bool                              boot_corpus_via_candidates = false;
};

// [v2 V1 fallback capability-gated — 当前版本]
// Profile-level capability flags. 同 CorpusPrepConfig:profile 自报 "本 target
// 是否允许 V1 bytes-only fallback 路径"。kernel/syz profile 默认 false →
// stage 的 v1 fallback 触发(eg. mutational/smash/hints 没拿到 artifact 又
// 没现成 wire bytes)即 fail-closed log+skip,**不再把 v2 engine 的 canonical
// text 当 wire 提交给 worker**(原是 worker child SIGABRT 的关联根因)。
// raw/AFL 等真 bytes-only family profile 添加时显式置 true,旧 V1 路径作为
// "capability-gated"行为保留。
struct ProfileCapabilities {
    // false(默认) = 严格 typed/artifact-first;stage 看不到 artifact 又没 wire
    //                bytes 时 skip + log,不 push 任何 task。
    // true        = 允许 v1 bytes-only fallback;此时 mutator.Mutate(seed)
    //                输出**必须**是 wire bytes(raw/AFL family invariant)。
    bool accept_bytes_only_fallback = false;

    // [Step 1 catch-all 迁 loop] 本 profile 是否启用 triage(= 旧 mut_c 的
    // triage_enabled 参数)。true → catch-all(现由 FuzzerLoop 承接)对 NewCov seed
    // 走 divert + push "triage" follow-up(triage_stage → core_path_job);false →
    // 直接入 inbox admit(XiUOS / 无 triage 链)。kernel profile 设 true。
    bool triage_enabled = false;
};

struct ProfileDefaults {
    // Profile 名称,与 LaunchPlan::profile 匹配。
    std::string name;

    // 该 profile 下"各组件选择"的默认值。
    // Resolver 会把 LaunchPlan 里空串的选择字段用 defaults.<field> 替换。
    // defaults.profile 必须与 name 一致(构造时设好)。
    startup::LaunchPlan defaults;

    // 本 profile 在 snapshot 执行模式下的默认 channel backend(per-mode 默认)。
    // 空 = 本 profile 不支持 snapshot(Resolver 在 snapshot_mode 下会报错)。
    // "模式 → 后端" 的映射声明在 profile 里(声明式、可扩展),不写死在 frontend;
    // 加一个支持 snapshot 的新 target,只需在它的 profile 设这一行。
    std::string snapshot_channel_backend_id;

    // 配置注入:在所有组件构造前调用,允许 profile 修改 OrchestratorConfig。
    // 典型用途:kernel profile 把 SanitizerMode 转译成 kernel cmdline 里的
    // "kasan=on" / "kcsan=on" 等 flag。
    // 失败返回 ComponentError;通常不会失败,这里用 Result<void> 与其他 API 对齐。
    using ConfigureFn = std::function<core::Result<void>(orchestrator::OrchestratorConfig&)>;
    ConfigureFn configure;

    // 目标特有校验。Orchestrator 在 configure 之后、Assemble 之前调用,
    // 读 OrchestratorConfig(含已装配好的 channel_backend 多态指针)做完整性校验。
    // 失败时 err 承载具体原因。
    using ValidateFn = std::function<bool(const orchestrator::OrchestratorConfig&, std::string&)>;
    ValidateFn validate;

    // Per-VM repro channel 配置派生。v4 channel 文档约定:shm_path / doorbell
    // 后缀、vm_id 递增、repro 专用 CPU/内存降配这些"组合级策略"由 profile
    // 给出,Assembler 不感知 target。返回值是两段式:
    //   - ChannelConfig:                    中性 channel_common 的 per-VM 副本(改 channel_id)
    //   - unique_ptr<IChannelBackendProfile>: 后端 Profile 的 per-VM 副本
    // 为空 lambda 时 Orchestrator 会走"共用 main channel 配置"的兜底。
    using DeriveReproCfgFn = std::function<
        std::pair<channel::ChannelConfig,
                  std::unique_ptr<channel::factory::IChannelBackendProfile>>(
            const orchestrator::OrchestratorConfig&, uint32_t repro_index)>;
    DeriveReproCfgFn derive_repro_channel_cfg;

    // [v2 PR2 — Corpus Generation Adaptation] corpus 加载层配置。
    // profile 自报 decoder + load_policy，orch 不再硬编码 (kSyzProg, linux-amd64)。
    // 详见上面 CorpusPrepConfig 注释。
    CorpusPrepConfig corpus_prep;

    // [v2 V1 fallback capability-gated — 当前版本] profile-level capability。
    // kernel/syz profile 默认(false)→ stage v1 fallback skip + log;raw/AFL
    // family 显式设 true 后保留 v1 路径。详见 ProfileCapabilities 注释。
    ProfileCapabilities capabilities;

    // [v2 SubT-A K5 / SubT-B + batch 3 PR-W1] framework primitive factory 字段。
    //
    // profile 自报怎么造 framework primitive;Assembler 走 profile.make_xxx()
    // dispatch。P7 fail-loud 语义:profile 存在但 factory 未设置或返回 nullptr
    // 都是 ComponentError,不再 silent fallback 到 kernel default。只有 profile
    // lookup 本身失败(prof == nullptr)才保留历史 kernel fallback。
    //
    // 7 family 接入(PyTorch numerical tolerance / 协议响应等价等)时 profile
    // 各自实现 factory,无需改 Assembler。详父 plan §2 P7。
    using MakeStabilityOracleFn = std::function<std::unique_ptr<refuzz::fuzzer::IStabilityOracle>()>;
    using MakeRetryPolicyFn     = std::function<std::unique_ptr<refuzz::fuzzer::IRetryPolicy>()>;
    // [v2 batch 3 PR-Y] priority calculator factory — profile 自报怎么造。
    // Assembler 装配同 SubT-A/B 模板:profile != null && !factory → ComponentError;
    // factory 返 nullptr → ComponentError;profile == null → fallback kernel default。
    using MakePriorityCalculatorFn = std::function<std::unique_ptr<refuzz::fuzzer::IPriorityCalculator>()>;
    // [v2 batch 3 G5] saturation filter factory — 同 PR-Y / SubT-A/B 模板。
    // kernel default = KernelCoverageSaturationFilter(默认 threshold=kDisabledThreshold → 饱和禁用,
    //   从不 drop;per-syscall 覆盖丢弃压制真实/mutate 覆盖,syz 无此过滤。休眠调试代码);
    // kernel_no_triage = NoopSaturationFilter(显式 wire,P7 一致 — 详 plan D4)。
    using MakeSaturationFilterFn   = std::function<std::unique_ptr<refuzz::fuzzer::ISaturationFilter>()>;
    MakeStabilityOracleFn    make_stability_oracle;
    MakeRetryPolicyFn        make_retry_policy;
    MakePriorityCalculatorFn make_priority_calculator;
    MakeSaturationFilterFn   make_saturation_filter;
};

} // namespace refuzz::profile
