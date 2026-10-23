// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/crash/target_toolkit_catalog.hpp"

#include "refuzz/crash/pipeline/engine/linuxkernel/syz_engine/syz_crash_analysis_engine.hpp"
#include "refuzz/crash/pipeline/engine/xiuos/xiuos_crash_analysis_engine.hpp"
#include "refuzz/crash/repro/engine/linuxkernel/syz_engine/syz_repro_engine.hpp"
#include "refuzz/crash/repro/engine/xiuos/xiuos_repro_engine.hpp"

#include <memory>

namespace refuzz::crash {

// [v1 — ROLLBACK: uncomment below and remove v2 block]
// namespace {
// // 构建最小 kernel fuzz 初始种子：getpid() + getuid() (V2 canonical text)。
// // 由 V2 engine 在 corpus 加载或 mutate 时通过 TextDecoder.decode 进 IR。
// std::vector<uint8_t> BuildKernelSyzSeedPayload()
// {
//     constexpr const char* kInitialText = "getpid()\ngetuid()\n";
//     const auto* p = reinterpret_cast<const uint8_t*>(kInitialText);
//     return std::vector<uint8_t>(p, p + std::strlen(kInitialText));
// }
// } // namespace

// [v2 PR2 — Corpus Generation Adaptation 当前版本]
// 删除 BuildKernelSyzSeedPayload + build_seed_payload 注册：
//   - syzkaller 也无 canonical bootstrap seed 的概念；
//   - corpus-independent generation 改由 ExploreJob（control/src/job/explore_job.cpp）
//     调 IMutatorEngine::Generate 完成（§015 §5 / §6.1）；
//   - target_toolkit 不再承担 "种子生产" 职责，专注 crash analysis / repro /
//     diagnostic provider 三件套。

void RegisterBuiltinTargetToolkits(TargetToolkitCatalog& catalog)
{
    // "kernel_linux_syz" — Linux kernel target(syzkaller 系 crash analysis +
    // repro minimizer)。对应原 kernel_profile 三个 create_* 工厂。
    {
        TargetToolkitCatalog::Entry entry;
        entry.meta = {
            "kernel_linux_syz",
            "Linux Kernel (syzkaller)",
            "Linux kernel target: syz crash analysis / syz repro minimizer",
        };
        entry.build = [](const TargetToolkitTraits::BuildContext& /*ctx*/)
            -> core::Result<std::unique_ptr<TargetToolkit>> {
            auto toolkit = std::make_unique<TargetToolkit>();
            toolkit->id = "kernel_linux_syz";

            toolkit->create_analysis_engine = [](
                    const TargetToolkitBuildArgs& args,
                    Addr2lineSymbolizer* sym)
                -> std::unique_ptr<ICrashAnalysisEngine> {
                return std::make_unique<KernelCrashAnalysisEngine>(
                    sym, args.sanitizer_mode);
            };

            toolkit->create_repro_engine = [](
                    const TargetToolkitBuildArgs& /*args*/,
                    Addr2lineSymbolizer* sym) -> std::unique_ptr<IReproEngine> {
                return std::make_unique<KernelReproEngine>(sym);
            };

            toolkit->create_diagnostic_provider = [](refuzz::channel::IChannel* /*ch*/)
                -> std::unique_ptr<IDiagnosticAttachmentProvider> {
                // final state: crash 诊断只消费 frozen snapshot,不再异步读取
                // worker log。保留 lambda 以维持接口契约,始终返回 nullptr。
                return nullptr;
            };

            // [v2 PR2] build_seed_payload 已删（详见接口头注释 + RegisterBuiltinTargetToolkits 头部）。

            return toolkit;
        };
        catalog.Register(std::move(entry));
    }

    // "xiuos" — XiUOS RTOS target toolkit.
    //
    // crash_pipeline 的持久化出口是 DiagnosticStore（reFuzz 正规 evidence sink）。
    // XiUOS finding（XiuosOracleSignal 产出的 state-violation / leak crash_payload,
    // 以及 trap AbnormalCompletion）经 feedback → EngineOutput.crash_dispatch
    // (CombinedCrashEvent) → CrashPipelineManager.Process → 这里注册的 op 链 →
    // DiagnosticStore。
    //
    // [XiUOS leak 一等公民化 Phase 1] analysis engine 改用 XiUOS 自己的
    // XiuosCrashAnalysisEngine（不再借 KernelCrashAnalysisEngine）。它注册
    // XiuosBuildContextOp 做 XiUOS 语义的 routing —— result_code==kResourceLeak →
    // CrashKind::kResourceLeak（独立 resource_leak/ bucket + leak_bytes 载体），
    // 其它 result_code / fault reason 复制 target-agnostic 路由让 wedge/error
    // 仍正确分桶；dedup/persist/enqueue/report 仍复用 target-agnostic op。
    // 没有 KernelReportParser / symbolizer（XiUOS UART worker 不产 kernel console，
    // 无 vmlinux）。
    //
    // repro engine = XiuosReproEngine(app-surface 面 crash 的 reFuzz 自带最小化):
    // verdict=worker_dead/kernel_crash、minimize=exec-wire call-level delta-debug、
    // 无 symbolize。经 IReproEngine 接口接入 ReproManager。diag provider 返回 nullptr。
    {
        TargetToolkitCatalog::Entry entry;
        entry.meta = {
            "xiuos",
            "XiUOS RTOS",
            "XiUOS target: XiUOS-owned crash analysis (resource_leak bucket) to DiagnosticStore",
        };
        entry.build = [](const TargetToolkitTraits::BuildContext& /*ctx*/)
            -> core::Result<std::unique_ptr<TargetToolkit>> {
            auto toolkit = std::make_unique<TargetToolkit>();
            toolkit->id = "xiuos";

            toolkit->create_analysis_engine = [](
                    const TargetToolkitBuildArgs& /*args*/,
                    Addr2lineSymbolizer* /*sym*/)
                -> std::unique_ptr<ICrashAnalysisEngine> {
                return std::make_unique<XiuosCrashAnalysisEngine>();
            };

            toolkit->create_repro_engine = [](
                    const TargetToolkitBuildArgs& /*args*/,
                    Addr2lineSymbolizer* /*sym*/) -> std::unique_ptr<IReproEngine> {
                return std::make_unique<XiuosReproEngine>();
            };

            toolkit->create_diagnostic_provider = [](refuzz::channel::IChannel* /*ch*/)
                -> std::unique_ptr<IDiagnosticAttachmentProvider> {
                return nullptr;
            };

            return toolkit;
        };
        catalog.Register(std::move(entry));
    }
}

} // namespace refuzz::crash
