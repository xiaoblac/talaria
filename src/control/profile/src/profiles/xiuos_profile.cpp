// Copyright 2026 reFuzz project author -------youngkk.
//
// xiuos profile — XiUOS RTOS UART-worker fuzzing 的默认能力组合(Stage 3 去山头)。
//
// 把 XiuosFuzzSession 私有闭环收敛进 reFuzz 正规件:profile 只声明"XiUOS 这个
// target 怎么把 Catalog 组合起来",FuzzerLoop + stage 链 + feedback + crash_pipeline
// 全部复用。各组件选择:
//
//   * channel_backend_id = "qemu_uart_xiuos"   (ChannelCatalog,已注册)
//   * target_toolkit     = "xiuos"             (TargetToolkitCatalog,最小条目)
//   * mutator_engine     = "xiuos"             (MutatorEngineCatalog,XiuosMutatorEngine)
//   * scheduler_engine   = "priority_scheduler"(SchedulerEngineCatalog,内含 round_robin)
//   * feedback_engine    = "xiuos_kcov"        (FeedbackEngineCatalog:exec_result +
//                          xiuos_coverage + xiuos_oracle,coverage-guided admit)
//   * corpus_store       = "in_memory"         (CorpusStoreCatalog)
//
// 与 kernel profile 的关键差异(都是 target 知识,不是临时 hack):
//
//   1. stage 链是 mutational-only:producer=[mut_p] / consumer=[mut_c]。**不含
//      generate_producer** —— XiuosMutatorEngine 不实现 IMutatorEngine::Generate
//      (默认 kSkipped),corpus-independent generation 对 XiUOS 无意义;XiUOS 靠
//      corpus bootstrap(LoadAll 读种子)起步。也不含 triage/minimize/smash/hints/
//      fault chain(那些是 kernel KCOV/repro 专属;XiUOS repro 暂不开)。
//
//   2. corpus 加载走 LenientBytes + 无 decoder:XiUOS 种子文件就是 self-describing
//      的 wire payload(XiuosEncodeProgram 产物),无需 typed materializer。
//      seed.artifact 保持 null、seed.payload = 原始 wire bytes。
//
//   3. capabilities.accept_bytes_only_fallback = true:MutationalProducerStage 在
//      seed.artifact==null 时走 mutator.Mutate(seed) 的 bytes 路径,
//      XiuosMutatorEngine.Mutate 返回的就是 re-encode 后的 XiUOS wire bytes
//      (raw/AFL family invariant),channeldispatcher payload-only 分支直接送 worker。
//      kernel/syz 严格 false(它们的 Mutate 返回 canonical text,不是 wire)。
//
// framework primitive factory 复用 kernel default(SignalSetIntersectionOracle /
// SyzkallerRetryPolicy / SyzkallerPriorityCalculator / NoopSaturationFilter)——
// XiUOS 无 triage chain 时这些不在热路径,但 Assembler P7 fail-loud 要求非空 factory。
//
// configure:无 sanitizer cmdline 注入(XiUOS 不走 Linux kernel cmdline)。
// validate:要求 channel_backend 为 XiuosUartProfile 且 backend_id=qemu_uart_xiuos。
// derive_repro_channel_cfg:留空(XiUOS 不开 dedicated repro VM)。

#include "refuzz/profile/builtin_profiles.hpp"

#include "refuzz/channel/factory/channel_catalog.hpp"     // channel_backend_id 常量
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"  // validate 里 dynamic_cast
#include "refuzz/channel/factory/ch32_uart_profile.hpp"   // [Phase Q2] 物理板 backend
#include "refuzz/channel/factory/sifive_uart_xiuos_profile.hpp"  // repro VM 派生(app-surface)
#include "refuzz/core/error.hpp"
#include "refuzz/corpus/corpus_prep_policy.hpp"            // CorpusLoadPolicy
// framework primitive factory — 复用 kernel default。
#include "refuzz/feedback/priority/syzkaller_priority_calculator.hpp"
#include "refuzz/feedback/retry/syzkaller_retry_policy.hpp"
#include "refuzz/feedback/saturation/noop_saturation_filter.hpp"
#include "refuzz/feedback/stability/signal_set_intersection_oracle.hpp"

#include <memory>
#include <string>
#include <utility>

namespace refuzz::profile {

namespace {

constexpr const char* kXiuosToolkit          = "xiuos";
constexpr const char* kXiuosMutatorEngine    = "xiuos";
constexpr const char* kXiuosFeedbackEngine   = "xiuos_kcov";
constexpr const char* kDefaultSchedulerEngine = "priority_scheduler";
constexpr const char* kDefaultCorpusStore     = "in_memory";

} // namespace

ProfileDefaults MakeXiuosProfile()
{
    ProfileDefaults p;
    p.name = "xiuos";

    p.defaults.profile            = p.name;
    p.defaults.mutator_engine     = kXiuosMutatorEngine;
    p.defaults.scheduler_engine   = kDefaultSchedulerEngine;
    p.defaults.corpus_store       = kDefaultCorpusStore;
    p.defaults.feedback_engine    = kXiuosFeedbackEngine;
    p.defaults.target_toolkit     = kXiuosToolkit;
    p.defaults.channel_backend_id =
        std::string(channel::channel_backend_id::kQemuUartXiuos);
    // XiUOS 不支持 snapshot 执行模式;snapshot_channel_backend_id 留空。


    // ── corpus 加载层:bytes-only(无 decoder)+ LenientBytes ──
    // build_decoder 留空 std::function → orchestrator corpus_materializer 为 null →
    // LoadAll 走 bytes-only(seed.artifact==null, seed.payload=原始 wire bytes)。
    p.corpus_prep.load_policy = ::refuzz::fuzzer::CorpusLoadPolicy::LenientBytes;

    // raw bytes-only family:允许 MutationalProducerStage 的 v1 bytes fallback。
    p.capabilities.accept_bytes_only_fallback = true;

    // ── framework primitive factory(复用 kernel default,P7 fail-loud 需非空)──
    p.make_stability_oracle = []() -> std::unique_ptr<refuzz::fuzzer::IStabilityOracle> {
        return std::make_unique<refuzz::fuzzer::SignalSetIntersectionOracle>();
    };
    p.make_retry_policy = []() -> std::unique_ptr<refuzz::fuzzer::IRetryPolicy> {
        return std::make_unique<refuzz::fuzzer::SyzkallerRetryPolicy>();
    };
    p.make_priority_calculator = []() -> std::unique_ptr<refuzz::fuzzer::IPriorityCalculator> {
        return std::make_unique<refuzz::fuzzer::SyzkallerPriorityCalculator>();
    };
    // XiUOS 无 triage/saturation interest decision → NoopSaturationFilter(透传),
    // 与 kernel_no_triage 同档(P7 一致,不留 nullptr)。
    p.make_saturation_filter = []() -> std::unique_ptr<refuzz::fuzzer::ISaturationFilter> {
        return std::make_unique<refuzz::fuzzer::NoopSaturationFilter>();
    };

    p.configure = [](orchestrator::OrchestratorConfig&) -> core::Result<void> {
        // XiUOS 不注入 Linux kernel cmdline;无 sanitizer 转译。
        return {};
    };

    p.validate = [](const orchestrator::OrchestratorConfig& cfg, std::string& err) -> bool {
        if (cfg.channel_backend == nullptr) {
            err = "xiuos profile: cfg.channel_backend is null (need Xiuos/Ch32 UartProfile)";
            return false;
        }
        // xiuos profile 同时服务 QEMU(qemu_uart_xiuos)与物理板(ch32_uart_xiuos)——
        // 同一 XiUOS fuzz profile(mutator/feedback/oracle/stage 全相同),仅 channel
        // backend 不同(QEMU TCP serial vs 真串口 + wlink)。见 docs/plans/xiuos-ch32-bringup.md。
        const bool is_qemu = cfg.channel_backend_id ==
            std::string(channel::channel_backend_id::kQemuUartXiuos);
        const bool is_ch32 = cfg.channel_backend_id ==
            std::string(channel::channel_backend_id::kCh32UartXiuos);
        // app-surface 面:rv64 sifive_u + 分离构建。profile 继承 XiuosUartProfile,
        // 故下方 dynamic_cast<XiuosUartProfile*> 直接接受,仅需放行 backend_id。
        const bool is_sifive = cfg.channel_backend_id ==
            std::string(channel::channel_backend_id::kQemuUartSifiveU);
        if (!is_qemu && !is_ch32 && !is_sifive) {
            err = "xiuos profile: cfg.channel_backend_id must be 'qemu_uart_xiuos', "
                  "'ch32_uart_xiuos' or 'qemu_uart_sifive_u', got '" +
                  cfg.channel_backend_id + "'";
            return false;
        }
        const bool ok_profile =
            dynamic_cast<const channel::factory::XiuosUartProfile*>(
                cfg.channel_backend.get()) != nullptr ||
            dynamic_cast<const channel::factory::Ch32UartProfile*>(
                cfg.channel_backend.get()) != nullptr;
        if (!ok_profile) {
            err = "xiuos profile: cfg.channel_backend is not Xiuos/Ch32 UartProfile";
            return false;
        }
        return true;
    };

    // ── derive_repro_channel_cfg:派生 dedicated repro VM(让 reFuzz 自带的
    // repro/minimizer 跑 XiUOS crash 的最小化,经 config repro.enable 驱动)──
    // QEMU backend(sifive_u / virt-rv32)= 第二个 QEMU 进程,跑在与主 VM 不同的
    // serial 端口上;物理板(ch32)单设备无法派生 → 返回 null profile(Assembler
    // 跳过)。镜像 kernel profile 的 derive_repro_channel_cfg,只是 xiuos 用 serial
    // 端口区分而非 ivshmem path。
    p.derive_repro_channel_cfg =
        [](const orchestrator::OrchestratorConfig& cfg, uint32_t i)
        -> std::pair<channel::ChannelConfig,
                     std::unique_ptr<channel::factory::IChannelBackendProfile>>
    {
        const auto* base = dynamic_cast<const channel::factory::XiuosUartProfile*>(
            cfg.channel_backend.get());
        const bool is_ch32 = dynamic_cast<const channel::factory::Ch32UartProfile*>(
            cfg.channel_backend.get()) != nullptr;
        if (base == nullptr || is_ch32) {
            return { cfg.channel_common, nullptr };  // 物理板/未知 → 不派生 repro VM
        }

        const uint32_t base_channel_id =
            cfg.channel_common.channel_id == 0 ? 1 : cfg.channel_common.channel_id;
        channel::ChannelConfig repro_common = cfg.channel_common;
        repro_common.channel_id = base_channel_id + cfg.fuzz_channel_count + i;
        repro_common.n_workers  = 1;

        // repro VM 用独立 serial 端口(主 VM 端口 + fuzz_channel_count + i + 1),
        // 避免与主 VM / 其它 fuzz channel 的 TCP serial 撞端口。
        const std::uint16_t repro_port = static_cast<std::uint16_t>(
            base->serial_port + cfg.fuzz_channel_count + i + 1);

        // app-surface(sifive_u):必须克隆最派生类型,否则 slice 掉
        // machine/app_bin_path/console_endpoint 等字段。
        const auto* sifive =
            dynamic_cast<const channel::factory::SifiveUartXiuosProfile*>(
                cfg.channel_backend.get());
        if (sifive != nullptr) {
            auto rp = std::make_unique<channel::factory::SifiveUartXiuosProfile>(*sifive);
            rp->serial_port      = repro_port;
            rp->console_endpoint = "null";  // repro VM console 不需落盘
            return { std::move(repro_common), std::move(rp) };
        }
        // virt-rv32 内核内部面:基类 XiuosUartProfile。
        auto rp = std::make_unique<channel::factory::XiuosUartProfile>(*base);
        rp->serial_port = repro_port;
        return { std::move(repro_common), std::move(rp) };
    };

    return p;
}

} // namespace refuzz::profile
