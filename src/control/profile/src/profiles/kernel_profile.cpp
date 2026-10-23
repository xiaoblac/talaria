// Copyright 2026 reFuzz project author -------youngkk.
//
// kernel-family profiles
//   "kernel"           — reFuzz 一等公民 default,syzkaller-equivalent (含 triage / minimize / smash / hints / fault chain)
//   "kernel_no_triage" — 显式 opt-out 退化版,无 triage chain
//   "kernel_full"      — 在 "kernel" 基础上追加 smash 配置变体
//
// Linux kernel syscall fuzzing 的默认能力组合:
//
//   * channel_backend_id = "qemu_ivshmem_linux"   (ChannelCatalog)
//   * target_toolkit     = "kernel_linux_syz"     (TargetToolkitCatalog)
//   * mutator_engine     = "syz"                  (MutatorEngineCatalog, v2 engine)
//   * scheduler_engine   = "priority_scheduler"   (SchedulerEngineCatalog)
//   * feedback_engine    = "kernel_kcov"          (FeedbackEngineCatalog)
//   * corpus_store       = "in_memory"            (CorpusStoreCatalog)
//
// profile 自身只再提供:
//   * configure(cfg):    按 SanitizerMode 追加 kernel cmdline 标志
//   * validate(cfg, err): 要求 execution_mode=kKernelSyscall 且 channel_backend
//                         为 QemuIvshmemLinuxProfile
//   * derive_repro_channel_cfg(cfg, i): 派生 per-VM repro channel 两段式配置
//                         (中性 ChannelConfig + 后端 Profile 克隆)
// 其余 crash/repro/diag/seed 工厂已下沉到 TargetToolkitCatalog。

#include "refuzz/profile/builtin_profiles.hpp"


#include "refuzz/channel/factory/channel_catalog.hpp"         // channel_backend_id 常量
#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/control/support/support_checker.hpp"         // [syscall-support-detection]
#include "refuzz/core/error.hpp"
// [v2 PR2 — Corpus Generation Adaptation] decoder 构造依赖 syz target / registry。
#include "refuzz/corpus/corpus_prep_policy.hpp"
// [v2 SubT-A K5 / SubT-B] kernel default framework primitive factory — kernel
// profile 自报 make_stability_oracle / make_retry_policy。
#include "refuzz/feedback/retry/syzkaller_retry_policy.hpp"
#include "refuzz/feedback/stability/signal_set_intersection_oracle.hpp"
#include "refuzz/feedback/stability/signal_voting_stability_oracle.hpp"
// [v2 batch 3 PR-Y] kernel default priority calculator factory。
#include "refuzz/feedback/priority/syzkaller_priority_calculator.hpp"
// [v2 batch 3 G5] kernel default saturation filter + noop for kernel_no_triage。
#include "refuzz/feedback/saturation/kernel_coverage_saturation_filter.hpp"
#include "refuzz/feedback/saturation/noop_saturation_filter.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"   // WrapWithEnabledCalls
#include "refuzz/proto_domain/types.hpp"  // ProgFormat::kSyzProg

#include <memory>
#include <string>
#include <utility>

namespace refuzz::profile {

namespace {

// "kernel_linux_syz" 是 TargetToolkitCatalog 里的唯一条目 id;
// 本地常量避免 profile 直接 include crash header。
constexpr const char* kKernelLinuxSyzToolkit = "kernel_linux_syz";

// MutatorEngineCatalog / SchedulerEngineCatalog / FeedbackEngineCatalog /
// CorpusStoreCatalog 的默认 id——与对应 RegisterBuiltin* 里的注册 id 保持一致。
constexpr const char* kDefaultMutatorEngine    = "syz";
constexpr const char* kDefaultSchedulerEngine  = "priority_scheduler";
constexpr const char* kDefaultFeedbackEngine   = "kernel_kcov";
constexpr const char* kDefaultCorpusStore      = "in_memory";

std::string ReplaceVmIdArg(const std::string& cmd, uint32_t vm_id)
{
    const std::string flag = "--vm-id";
    const std::string value = std::to_string(vm_id);
    const size_t pos = cmd.find(flag);
    if (pos == std::string::npos) {
        std::string out = cmd;
        if (!out.empty()) {
            out += ' ';
        }
        out += flag + " " + value;
        return out;
    }

    size_t value_begin = pos + flag.size();
    while (value_begin < cmd.size() && cmd[value_begin] == ' ') {
        ++value_begin;
    }
    std::string out = cmd;
    if (value_begin >= cmd.size()) {
        out += " " + value;
        return out;
    }

    const size_t value_end = cmd.find(' ', value_begin);
    if (value_end == std::string::npos) {
        out.replace(value_begin, std::string::npos, value);
    } else {
        out.replace(value_begin, value_end - value_begin, value);
    }
    return out;
}

void AppendKernelSanitizerCmdline(orchestrator::OrchestratorConfig& cfg)
{
    std::string extra;
    switch (cfg.target.sanitizer_mode) {
    case orchestrator::SanitizerMode::kKasan: extra = "kasan=on"; break;
    case orchestrator::SanitizerMode::kKcsan: extra = "kcsan=on"; break;
    case orchestrator::SanitizerMode::kUbsan: extra = "ubsan=on"; break;
    case orchestrator::SanitizerMode::kNone:
    default:
        return;
    }

    // kernel_cmdline 是 QEMU/Linux 后端专属字段;非该后端下不适用。
    auto* qemu_profile = dynamic_cast<channel::factory::QemuIvshmemLinuxProfile*>(
        cfg.channel_backend.get());
    if (qemu_profile == nullptr) {
        return;
    }
    auto& cmdline = qemu_profile->runtime.instance.kernel_cmdline;
    if (!cmdline.empty()) {
        cmdline += " ";
    }
    cmdline += extra;
}

} // namespace

ProfileDefaults MakeKernelNoTriageProfile()
{
    ProfileDefaults p;
    p.name = "kernel_no_triage";

    // defaults:该 profile 下每个选择字段的默认 catalog id。
    p.defaults.profile            = p.name;
    p.defaults.mutator_engine     = kDefaultMutatorEngine;
    p.defaults.scheduler_engine   = kDefaultSchedulerEngine;
    p.defaults.corpus_store       = kDefaultCorpusStore;
    p.defaults.feedback_engine    = kDefaultFeedbackEngine;
    p.defaults.channel_backend_id =
        std::string(channel::channel_backend_id::kQemuIvshmemLinux);
    // snapshot 执行模式下本 profile 的默认后端(Resolver 在 snapshot_mode 时选它)。
    p.snapshot_channel_backend_id =
        std::string(channel::channel_backend_id::kQemuIvshmemSnapshotLinux);
    p.defaults.target_toolkit     = kKernelLinuxSyzToolkit;
    // corpus_admission 暂不使用;保持空串。

    // [v2 PR2 — Corpus Generation Adaptation 当前版本]
    // 加 generate_producer 在 mutational_producer 之前：
    //   - 空 corpus → generate_producer 100% 投 task（无需 bootstrap canonical seed）
    //   - 非空 corpus → generate_producer 5% 投，否则 mutational_producer 接管
    // §015 §5 已规划该 stage 但排在 Phase 5；为修 corpus 单调性提前到现在。

    // [v2 PR2 — Corpus Generation Adaptation]
    // profile 自报 corpus 加载层：decoder + load_policy。
    // 取代 orchestrator.cpp 原有硬编码 (kSyzProg, linux-amd64) + StrictTyped。
    // syz/v2 strict typed：decode 失败的 seed 在 LoadAll/LoadCrashRepros 直接 drop
    // （PR1 fail-closed 契约）；bytes-only seed 不会污染 corpus。
    p.corpus_prep.build_decoder =
        [](const orchestrator::OrchestratorConfig& cfg)
            -> ::refuzz::program::ArtifactMaterializerFn {
        ::refuzz::program::RegisterBuiltinArtifactMaterializers();
        const auto& t = ::refuzz::program::syz::Target::linux_amd64();
        (void)cfg;
        // [machine-check] DECODE only — return the base materializer with NO
        // enabled-calls filter. The corpus must always decode (a seed using a
        // non-enabled syscall is a valid program, not "undecodable"); the
        // allow-list FILTER is a separate step the orchestrator applies AFTER the
        // machine-check, dropping PendingSeedMap candidates whose calls aren't in
        // the *probed* enabled set. (Previously WrapWithEnabledCalls conflated
        // decode with filtering via the static mask → spurious drop_undecodable.)
        return ::refuzz::program::MakeRegistryMaterializer(
            ::refuzz::fuzzer::ProgFormat::kSyzProg,
            ::refuzz::program::ProgramTargetKey{t.os(), t.arch(), t.revision()});
    };
    p.corpus_prep.load_policy = ::refuzz::fuzzer::CorpusLoadPolicy::StrictTyped;

    // [v2 SubT-A K5 / SubT-B] framework primitive factory — kernel default。
    // 所有 kernel-* profile (NoTriage / kernel / Full) 都继承此 factory(std::function
    // copy);其它 family 注册自己的 profile 时各自覆盖。详 docs/admit-pipeline-alignment/
    // 200_batch2_framework_primitives.md §3.A / §3.B。
    // [k-of-n 自适应去抖] kernel 用投票式 stability oracle。normal program 走
    // 3-of-5；boot corpus 走 k=2、最少 4 个总样本、无新增最多 6 个总样本。
    // discovery 已占 signals[0]，所以 boot 的 min=4 只新增 3 次 replay；持续发现
    // signal 时的 20 样本硬上限由 core-path job 单独执行。其它 family(xiuos)
    // 默认构造 (2,2,0)+严格 intersection oracle，不受影响。
    p.make_stability_oracle = []() -> std::unique_ptr<refuzz::fuzzer::IStabilityOracle> {
        return std::make_unique<refuzz::fuzzer::SignalVotingStabilityOracle>();
    };
    p.make_retry_policy = []() -> std::unique_ptr<refuzz::fuzzer::IRetryPolicy> {
        return std::make_unique<refuzz::fuzzer::SyzkallerRetryPolicy>(
            /*boot_verify_runs=*/6, /*boot_min_votes=*/2, /*boot_min_runs=*/4);
    };
    // [v2 batch 3 PR-Y] kernel default priority calculator — bit packing 模拟
    // syzkaller hash.go(详 syzkaller_priority_calculator.hpp)。
    p.make_priority_calculator = []() -> std::unique_ptr<refuzz::fuzzer::IPriorityCalculator> {
        return std::make_unique<refuzz::fuzzer::SyzkallerPriorityCalculator>();
    };
    // [v2 batch 3 G5] kernel_no_triage 显式 NoopSaturationFilter(plan D4):
    // no-triage profile 跳过 triage / verify / saturation 等 interest decision,
    // 等价 syzkaller "fastest path",因此 saturation 也 disable 走透传。
    // **kernel / kernel_full 在继承之后覆盖为真实 KernelCoverageSaturationFilter**
    // (见 MakeKernelProfile 末尾)。P7 一致 — 不留 nullptr 让 Assembler fail-loud。
    p.make_saturation_filter = []() -> std::unique_ptr<refuzz::fuzzer::ISaturationFilter> {
        return std::make_unique<refuzz::fuzzer::NoopSaturationFilter>();
    };

    p.configure = [](orchestrator::OrchestratorConfig& cfg) -> core::Result<void> {
        AppendKernelSanitizerCmdline(cfg);
        return {};
    };

    p.validate = [](const orchestrator::OrchestratorConfig& cfg, std::string& err) -> bool {
        if (cfg.target.execution_mode != orchestrator::ExecutionMode::kKernelSyscall) {
            err = "kernel profile requires target.execution_mode=kernel_syscall";
            return false;
        }
        if (cfg.channel_backend == nullptr) {
            err = "kernel profile: cfg.channel_backend is null (need QemuIvshmemLinuxProfile)";
            return false;
        }
        // snapshot 后端复用 QemuIvshmemLinuxProfile,只是 catalog 分派到 SnapshotAssembler;
        // 两个 id 都放行(dynamic_cast 下面仍校验 profile 形态)。
        if (cfg.channel_backend_id !=
                std::string(channel::channel_backend_id::kQemuIvshmemLinux) &&
            cfg.channel_backend_id !=
                std::string(channel::channel_backend_id::kQemuIvshmemSnapshotLinux)) {
            err = "kernel profile: cfg.channel_backend_id must be 'qemu_ivshmem_linux' or "
                  "'qemu_ivshmem_snapshot_linux', got '" + cfg.channel_backend_id + "'";
            return false;
        }
        if (dynamic_cast<const channel::factory::QemuIvshmemLinuxProfile*>(
                cfg.channel_backend.get()) == nullptr) {
            err = "kernel profile: cfg.channel_backend is not QemuIvshmemLinuxProfile";
            return false;
        }
        return true;
    };

    // Per-VM repro channel 派生。与旧 TargetProfile 的同名 lambda 保持等价行为;
    // workdir 仍然由 Orchestrator 传 ctx.vm_workdir 覆盖,此处不派生 workdir。
    p.derive_repro_channel_cfg = [](const orchestrator::OrchestratorConfig& cfg,
                                    uint32_t i)
        -> std::pair<channel::ChannelConfig,
                     std::unique_ptr<channel::factory::IChannelBackendProfile>>
    {
        const auto* main_profile = dynamic_cast<const channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        if (main_profile == nullptr) {
            return { cfg.channel_common, nullptr };
        }

        const uint32_t base_channel_id = cfg.channel_common.channel_id == 0
            ? 1 : cfg.channel_common.channel_id;

        channel::ChannelConfig repro_common = cfg.channel_common;
        repro_common.channel_id = base_channel_id + cfg.fuzz_channel_count + i;
        repro_common.n_workers = 1;

        auto repro_profile =
            std::make_unique<channel::factory::QemuIvshmemLinuxProfile>(*main_profile);

        repro_profile->runtime.instance.index = 0;
        const uint32_t repro_vm_id = cfg.vm_id + cfg.fuzz_channel_count + i;
        const std::string repro_suffix = "_repro_" + std::to_string(i);

        repro_profile->infra.shm_path = main_profile->infra.shm_path + repro_suffix;
        repro_profile->transport.doorbell_socket_path =
            main_profile->transport.doorbell_socket_path + repro_suffix;
        repro_profile->runtime.instance.ivshmem_path = repro_profile->infra.shm_path;
        repro_profile->runtime.instance.ivshmem_socket =
            repro_profile->transport.doorbell_socket_path;

        // repro VM 降配:1 核 1G,避免与 fuzzing VM 抢资源导致宿主机卡死。
        repro_profile->runtime.instance.cpu    = 1;
        repro_profile->runtime.instance.mem_mb = 1024;
        repro_profile->runtime.instance.ivshmem_vectors = 1;
        repro_profile->infra.n_workers                  = repro_common.n_workers;
        repro_profile->transport.n_workers              = repro_common.n_workers;
        repro_profile->worker.n_workers                 = repro_common.n_workers;

        repro_profile->worker.worker_start_cmd =
            ReplaceVmIdArg(repro_profile->worker.worker_start_cmd, repro_vm_id);

        return { std::move(repro_common), std::move(repro_profile) };
    };

    return p;
}

// reFuzz 一等公民 default profile：在 MakeKernelNoTriageProfile() 基础上把 chain 升级为
//   producer:[min_p, triage_p, smash_p, hints_p, fault_p, gen_p, mut_p]
//   consumer:[triage_c, min_c, hints_c, fault_c, mut_c]
// 并设：
//   mut_c.triage_enabled=true
//   triage_p.count=3
//   min_p.attempts=3, min_p.mode=kCallsOnly
//   hints_p.enabled / fault_p.enabled = "auto"(Resolver 按 feedback / target 自动 flip)
//
// chain 顺序语义：
//   producer: min_p > triage_p > smash_p > hints_p > fault_p > gen_p > mut_p
//             (follow-up 优先,gen_p/mut_p 走默认生成路径兜底);
//   consumer: triage_c 先（owner event 截留），
//             min_c 次,
//             hints_c / fault_c 处理各自 inflight,
//             mut_c 末尾 catch-all。
//
// 与 MakeKernelNoTriageProfile() 共享 configure / validate / derive_repro_channel_cfg
// （均通过 std::function 拷贝继承）。
//
// [2026-05-08 swap rename] 历史名 MakeKernelProfileWithTriage / "kernel_triage"
// 已退役;改动来源 docs/admit-pipeline-alignment/100_batch1_default_triage.md
ProfileDefaults MakeKernelProfile()
{
    auto p = MakeKernelNoTriageProfile();
    p.name = "kernel";
    p.defaults.profile = "kernel";

    // [candidate-model gate] kernel(+ kernel_full,经 MakeKernelProfile base 继承)
    // 的 stage 链下面会加 corpus_verify_p/c + min_p/c → boot corpus 走 candidate
    // (pending→verify→minimize→admit,corpus 从 ~0 长起,与 syz 同构)。
    // kernel_no_triage(无 corpus_verify 链)与 xiuos 保持默认 false = 直接 admit。
    p.corpus_prep.boot_corpus_via_candidates = true;

    // [v2 batch 3 G5] 继承 NoTriage 的 NoopSaturationFilter 之后**覆盖**为
    // KernelCoverageSaturationFilter — kernel(+ kernel_full)profile 跑 triage /
    // corpus_verify / interest decision。kernel_full 通过 MakeKernelProfile() base 自动继承。
    // per-syscall 饱和**默认禁用**(filter 默认 threshold=kDisabledThreshold=0xFFFFFFFFu,从不
    // drop):它会在 admission 前丢掉热门 syscall 上的真·novel 边、压制真实/mutate 覆盖,且当前
    // syzkaller 无此过滤。profile 不在此配置/暴露阈值;要内部调试重启用,直接给构造传真实 threshold。
    p.make_saturation_filter = []() -> std::unique_ptr<refuzz::fuzzer::ISaturationFilter> {
        return std::make_unique<refuzz::fuzzer::KernelCoverageSaturationFilter>();
    };

    p.capabilities.triage_enabled = true;

    return p;
}

// [v2 Phase 4 Step 4.4 — 当前版本]
// 可选 opt-in profile：以 MakeKernelProfile()(swap 后的 default,已含 smash/
// hints/fault stage)为 base 拷贝。chain 字面与 default kernel 等价:
//   producer:[min_p, triage_p, smash_p, hints_p, fault_p, gen_p, mut_p]
//   consumer:[triage_c, min_c, hints_c, fault_c, mut_c]   (沿用 default kernel chain 不变)
//
// 注:swap rename 后 default kernel 已包含 smash/hints/fault stage,
// 因此本函数 body 里对 smash_p/hints_p/hints_c/fault_p/fault_c 的 emplace
// 在 std::map::emplace 重复 key 语义下为 no-op。kernel_full 跟 default kernel
// 实质等价,真实增量 stage 待 follow-up 整改(批次 4 / 7-family review)。
//
// 含义：
//   * minimize > triage > smash > hints > fault > mutational（chain 顺序生效，
//     与 015 §4.8.1 priority 表方向一致——triage 永远先于 smash）；
//   * smash backlog 经 arbiter 的 request-window（dispatch_window_limit）节流，不靠 chain 顺序抢占；
//   * hints / fault stage enabled="auto",Resolver 按 feedback / target 自动 flip；
//   * mut_p 默认路径兜底；mut_c.triage_enabled=true（继承自 default kernel）。
//
// smash：固定 25 变体的 emit job（= syz `const iters = 25`），逐变体 fire-and-forget，与
//   continuation 共用同一个 arbiter request-window（dispatch_window_limit）自然节流 ——
//   不存在 “max_concurrent_seeds × iterations < 窗口” 这类耦合，也无 assembler 校验。
//
// 与 MakeKernelNoTriageProfile() 共享 configure / validate / derive_repro_channel_cfg
// （通过 std::function 拷贝在 MakeKernelProfile() → MakeKernelNoTriageProfile() 链上继承）。
ProfileDefaults MakeKernelProfileFull()
{
    auto p = MakeKernelProfile();
    p.name = "kernel_full";
    p.defaults.profile = "kernel_full";


    return p;
}

} // namespace refuzz::profile
