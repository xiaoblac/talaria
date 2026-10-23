#pragma once

// [v3 Phase 1.B] IChannelAssembler — 合规后端组合装配入口
//
// 设计来源：docs/channel-redesign/v3/70_channel_assembly.md §2
//
// 一个 Assembler = 一组"合规的后端组合"的装配步骤集合：
//   Substrate + ControlPlane + DataPlane + ConsoleSource + StepEventSource
//   + HealthMonitor(+ Sensors) + Recovery(+ Policy)
//
// Assembler 返回 ChannelComponents（装配好但尚未 Boot 的一组 unique_ptr）；
// ChannelBuilder 再把它们塞进 Channel 实例。
//
// 本文件只定义接口与数据骨架；具体实现（QemuIvshmemLinuxAssembler / VsockLinux / ...）
// 在 Phase 4+ 落地（见 80_migration.md）。

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/evidence/console_ring_buffer.hpp"
#include "refuzz/channel/evidence/console_source.hpp"
#include "refuzz/channel/evidence/progress_clock.hpp"
#include "refuzz/channel/evidence/step_event_source.hpp"
#include "refuzz/channel/factory/channel_backend_profile.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace refuzz::channel {

namespace cc = refuzz::core::channel_contract;


// ChannelUse — fuzz 主路径 / repro 通道区分
//
// Assembler 按 `use` 派生 workdir / port offset / 是否启用若干 Sensor 等；
// 不需要为每种 use 都注册一个 id，同一个后端组合共用一个 id。
enum class ChannelUse : uint8_t {
    kFuzz = 0,
    kRepro,
};

// ChannelConfig — Channel 自身的运行参数（中性 / 后端无关）
//
// 与对外合同 schema 无关：只有 Channel 内部消费。
// backend_id 会在 Snapshot 里回填到 cc::ChannelSnapshot 里（telemetry dimension tag）。
struct ChannelConfig {
    uint32_t                            channel_id = 0;
    uint32_t                            n_workers = 0;
    ChannelUse                          use = ChannelUse::kFuzz;
    std::string                         backend_id;   // e.g. "qemu_ivshmem_linux"

    runtime::DeployBundle               deploy_bundle;

    std::chrono::milliseconds           wait_ready_timeout{60'000};
    std::chrono::milliseconds           loop_interval{100};

    // 中性运行参数：
    //   - health_check_interval : NoteHealthy 节流间隔
    //   - input_queue_capacity  : Submit 入队容量上限
    //   - pre_reboot_drain      : reboot 前健康 worker 排空窗口
    //
    // [Phase G] input_queue_capacity 调参约定:
    //   - 经验倍数 ≈ n_workers × 3
    //     (>= 2x 能填满 exec 流水线,再大只是无意义的 busy 噪音)
    //   - 在 config_parser 里按此倍数派生,JSON 显式值优先覆盖
    //   - 这里保留数值 64 只是"orchestrator 未传 n_workers 时的最后保底",
    //     正常路径都会被派生值覆盖。
    std::chrono::milliseconds           health_check_interval{500};
    std::size_t                         input_queue_capacity = 64;
    std::chrono::milliseconds           pre_reboot_drain{5500};

    // [v2 PR-E abnormal console snapshot lines — 当前版本]
    // abnormal completion 路径(worker 上报 abnormal / channel recovery 触发
    // EmitAbnormalCompletion)从共享 ConsoleRingBuffer 取的最近行数,写入
    // AbnormalCompletion.console_snapshot,下游 BuildContextOp 据此填 ctx.console_log。
    // 默认 80 与 HeartbeatSensorConfig.console_snapshot_lines 对齐,覆盖典型 rcu
    // stall / softlockup / hung_task / panic backtrace 多行上下文。
    // 0 = 不抓(等价于 ring buffer 不可用),退化到旧行为(report0 无 [console] block)。
    // ring buffer 实际容量 max_lines=200 (console_ring_buffer.hpp),取超出会自动截断。
    uint32_t                            abnormal_console_snapshot_lines = 80;

    // Wire-level payload upper bound (bytes). Assembler sets it from the
    // backend's wire constant (ivshmem: MAX_INPUT_SIZE = 4 MiB; XiUOS:
    // XIUOS_MAX_PAYLOAD = 512). Channel::Submit checks this before queueing.
    //
    // Required from any assembler that produces a Channel with shm == nullptr;
    // for ivshmem backends Channel falls back to ShmInfra::MaxInput() when
    // this field is left 0, preserving v1 behavior. New non-ivshmem backends
    // MUST populate this field explicitly — otherwise Channel rejects every
    // non-empty Submit (fail-closed).
    std::size_t                         max_payload_size = 0;

    // [crash-execution-history-ring] Layer-2 crash history depth: per-worker-slot
    // count-bounded ring of recently COMPLETED programs (mirrors syzkaller
    // LastExecuting). Lets a confirmed kernel-crash harvest reconstruct the recent
    // execution sequence, so async/deferred-trigger bugs (USB async firmware, RCU
    // callbacks, timers, workqueue-deferred frees) — whose triggering syscall has
    // already left the in-flight set — keep their context. 0 = disabled (Layer-1
    // in-flight-only behavior). See docs/plans/crash-execution-history-ring.md.
    std::size_t                         crash_history_depth = 16;

    // [Task2 syz-parity suppression] 注入的"这段 console 是否是真崩"判定。空 = 不过滤
    //   (所有 kKernelCrash 按真崩处理,旧行为)。非空时 Channel::HandleFault 对 kKernelCrash
    //   事件先问它,benign-only(如 mand-mount deprecation WARNING)→ 丢弃不 reboot。
    //   谓词的"数据"(suppression 正则表)属于 crash 子系统的 linux-kernel report parser;
    //   由 orchestrator(唯一同时握有 crash 子系统 + channel config 的层)在 linux-kernel
    //   target 上注入,通用 channel/health 不感知 linux 崩溃知识。
    std::function<bool(const std::string&)> is_real_kernel_crash;
};

// ChannelBuildContext — Assembler 的唯一输入（Channel 子系统对外的聚合入口）
//
// 严格两段式结构：
//
//   ChannelBuildContext {
//     ChannelConfig channel_cfg;                 // 中性编排参数（所有后端共用）
//     const IChannelBackendProfile* backend_profile;   // 后端组件 configs 打包（多态）
//     uint32_t vm_index;                         // substrate 级实例下标
//     std::string vm_workdir;                    // VM 独立工作目录（orchestrator 在
//                                                //   SessionLayout.vm_dir(i)/repro_dir(i)
//                                                //   算好后填入；Assembler 把它喂给
//                                                //   后端 RuntimeConfig.instance.workdir）
//   }
//
// 设计要旨：
//   - Channel 子系统对外只暴露这一个"聚合入口"；Orchestrator 构造 ctx 即
//     完成了 Channel 所需的全部配置描述（两段配置：中性 + 后端专属）。
//   - 中性字段（channel_id / n_workers / loop_interval / ...）统一在 ChannelConfig。
//   - 组件级 config（infra / runtime / worker / transport / health / recovery）
//     由具体 Profile 承载；Assembler 内部 dynamic_cast 到具体 profile 类型读字段，
//     失败则返回 Err。Assembler 不做"我是什么后端"的 if/else 分支判断。
//   - 换新后端 = 新 Profile + 新 Assembler；ChannelBuildContext 结构保持不变。
//   - vm_workdir 是 orchestrator → executor 方向的路径下发通道；executor/channel
//     对 SessionLayout 零感知（模块边界）。
struct ChannelBuildContext {
    ChannelConfig                           channel_cfg;
    const factory::IChannelBackendProfile*  backend_profile = nullptr;
    uint32_t                                vm_index = 0;
    std::string                             vm_workdir;
};

// ChannelComponents — Assembler 的输出
//
// 所有字段均为抽象类型；Channel 成员持有的就是这些接口。
// steps 允许为 null（非 ivshmem 场景可能没有 step event ring）。
// shm   允许为 null（非 ivshmem backend 可能没有 mmap backbone）。
//
// [Phase D/E] shm 与 CP/DP/Steps 共享 ShmInfra 生命周期；
//   由 Assembler 构造并以 shared_ptr 方式在组件之间分发。
struct ChannelComponents {
    std::shared_ptr<infra::ShmInfra>               shm;       // 可为 null
    std::unique_ptr<runtime::ISubstrate>           substrate;
    std::unique_ptr<control::IControlPlane>        control;
    std::unique_ptr<data::IDataPlane>              data;
    std::unique_ptr<evidence::IConsoleSource>      console;
    // §3.11-B — 跨 sensor 共享的 console 行缓冲。ConsoleSensor 写、
    // HeartbeatSensor 读。Assembler 构造，Channel 拥有；可为 null（
    // 不抓 console buffer 的 backend，如 mock channel）。
    std::unique_ptr<evidence::ConsoleRingBuffer>   console_ring;
    // 聚合前进时钟（检测器 A/B 的中立信号）。Assembler 构造，Channel 拥有；
    // 写方=HeartbeatSensor(心跳推进)+Channel(completion)；读方=VmAliveSensor+HeartbeatSensor。
    // 可为 null（不做 liveness 聚合检测的后端）。
    std::unique_ptr<evidence::ProgressClock>       progress_clock;
    std::unique_ptr<evidence::IStepEventSource>    steps;     // 可为 null
    std::unique_ptr<health::IHealthMonitor>        health;
    std::unique_ptr<recovery::IRecovery>           recovery;

    ChannelConfig                                  channel_cfg;
};

// IChannelAssembler — 合规后端组合装配接口
class IChannelAssembler {
public:
    virtual ~IChannelAssembler() = default;

    virtual std::string_view               Id() const = 0;

    // Assemble：装配组件并返回 ChannelComponents；装配期校验失败返回 Error。
    // 时序（StartVM / DeployArtifacts / Open console 等）由 Channel::Boot 执行。
    virtual Result<ChannelComponents>      Assemble(const ChannelBuildContext& ctx) = 0;
};

} // namespace refuzz::channel
