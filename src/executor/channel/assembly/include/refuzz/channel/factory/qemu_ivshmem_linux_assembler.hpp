#pragma once

// QemuIvshmemLinuxAssembler — "qemu_ivshmem_linux" 后端的组件装配器
//
// 设计来源：docs/channel-redesign/v4.0/080_flow_matrix.md（组装顺序）
//           docs/channel-redesign/v4.0/090_extension_recipe.md（扩展点）
//
// 两段式配置输入：
//   - ctx.channel_cfg        : 中性编排参数（channel_id / n_workers / loop_interval / ...）
//   - ctx.backend_profile    : dynamic_cast 到 QemuIvshmemLinuxProfile；失败返回 Err
//
// 按组件依赖顺序构造：
//   ShmInfra → Runtime(ISubstrate) → IvshmemControlPlane → IvshmemDataPlane
//   → UnixSerialConsoleSource / IvshmemStepEventSource
//   → HealthMonitor(+ Heartbeat/Console/VmAlive Sensor) → Recovery
// 以 ChannelComponents 形式交给 ChannelBuilder::Build；Channel::Boot 只做时序编排。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string_view>

namespace refuzz::channel {

namespace cc = refuzz::core::channel_contract;


class IChannel;  // 前向

class QemuIvshmemLinuxAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;

    // 构造七件套 + ShmInfra；返回 ChannelComponents。
    //   - shm        : shared_ptr<ShmInfra>，被 CP/DP/Steps 共享
    //   - substrate  : unique_ptr<Runtime>（继承 ISubstrate）
    //   - control    : unique_ptr<IvshmemControlPlane>
    //   - data       : unique_ptr<IvshmemDataPlane>
    //   - console    : unique_ptr<UnixSerialConsoleSource>（Open 延后到 Boot）
    //   - steps      : unique_ptr<IvshmemStepEventSource>
    //   - health     : unique_ptr<HealthMonitor>（Sensor 已 AddSensor，view 空，Boot 里 Bind）
    //   - recovery   : unique_ptr<Recovery>（持 ISubstrate* + DeployBundle）
    //   - channel_cfg: ChannelConfig 直接透传（Assembler 只回填 backend_id）
    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;

    // AssembleAndBuild = Assemble → ChannelBuilder::Build；返回 unique_ptr<IChannel>。
    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

} // namespace refuzz::channel
