#pragma once

// Ch32UartXiuosAssembler — "ch32_uart_xiuos" 后端组件装配器(物理 CH32V208RBT6 板)
//
// 设计来源:docs/plans/xiuos-ch32-bringup.md(Phase Q2)。
//
// 与 QemuUartXiuosAssembler **同构**,只换两处:
//   - Substrate:Ch32UartSubstrate(wlink flash/reset + 真串口)取代 XiuosUartSubstrate(spawn QEMU)。
//   - Backbone transport:serial(/dev/ttyACM*)取代 TCP。
// ControlPlane / DataPlane / NullConsoleSource / HealthMonitor(WedgeRelay + VmAlive)/
// Recovery 全部复用 XiUOS 同件(wire 协议 arch 无关)。
//
// 两段式配置输入:
//   - ctx.channel_cfg     : 中性编排参数
//   - ctx.backend_profile : dynamic_cast 到 factory::Ch32UartProfile;失败返回 Err

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string_view>

namespace refuzz::channel {

class IChannel;  // 前向

class Ch32UartXiuosAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;

    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;

    // AssembleAndBuild = Assemble → ChannelBuilder::Build;返回 unique_ptr<IChannel>。
    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

}  // namespace refuzz::channel
