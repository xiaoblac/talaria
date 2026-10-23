#pragma once

// QemuUartXiuosAssembler — "qemu_uart_xiuos" 后端组件装配器
//
// 设计来源：docs/channel-redesign/v4.0/090_extension_recipe.md
//
// 两段式配置输入：
//   - ctx.channel_cfg     : 中性编排参数（channel_id / n_workers / ...）
//   - ctx.backend_profile : dynamic_cast 到 factory::XiuosUartProfile；失败返回 Err
//
// 装配顺序（XiUOS 比 ivshmem 简单——无 ShmInfra、无 doorbell、无 SSH）：
//   XiuosUartBackbone (shared infra)
//     → XiuosUartSubstrate (QEMU virt-rv32 进程)
//     → XiuosUartControlPlane (backbone)
//     → XiuosUartDataPlane (backbone)
//     → NullConsoleSource / NoopHealthMonitor / NoopRecovery
// 以 ChannelComponents 形式交给 ChannelBuilder::Build；Channel::Boot 只做时序编排。
//
// 已知限制（Phase 2 §B v1，未来工作）：
//   - 没有真正的 XiuosUartConsoleSource，无法捕获 XiUOS KPrintf / HandleTrap 输出
//   - Noop Health/Recovery，VM 进程死亡不会自动重启
//   - n_workers > 1 被归一到 1（XiUOS in-kernel worker 单实例）

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string_view>

namespace refuzz::channel {

class IChannel;  // 前向

class QemuUartXiuosAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;

    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;

    // AssembleAndBuild = Assemble → ChannelBuilder::Build；返回 unique_ptr<IChannel>。
    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

}  // namespace refuzz::channel
