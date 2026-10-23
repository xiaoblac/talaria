#pragma once

// SifiveUartXiuosAssembler — "qemu_uart_sifive_u" 后端组件装配器
//
// 镜像 QemuUartXiuosAssembler,但目标是 app-surface 面:rv64 sifive_u + 分离构建
// kernel.elf/app.bin。装配时 dynamic_cast 到 factory::SifiveUartXiuosProfile,把
// machine / app_bin_path / app_load_addr 透传进**共用的** XiuosUartSubstrate::Config
// (同 fork-QEMU + TCP serial 机制,仅 argv 不同)。backbone / ControlPlane /
// DataPlane / health / recovery 与 qemu_uart_xiuos 完全相同 —— 全栈复用。
//
// 详见 docs/plans/xiuos-app-surface-fuzz-phase2.md。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string_view>

namespace refuzz::channel {

class IChannel;  // 前向

class SifiveUartXiuosAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;

    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;

    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

}  // namespace refuzz::channel
