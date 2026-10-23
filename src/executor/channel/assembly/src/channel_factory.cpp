// ChannelFactory 实现
//
// 职责：
//   Create(ChannelConfig, IChannelBackendProfile)：组 ChannelBuildContext
//   后转发到 QemuIvshmemLinuxAssembler::AssembleAndBuild。

#include "refuzz/channel/factory/channel_factory.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_assembler.hpp"
#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include <memory>

namespace refuzz::channel {

// ============================================================
// Create — 两段式：中性 cfg + 后端 profile
// ============================================================
//
// 内部组 ChannelBuildContext 并透传给 QemuIvshmemLinuxAssembler::AssembleAndBuild。
// AssembleAndBuild 内部会走 ChannelBuilder::Build，完成"装配 + 构造 + 校验"。

Result<std::unique_ptr<IChannel>> ChannelFactory::Create(
    const ChannelConfig&                   cfg,
    const factory::IChannelBackendProfile& profile)
{
    ChannelBuildContext ctx;
    ctx.channel_cfg     = cfg;
    ctx.backend_profile = &profile;
    ctx.vm_index        = 0;
    return QemuIvshmemLinuxAssembler::AssembleAndBuild(ctx);
}

} // namespace refuzz::channel
