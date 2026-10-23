#pragma once

// ChannelFactory — Channel 创建工厂
//
// 两段式签名：
//   Create(const ChannelConfig& cfg, const IChannelBackendProfile& profile)
//     → Result<std::unique_ptr<IChannel>>
//
// 设计约束：
//   - `ChannelCatalog::Build(id, ctx)` 是主线路径；ChannelFactory::Create
//     作为 Catalog 注册 lambda 的底层实现复用点（此处是
//     QemuIvshmemLinuxAssembler::AssembleAndBuild 的薄包装）。
//
// 职责：
//   1. 组装 ChannelBuildContext
//   2. 调 QemuIvshmemLinuxAssembler::AssembleAndBuild


#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/factory/channel_assembler.hpp"       // ChannelConfig
#include "refuzz/channel/factory/channel_backend_profile.hpp" // IChannelBackendProfile
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string>

namespace refuzz::channel {

namespace cc = refuzz::core::channel_contract;


class ChannelFactory {
public:
    /// @brief 中性 cfg + 后端 profile 两段式创建
    ///
    /// 内部组 ChannelBuildContext，直接走 QemuIvshmemLinuxAssembler::AssembleAndBuild。
    /// 选择哪个 Assembler 的职责在调用方（或 ChannelCatalog::Build）；此函数目前
    /// 硬连接到 QemuIvshmemLinuxAssembler，主要供直接使用者和内部测试调用。
    ///
    /// @param cfg     中性 channel config（channel_id / n_workers / loop_interval / ...）
    /// @param profile 后端专属 config（QemuIvshmemLinuxProfile / ...）
    /// @return        成功返回 IChannel 实例；配置非法返回 Error{kConfig, "..."}
    static Result<std::unique_ptr<IChannel>> Create(
        const ChannelConfig&                    cfg,
        const factory::IChannelBackendProfile&  profile);
};

} // namespace refuzz::channel
