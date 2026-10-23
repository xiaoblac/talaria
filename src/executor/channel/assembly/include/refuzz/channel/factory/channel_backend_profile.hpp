#pragma once

// channel_backend_profile.hpp — IChannelBackendProfile
//
// Backend-specific 配置的多态 tag 接口。
//
// 设计意图：
//   - Channel 编排层（Channel / ChannelBuilder / 大部分 Catalog 逻辑）对 profile
//     类型保持无感。
//   - 只有 Assembler 才消费具体 profile：在 `Assemble(ChannelBuildContext)` 里
//     `dynamic_cast<const ConcreteProfile*>(ctx.backend_profile)`，失败则返回
//     Err；成功则从 profile 字段构造组件。
//   - BackendId() 是唯一要求具体 profile 实现的方法，用于：
//       a) Catalog 注册键对齐
//       b) dynamic_cast 失败时的诊断消息
//
// 不在这里定义的能力：
//   - 没有 DefaultSessionTiming() 之类的虚方法。SessionTiming 由 Channel::Boot
//     从 ChannelConfig::wait_ready_timeout 派生后注入 CP，而非 profile 提供。
//   - 没有容量/能力 flag。组件差异通过"换 Assembler"表达，不在 profile 接口层。

#include <string_view>

namespace refuzz::channel::factory {

class IChannelBackendProfile {
public:
    virtual ~IChannelBackendProfile() = default;

    // 稳定、唯一的后端标识（与 ChannelCatalog 注册键对齐）。
    // 推荐命名格式："<substrate>_<transport>_<guest>"，例如 "qemu_ivshmem_linux"。
    virtual std::string_view BackendId() const noexcept = 0;
};

} // namespace refuzz::channel::factory
