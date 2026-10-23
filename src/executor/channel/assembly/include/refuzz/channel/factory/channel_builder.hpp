#pragma once

// [v3.5 Phase D] ChannelBuilder — 将 Assembler 产出的 ChannelComponents 组装为 Channel
//
// 设计来源：docs/channel-redesign/v3.5/130_phase_D_builder.md
//
// 职责：
//   1. 校验 ChannelComponents 必填字段非空（提前拦截非法装配）
//   2. 通过 friend 关系调用 Channel 的 private 构造器
//   3. 返回 unique_ptr<Channel>；调用方负责 Boot/Close
//
// Builder 是**唯一**的从 ChannelComponents 到 Channel 的通路：
//   - Channel::Channel(ChannelComponents) 是 private；
//   - 只有 ChannelBuilder 通过 friend 可构造。
// 这样添加新 Assembler 时"必须经过 Builder"成为编译期约束。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>

namespace refuzz::channel {

class Channel;  // 前向：定义在 orchestration/include/refuzz/channel/channel_impl.hpp

class ChannelBuilder {
public:
    // Build：从已装配的 ChannelComponents 构造 Channel 实例（尚未 Boot）。
    //
    // 校验：
    //   - substrate / control / data / console / health / recovery 必须非空
    //   - shm / steps 可为空（非 ivshmem backend 或 mock 场景）
    //
    // 失败返回 Error{kConfig, ...}；成功返回 unique_ptr<Channel>。
    static Result<std::unique_ptr<Channel>> Build(ChannelComponents components);
};

} // namespace refuzz::channel
