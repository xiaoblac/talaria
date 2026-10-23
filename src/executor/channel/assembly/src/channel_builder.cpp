// ChannelBuilder::Build 实现（v3.5 Phase D）
//
// 唯一"从 ChannelComponents 到 Channel"的通路：
//   1. 校验必填字段
//   2. 通过 friend 关系调用 Channel 的 private 构造器
//
// 外部代码不应直接 new Channel；Channel 构造器 private + friend ChannelBuilder
// 使得该约束在编译期可检。
//
// 设计来源：docs/channel-redesign/v3.5/130_phase_D_builder.md

#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/channel_impl.hpp"   // Channel 完整定义（friend 可见）
#include "refuzz/channel/result.hpp"

#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace refuzz::channel {

namespace {

bool ComponentsValid(const ChannelComponents& c, std::string* err)
{
    auto fail = [&](const char* msg) {
        if (err) *err = msg;
        return false;
    };
    if (!c.substrate) return fail("ChannelComponents.substrate must not be null");
    if (!c.control)   return fail("ChannelComponents.control must not be null");
    if (!c.data)      return fail("ChannelComponents.data must not be null");
    if (!c.console)   return fail("ChannelComponents.console must not be null");
    if (!c.health)    return fail("ChannelComponents.health must not be null");
    if (!c.recovery)  return fail("ChannelComponents.recovery must not be null");
    // steps / shm 允许为空（非 ivshmem backend 或 mock 场景）

    // input_queue_capacity 硬契约 — 所有装配路径必经此处,封死 parser 之外的入口
    // (mock/qemu/custom_health/测试直造 ChannelComponents 都会落到这里)。
    // - cap=0 会让 Submit 永远 kBusy 卡死整个 channel
    // - cap>UINT32_MAX 会在 channel.cpp 的 uint32_t cap 截断处出错
    const auto cap = c.channel_cfg.input_queue_capacity;
    if (cap < 1) {
        return fail("ChannelComponents.channel_cfg.input_queue_capacity must be >= 1");
    }
    if (cap > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        return fail("ChannelComponents.channel_cfg.input_queue_capacity must be <= UINT32_MAX");
    }

    return true;
}

} // namespace

Result<std::unique_ptr<Channel>> ChannelBuilder::Build(ChannelComponents components)
{
    std::string err;
    if (!ComponentsValid(components, &err)) {
        return Error{ErrorKind::kConfig,
                     "ChannelBuilder::Build validation failed: " + err};
    }
    return Result<std::unique_ptr<Channel>>::Ok(
        std::unique_ptr<Channel>(new Channel(std::move(components))));
}

} // namespace refuzz::channel
