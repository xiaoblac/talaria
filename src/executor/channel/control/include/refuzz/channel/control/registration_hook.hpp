#pragma once

// [v3.5 Phase B] RegistrationControlHook — CP→DP 的"可写"反向视图（中性类型）
//
// 原先位于 ivshmem_control_plane.hpp，Phase B 搬到此中性头以便 DataPlane 等
// 组件在不 include IvshmemControlPlane 的情况下接收 RegistrationControlHook。
//
// 为什么需要：
//   DataPlane 的 Resume 需要依据 guest/host state 重建"某 worker 是否已注册"；
//   如果让 DP 直接持有 IControlPlane* 并调 SetRegistered，会反向暴露 CP 全接口。
//   通过闭包只暴露 "set_registered(wid, val)" 这一个动作，最小化 CP→DP 权限。
//
// 非 ivshmem 后端也可以使用此 hook（甚至返回空闭包作为 no-op）。

#include <cstdint>
#include <functional>

namespace refuzz::channel::control {

struct RegistrationControlHook {
    std::function<void(uint32_t /*worker_id*/, bool /*registered*/)> set_registered;
};

} // namespace refuzz::channel::control
