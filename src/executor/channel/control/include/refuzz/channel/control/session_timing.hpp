#pragma once

// [v3.5 Phase B] SessionTiming — Control 面握手相关的超时/轮询间隔（中性类型）
//
// 原先位于 ivshmem_control_plane.hpp，Phase B 搬到此中性头以便 DataPlane 等
// 组件在不 include IvshmemControlPlane 的情况下构造 SessionTiming。
//
// 非职责：
//   - 不与 ivshmem 语义绑定；纯 duration 聚合体
//   - 不感知任何 IControlPlane/IDataPlane 具体实现

#include <chrono>

namespace refuzz::channel::control {

struct SessionTiming {
    std::chrono::microseconds wait_ready_timeout_us{10'000'000}; // 10s
    std::chrono::microseconds wait_ready_poll_us{1'000};         // 1ms
};

} // namespace refuzz::channel::control
