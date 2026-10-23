#pragma once

// dispatch_record.hpp — Channel 内部诊断/跟踪类型
//
// 作用域：channel 组件内部使用（Channel::pending_ / DispatchState 流转）；
// 不进对外合同。channel-private，不应被外部模块 include；外部需要的类型
// 一律走 refuzz/core/channel_contract.hpp。

#include "refuzz/core/channel_contract.hpp"  // kAnyWorkerId
#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::channel {

// DispatchState — DispatchRecord 内部状态（见 docs/channel-redesign/v3/.. §18.4.2）
//   kActive    : 正常 inflight
//   kUntrusted : health_internal 强门控期间标记
enum class DispatchState : uint8_t {
    kActive = 0,
    kUntrusted,
};

// DispatchRecord — channel 内部唯一 inflight 状态源（loop_thread_ 独占写读）
struct DispatchRecord {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    uint32_t slot_id = 0;
    uint32_t dispatch_gen = 0;
    uint32_t generation = 0;
    uint64_t submit_ts_us = 0;
    refuzz::proto::TaskTrace trace{};
    std::vector<uint8_t> payload;
    // [v2 Epic 5 PR-5-B] TaskSlot.flags wire encoding; carries through
    // kUntrusted → re-dispatch path so KCOV_TRACE_CMP mode survives a worker
    // recovery cycle.
    uint32_t exec_flags = 0;
    // Strict worker-slot affinity carried from ChannelDispatchRequest. The
    // recovery rebuild loop must respect this — re-dispatching an affined
    // task to a different worker breaks caller-requested transport placement.
    // Resource identity is preserved separately in target_proc_id.
    // kAnyWorkerId means "no affinity, round-robin OK".
    uint32_t target_worker_id = ::refuzz::core::channel_contract::kAnyWorkerId;
    uint32_t target_proc_id = ::refuzz::core::channel_contract::kAnyProcId;
    DispatchState state = DispatchState::kActive;
    uint64_t last_dispatch_ts_us = 0;
};

} // namespace refuzz::channel
