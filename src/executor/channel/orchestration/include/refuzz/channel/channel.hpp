#pragma once

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <chrono>
#include <cstddef>
#include <vector>

// Forward-declare metric types to avoid pulling in metric headers from this interface.
namespace refuzz::core::metrics {
struct ChannelMetrics;
class MetricRegistry;
} // namespace refuzz::core::metrics

namespace refuzz::channel {

// 文件级 `namespace cc = refuzz::core::channel_contract;` 缩写，引用对外合同类型。
namespace cc = refuzz::core::channel_contract;

using EventList = std::vector<cc::ChannelEvent>;

// IChannel — 所有 Channel 实现的通用接口
//
// 只包含所有 Channel 类型都具备的方法：
//   - 生命周期（Boot/Close）
//   - 数据平面（Submit/DrainEvents）
//   - 观测平面（ObserveSnapshot/DrainObserveEvents）
//
// 实现特有方法（例如 class Channel 的 free_slots/inflight/generation/DetailSnapshot）
// 定义在各自的具体类中，不在此接口暴露。
class IChannel {
public:
    virtual ~IChannel() = default;

    // ── 生命周期 ──
    virtual refuzz::channel::Result<void> Boot() = 0;
    virtual void Close() = 0;

    // ── 数据平面 ──
    // 返回 3 种事件：Completion / AbnormalCompletion / Fault
    virtual cc::ChannelSubmitResult Submit(const cc::ChannelDispatchRequest& request,
                                           std::chrono::microseconds wait_for_slot) = 0;
    // [submit path heap churn 减少 2026-05-22] rvalue Submit overload —
    // caller std::move(req) 触发, impl 可 std::move 进 internal slot 避免
    // 一次 deep payload copy. Default forward to const& 让 subclass 不必
    // override (degrades to 1 copy inside concrete impl, ≡ 旧行为).
    virtual cc::ChannelSubmitResult Submit(cc::ChannelDispatchRequest&& request,
                                           std::chrono::microseconds wait_for_slot) {
        return Submit(static_cast<const cc::ChannelDispatchRequest&>(request),
                      wait_for_slot);
    }
    virtual bool DrainEvents(EventList& events,
                             std::chrono::microseconds timeout) = 0;

    // [machine-check C4.6 ③] Read the per-VM env facts worker-0 published into
    // the transport (ivshmem ShmHeader). Returns false if unavailable / not yet
    // published / non-ivshmem transport — the host then falls back to the static
    // SupportEnv. Default: not supported.
    virtual bool ReadGuestEnvFeatures(::EnvFeatures* /*out*/) const { return false; }

    // Publish the run-lifetime transition that the one-time boot-corpus
    // candidate phase has finished. Non-ivshmem channels have no mirror.
    virtual void PublishInitialCorpusTriaged() {}


    // ── 观测平面 ──
    virtual void AttachObservabilityPublishers(
        refuzz::core::BroadcastBus<cc::ChannelSnapshot>* snapshot_bus,
        refuzz::core::BroadcastBus<cc::ChannelObserveEvent>* event_bus,
        core::metrics::ChannelMetrics* metrics = nullptr,
        core::metrics::MetricRegistry* registry = nullptr) = 0;
    virtual cc::ChannelSnapshot ObserveSnapshot() const = 0;
    virtual bool DrainObserveEvents(cc::ChannelObserveEventList&, std::chrono::microseconds) = 0;
};

} // namespace refuzz::channel
