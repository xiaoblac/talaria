// Copyright 2026 reFuzz project author -------youngkk.
//
// ObservationBus: 默认 vector<unique_ptr<sink>> + 顺序广播实现。
// R2 引入。

#include "worker/observation/observation_bus.hpp"

namespace refuzz::worker {

void ObservationBus::ConfigureProcId(uint32_t proc_id)
{
    for (auto& s : sinks_) {
        s->ConfigureProcId(proc_id);
    }
}

void ObservationBus::AddSink(std::unique_ptr<IObservationSink> sink)
{
    if (sink != nullptr) {
        sinks_.push_back(std::move(sink));
    }
}

bool ObservationBus::InitAll()
{
    bool any_failed = false;
    for (auto& s : sinks_) {
        if (!s->Init()) {
            // 单个 sink Init 失败不致命：sink 自降级,bus 继续运行。
            any_failed = true;
        }
    }
    return !any_failed;
}

void ObservationBus::Publish(ObservationEvent ev, const ObservationContext& ctx)
{
    for (auto& s : sinks_) {
        s->OnEvent(ev, ctx);
    }
}

void ObservationBus::PackAllFeedback(uint8_t* out, uint32_t out_cap,
                                     uint32_t* inout_len)
{
    if (out == nullptr || inout_len == nullptr) {
        return;
    }
    for (auto& s : sinks_) {
        s->PackFeedback(out, out_cap, inout_len);
    }
}

uint32_t ObservationBus::SnapshotAllForCrash(uint8_t* out, uint32_t out_cap) const
{
    // async-signal-safe 路径：每个 sink 写到 out + cur_offset; 累加返回。
    if (out == nullptr || out_cap == 0) {
        return 0;
    }
    uint32_t total = 0;
    for (const auto& s : sinks_) {
        if (total >= out_cap) break;
        const uint32_t remaining = out_cap - total;
        const uint32_t wrote = s->SnapshotForCrash(out + total, remaining);
        total += wrote;
    }
    return total;
}

size_t ObservationBus::TotalBufferBytes() const
{
    size_t total = 0;
    for (const auto& s : sinks_) {
        total += s->BufferBytes();
    }
    return total;
}

bool ObservationBus::RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds)
{
    bool ok = true;
    for (auto& s : sinks_) {
        if (!s->RemapInternalFds(next_fd, preserved_fds)) {
            ok = false;
        }
    }
    return ok;
}

size_t ObservationBus::SinkCount() const
{
    return sinks_.size();
}

IExtraKcovControl* ObservationBus::FindExtraKcovControl()
{
    for (auto& s : sinks_) {
        if (IExtraKcovControl* ctrl = s->AsExtraKcovControl()) {
            return ctrl;
        }
    }
    return nullptr;
}

RuntimeFailure ObservationBus::RuntimeFailureState() const
{
    for (const auto& sink : sinks_) {
        const RuntimeFailure failure = sink->RuntimeFailureState();
        if (failure != RuntimeFailure::kNone) {
            return failure;
        }
    }
    return RuntimeFailure::kNone;
}

} // namespace refuzz::worker
