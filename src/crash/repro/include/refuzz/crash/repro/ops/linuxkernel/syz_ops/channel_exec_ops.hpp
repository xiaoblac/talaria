#pragma once

// syz_ops 执行交互入口：通过 ReproChannel 适配 channel 交互。
#include "refuzz/crash/repro/core/exec_adapter.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/adapter/repro_channel.hpp"

namespace refuzz::crash {

class ChannelExecOps : public IExecAdapter {
public:
    explicit ChannelExecOps(ReproChannel& channel)
        : channel_(channel)
    {}

    bool EnsureReady() override
    {
        return channel_.EnsureReady();
    }

    RunResult Execute(const std::vector<uint8_t>& payload, uint64_t exec_id) override
    {
        return channel_.Execute(payload, exec_id);
    }

    bool RestartBetweenRuns() override
    {
        return channel_.RestartBetweenRuns();
    }

    void RequestStop() override
    {
        channel_.RequestStop();
    }

private:
    ReproChannel& channel_;
};

} // namespace refuzz::crash

