#pragma once

// IExecAdapter — repro 执行适配器接口（Adapter 层）
// Manager 只依赖该接口，不直接依赖具体 channel 交互细节。

#include "refuzz/crash/repro/core/exec_result.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::crash {

class IExecAdapter {
public:
    virtual ~IExecAdapter() = default;

    virtual bool EnsureReady() = 0;
    virtual RunResult Execute(const std::vector<uint8_t>& payload, uint64_t exec_id) = 0;
    virtual bool RestartBetweenRuns() = 0;
    virtual void RequestStop() = 0;
};

} // namespace refuzz::crash

