#pragma once

// ReproChannel — 将 IChannel 封装为单任务事件驱动执行器
// repro 流程虽然是顺序执行模式（提交一个程序 → 等待结果 → 分析 → 下一个），
// 但底层仍然复用 executor 与 channel 的交互语义：
// - Submit 只负责发请求
// - DrainEvents(false) 只表示本轮没有事件，不等于本次执行超时
// - 只有匹配当前 executor_id 的 kTaskCompleted 才是本次执行结果

#include "refuzz/channel/channel.hpp"
#include "refuzz/crash/repro/core/exec_result.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::crash {

class ReproChannel {
public:
    explicit ReproChannel(refuzz::channel::IChannel* channel,
                          std::chrono::milliseconds execute_timeout =
                              std::chrono::milliseconds{30000});
    ~ReproChannel() = default;

    // [v1 old flow ROLLBACK]
    // 单任务执行：AcquireLease → Submit → 事件循环直到 completion / control-event / deadline
    // [v2 new flow 当前版本]
    // 单任务执行：Submit(原子分配 slot) → 事件循环直到 completion / control-event / deadline
    RunResult Execute(const std::vector<uint8_t>& payload, uint64_t executor_id);

    // 请求停止：后续执行/恢复快速返回，不再触发 restart/reboot。
    void RequestStop();

    // 两次运行之间只探测 channel 可用性；恢复由 channel 侧统一负责。
    bool RestartBetweenRuns();

    // 快速探测 channel 是否可用（不直接触发 recovery）
    bool EnsureReady();

private:
    bool StopRequested() const;

    refuzz::channel::IChannel* channel_ = nullptr;
    std::chrono::milliseconds execute_timeout_{30000};
    std::atomic<bool> stopping_{false};
};

} // namespace refuzz::crash
