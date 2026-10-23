#pragma once

// XiuosReproExecOps — XiUOS 专属的 repro 执行适配器。
//
// XiUOS 的 finding 多是 wedge / worker-dead:wedge = worker 永久阻塞在某个 ecall
// 里,worker-dead = worker 进程死掉。两者都让 worker 对下一次运行不可用。
//
// channel 自带健康监控(WedgeRelaySensor → recovery_)会在后台线程上**安全地**重启
// 卡死的 worker(实测主 channel ~140ms 完成,generation 自增);但它的检测窗口比单次
// Execute 的超时长。通用 ChannelExecOps 在 2.5s execute_timeout 一到就返回 timed_out,
// 紧接着把下一个候选丢给还卡着、recovery 还没触发的 worker → 后续每个候选都超时 →
// minimize 把"还在重现"误判到每个候选头上 → 程序过度坍缩成单条(常是被 worker 守卫
// 短路、根本到不了内核的)调用。
//
// 本适配器自愈:某次运行把 worker 弄坏(timeout/crash/error)后,在跑下一个候选**之前**
// 等待 channel 自身的 recovery 完成(轮询 snapshot 直到 generation 自增且 lifecycle 回到
// running)。**不**自己 Close→Boot(裸重启 substrate 不安全,会段错误);只同步等待既有的、
// 设计好的安全 recovery 路径。这样每个候选都在"运行前健康"的 worker 上评估,verdict 因此
// 可归因到该候选本身。
//
// 不改动通用/syz 侧:复用 ReproChannel 做事件循环执行(组合,不修改),只额外持有 IChannel
// 句柄用于观测 recovery 进度。仅 XiUOS target 装配此适配器(见 orchestrator 按
// IReproEngine::RequiresHardRebootBetweenRuns 选路)。

#include "refuzz/channel/channel.hpp"
#include "refuzz/crash/repro/core/exec_adapter.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/adapter/repro_channel.hpp"

#include <atomic>
#include <chrono>
#include <thread>

namespace refuzz::crash {

class XiuosReproExecOps : public IExecAdapter {
public:
    // `channel` 复用做单任务事件循环执行;`vm` 是同一条底层 channel,用于观测 recovery
    // 进度。两者必须指向同一 IChannel。recovery_wait 是等待 channel 自愈的上限。
    XiuosReproExecOps(ReproChannel& channel, refuzz::channel::IChannel& vm,
                      std::chrono::milliseconds recovery_wait = std::chrono::milliseconds{12000})
        : channel_(channel), vm_(vm), recovery_wait_(recovery_wait)
    {}

    bool EnsureReady() override
    {
        return RecoverIfPoisoned() && channel_.EnsureReady();
    }

    RunResult Execute(const std::vector<uint8_t>& payload, uint64_t exec_id) override
    {
        // 保证本候选在"运行前健康"的 worker 上跑:若上一次运行弄坏了 worker,先等 recovery。
        if (!RecoverIfPoisoned()) {
            RunResult r;
            r.error = true;
            return r;
        }
        RunResult run = channel_.Execute(payload, exec_id);
        // wedge(timeout)/ worker-dead(crash)/ channel error 都让 worker 对下一次运行
        // 不可用 → 记下当前 generation,下个 Execute 进来先等它被 recovery 自增。
        poisoned_ = run.timed_out || run.crashed || run.error;
        if (poisoned_) {
            poisoned_generation_ = vm_.ObserveSnapshot().generation;
        }
        return run;
    }

    bool RestartBetweenRuns() override
    {
        return RecoverIfPoisoned() && channel_.EnsureReady();
    }

    void RequestStop() override
    {
        stopping_.store(true);
        channel_.RequestStop();
    }

private:
    bool RecoverIfPoisoned()
    {
        if (!poisoned_) {
            return true;
        }
        // 等 channel 自带的 recovery(WedgeRelaySensor → recovery_,后台线程)重启 worker:
        // generation 自增 + lifecycle 回到 running == 拿到全新 worker。轮询而非裸重启。
        const auto deadline = std::chrono::steady_clock::now() + recovery_wait_;
        while (std::chrono::steady_clock::now() < deadline && !stopping_.load()) {
            const auto snap = vm_.ObserveSnapshot();
            const bool rebooted =
                snap.generation != 0 &&
                snap.generation != poisoned_generation_ &&
                snap.lifecycle_state ==
                    refuzz::core::channel_contract::ChannelLifecycleState::kRunning;
            if (rebooted) {
                poisoned_ = false;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        return false;
    }

    ReproChannel& channel_;
    refuzz::channel::IChannel& vm_;
    std::chrono::milliseconds recovery_wait_;
    bool poisoned_ = false;
    std::uint32_t poisoned_generation_ = 0;
    std::atomic<bool> stopping_{false};
};

} // namespace refuzz::crash
