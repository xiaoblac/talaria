// ProgressClock —— 中立的"聚合 guest 前进"时钟。
//
// 形状与 ConsoleRingBuffer 平级：一个不属于任何单个 sensor、也不属于 health
// 子系统的共享 liveness 信号，由 Channel/assembler 创建并按引用注入给写读两方。
//
//   写方（生产者）：HeartbeatSensor（某 worker 心跳推进时）、Channel 的 completion
//                   收割路径（一个 program 执行完 = guest 真在前进）。
//   读方（消费者）：VmAliveSensor（检测器 A：聚合冻结超时 → 推断 VM 死）、
//                   HeartbeatSensor（检测器 B：本 worker 冻结 while 聚合在前进 → 真卡）。
//
// 为什么不放进 health：health 的职责面是"产出 CrashEvent"，单向 sensor→Channel。
// "completion 发生了"本质是执行/fuzz 事件，不是 health 事件；把它塞进 HealthMonitor
// 会引入 Channel→health 的反向边、混淆关注点。聚合前进进度本来就缺一个家——按
// ConsoleRingBuffer 的样子在 evidence/ 立一等公民信号，各 sensor 只依赖它需要的这块。
//
// 生命周期：Channel 拥有（unique_ptr），声明顺序保证晚于引用它的 sensor / health_monitor
// 析构（与 console_ring_ 同一 ownership 槽）。
//
// 线程模型：多生产者 / 多消费者，单个 std::atomic<uint64_t> 即足够，无需锁。

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace refuzz::channel::evidence {

class ProgressClock {
public:
    // 构造即从 now 起步：避免"还没有任何 Note() 之前"被读成长时间冻结。
    ProgressClock() noexcept { last_us_.store(NowUs(), std::memory_order_relaxed); }

    ProgressClock(const ProgressClock&)            = delete;
    ProgressClock& operator=(const ProgressClock&) = delete;

    // 任一前进事件刷新时钟。热路径，release store。
    void Note() noexcept { last_us_.store(NowUs(), std::memory_order_release); }

    // 最近一次前进的时刻（steady_clock 微秒）。acquire load。
    uint64_t LastUs() const noexcept { return last_us_.load(std::memory_order_acquire); }

    // 重置为 now。Channel 在 ResumeMonitoring / reboot 完成后调用，避免停采期间的
    // 陈旧值被检测器 A 算进"聚合冻结时长"。
    void Reset() noexcept { Note(); }

private:
    static uint64_t NowUs() noexcept {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    std::atomic<uint64_t> last_us_{0};
};

} // namespace refuzz::channel::evidence
