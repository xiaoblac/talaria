#pragma once

// ConsoleSensor — 行级 Console 观察 Sensor
//
// 设计来源：docs/channel-redesign/v3/50_health.md §4.2 / 40_evidence.md §4
//
// 职责：
//   - 后台线程阻塞在 IConsoleSource::ReadLine 上读行
//   - 行级 pattern match：命中 kernel crash 模式 → Publish kKernelCrash
//   - Source 进入 kEof → Publish kVmDead（EOF 等价 VM 进程退出）
//   - Source 进入 kError → Publish kHealthInternalFault
//
// 与底层解耦：
//   - 输入源通过 IConsoleSource::ReadLine 抽象，不关心底层 fd / socket / pipe
//   - step_event_snapshot 字段来自注入的 IStepEventSource（可选；为 null 则不填）
//
// Pattern 集合：见 §18.3.4

#include "refuzz/channel/evidence/console_ring_buffer.hpp"
#include "refuzz/channel/evidence/console_source.hpp"
#include "refuzz/channel/evidence/step_event_source.hpp"
#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace refuzz::channel::health {

struct ConsoleSensorConfig {
    // crash pattern 匹配前保留的上文行数（滑动窗口）
    uint32_t pre_context_lines = 20;
    // crash pattern 匹配后继续收集的下文行数（含 match 行本身）
    uint32_t post_context_lines = 60;
    // ReadLine 单次 block 超时
    std::chrono::milliseconds read_line_timeout{200};
    // 是否采集 StepEventRing 快照
    bool capture_step_events = false;
};

class ConsoleSensor final : public IHealthSensor {
public:
    // 构造：注入 console source + 可选 step source + 可选 ring buffer
    // console_source 必须已 Open（Sensor 内不做 Open；由装配方负责）。
    // §3.11-B — `ring_buffer` 非空时，每读到一行就 push 一份到该 buffer，
    // 让 HeartbeatSensor / 诊断 dump 等其它消费者能旁路获取最近的 console
    // 上下文，不需要再次消费 IConsoleSource 流。null 时退化到旧行为。
    ConsoleSensor(evidence::IConsoleSource*        console_source,
                  evidence::IStepEventSource*      step_source,
                  ConsoleSensorConfig              config,
                  evidence::ConsoleRingBuffer*     ring_buffer = nullptr) noexcept;

    ~ConsoleSensor() override;

    ConsoleSensor(const ConsoleSensor&)            = delete;
    ConsoleSensor& operator=(const ConsoleSensor&) = delete;

    std::string_view Name() const override { return "console"; }

    Result<void> Start(HealthPublisher& publisher) override;
    void         Stop() override;
    void         Poke() override;

private:
    void ThreadMain();
    void ProcessLine(const std::string& line);
    // 构造 CrashFragment 并 Publish
    void ReportCrash(CrashKind kind, CrashEventOrigin origin);

    evidence::IConsoleSource*    console_source_;
    evidence::IStepEventSource*  step_source_ = nullptr;
    ConsoleSensorConfig          config_;
    HealthPublisher*             publisher_ = nullptr;
    // §3.11-B — 行旁路 buffer，供 HeartbeatSensor 等读取。可为 null。
    evidence::ConsoleRingBuffer* ring_buffer_ = nullptr;

    std::thread       thread_;
    std::atomic<bool> stop_flag_{false};
    bool              thread_running_ = false;

    // pattern 状态机（ThreadMain 独占）
    enum class State { IDLE, COLLECTING_POST };
    State                    state_        = State::IDLE;
    std::deque<std::string>  pre_context_;
    std::vector<std::string> post_context_;
    CrashKind                pending_kind_ = CrashKind::kKernelCrash;
};

} // namespace refuzz::channel::health
