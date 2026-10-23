#pragma once

// [v3 Phase 1.B] IConsoleSource — 行流抽象（console / dmesg / stdio）
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §2.1
// 职责：
//   - Open(endpoint)：按描述符建连接
//   - ReadLine(timeout)：阻塞读一行；超时 / EOF / 错误均返回 nullopt
//   - Wakeup()：唤醒阻塞的 ReadLine（Sensor Stop / HealthMonitor Suspend 使用）
//   - Close() / CurrentState() / LastError()
//
// 非职责：
//   - 不 pattern match（ConsoleSensor 做）
//   - 不上报 VmDead（ConsoleSensor 观察 kEof 后 Publish）
//   - 不缓存多行（一次一行；上层自己维护窗口）

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/result.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace refuzz::channel::evidence {

class IConsoleSource {
public:
    virtual ~IConsoleSource() = default;

    // Open：按 endpoint 建立连接；成功后 CurrentState()==kOpen
    virtual Result<void> Open(const ConsoleEndpoint& endpoint) = 0;

    // ReadLine：
    //   - 返回 line：读到一行完整数据（去掉行末换行符）
    //   - 返回 nullopt：超时 / EOF / 可恢复错误；原因由 CurrentState() 区分
    //
    // 约束：不允许丢行 —— 底层 TCP 粘包 / 部分读必须内部缓存拼回行边界
    virtual std::optional<std::string>
        ReadLine(std::chrono::milliseconds timeout) = 0;

    // Wakeup：唤醒阻塞在 ReadLine 的线程；实现用 pipe / eventfd / socket shutdown
    virtual void Wakeup() = 0;

    virtual void Close() = 0;

    // 状态查询（ConsoleSensor 用来判定 EOF→VmDead）
    enum class State : uint8_t { kIdle, kOpen, kEof, kError };

    virtual State       CurrentState() const = 0;
    virtual std::string LastError() const = 0;
};

} // namespace refuzz::channel::evidence
