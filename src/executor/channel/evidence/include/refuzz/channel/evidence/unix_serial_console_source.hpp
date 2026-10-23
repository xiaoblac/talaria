#pragma once

// [v3 Phase 3] UnixSerialConsoleSource — 基于 UNIX socket 的 IConsoleSource 实现
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §2.1 / 80_migration.md §4.1
//
// 语义：
//   - Open(endpoint)：对 endpoint.kind==kUnixSocket，connect AF_UNIX / SOCK_STREAM
//                     对 endpoint.kind==kFdBorrow，直接接管 fd（不 close，不 own）
//   - ReadLine(timeout)：阻塞读一行；超时 → nullopt（State 不变）；EOF/错误 → nullopt
//                        + State 切换到 kEof/kError；粘包时内部缓存断点
//   - Wakeup()：写 wakeup_pipe_[1] 唤醒 poll；不关 socket
//   - Close()：关 socket 与 pipe；State → kIdle（允许再次 Open）
//
// 并发约束：
//   - ReadLine 仅允许在单一消费者线程调用
//   - Wakeup / Close 允许在任意线程调用（通过 wakeup pipe 唤醒 poll）
//
// 非职责：
//   - 不做 crash pattern match（ConsoleSensor 做）
//   - 不做 fd-borrow 的生命周期管理（由 Substrate / 测试方负责）

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/evidence/console_source.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <optional>
#include <string>

namespace refuzz::channel::evidence {

class UnixSerialConsoleSource final : public IConsoleSource {
public:
    UnixSerialConsoleSource() = default;
    ~UnixSerialConsoleSource() override;

    UnixSerialConsoleSource(const UnixSerialConsoleSource&) = delete;
    UnixSerialConsoleSource& operator=(const UnixSerialConsoleSource&) = delete;

    Result<void> Open(const ConsoleEndpoint& endpoint) override;

    std::optional<std::string>
        ReadLine(std::chrono::milliseconds timeout) override;

    void Wakeup() override;
    void Close() override;

    State       CurrentState() const override { return state_.load(std::memory_order_acquire); }
    std::string LastError() const override;

private:
    // 关闭 fd/pipe，保留 state_ 不变；供 Close/Open 失败回滚内部使用
    void ReleaseFds() noexcept;

    // 由 Open(kUnixSocket) 建连，失败返回 Error；socket_fd_ 被填
    Result<void> ConnectUnixSocket(const std::string& path);

    // 从 socket 拉数据补 line_buffer_，按 '\n' 切出一行并返回
    // 返回 false 表示本次 poll 内没读到完整行（需要继续下一轮 poll/等）
    // pending_eof_ / pending_error_ 由本函数/poll 层置位
    bool TryConsumeFromBuffer(std::string& out_line);

    // 真实读 socket 到 line_buffer_ 尾；读 0 表示 EOF；<0 保留 errno 到 last_error_
    // 返回 false 表示本次 read 无法推进（EOF / 不可恢复错误），调用者应切状态退出
    bool PumpOnce();

    // fd 资源
    int  socket_fd_       = -1;
    bool socket_owned_    = false;   // kFdBorrow 时为 false，Close 不关它
    int  wakeup_pipe_[2]  = {-1, -1};

    // line-split 累积缓冲；Open 时清空
    std::string line_buffer_;

    // 状态机
    std::atomic<State> state_{State::kIdle};
    std::string        last_error_;
};

} // namespace refuzz::channel::evidence
