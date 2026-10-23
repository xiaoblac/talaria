// ChildWaiter: async child-exit detection,pidfd_open 优先,WNOHANG waitpid
// fallback。
//
// 服务 P4 DoubleForkTopology — daemon `unshare(NEWPID); fork()` 出 loop child
// 后,daemon 主循环还要处理 ivshmem RPC / 多 worker 协调,不能简单阻塞 waitpid。
// pidfd 把"child 退出"变成 fd event,加进 epoll/poll 跟 RPC / 设备 IO multiplex。
//
// 路径选择:
//   - pidfd_open(pid, 0) 成功(kernel >= 5.3 + CAP_KILL or owner): pidfd 路径,
//     PollFd() 返 fd >= 0 给 epoll 用;HasExited() 走 poll(fd, POLLIN, 0)。
//   - pidfd_open 失败: fallback,PollFd() 返 -1,HasExited() / WaitFor 走
//     waitpid(WNOHANG) 轮询。两种模式 reap 都用 waitpid(给 ExitStatus())。
//
// 单 child 监控,move-only。Watch 后可 Reset 重新 Watch 别的 pid。

#pragma once

#include <cstdint>
#include <sys/types.h>

namespace refuzz::worker::topology {

class ChildWaiter {
public:
    ChildWaiter() = default;
    ~ChildWaiter();

    ChildWaiter(const ChildWaiter&) = delete;
    ChildWaiter& operator=(const ChildWaiter&) = delete;
    ChildWaiter(ChildWaiter&& other) noexcept;
    ChildWaiter& operator=(ChildWaiter&& other) noexcept;

    // 开始监控指定 child pid。
    // 成功返 0(pidfd 或 fallback 路径都算成功);invalid pid 返非 0。
    // 若 pidfd_open 不可用(老 kernel / 权限),自动 fallback,PollFd() 返 -1。
    int Watch(pid_t pid);

    // pidfd_open 成功路径下返 pidfd(>= 0);fallback 路径返 -1。
    // pidfd 可加进 epoll(EPOLLIN)/poll(POLLIN) 等 child 死亡通知。
    int PollFd() const { return pidfd_; }
    int ReleasePollFd();

    // pidfd 路径是否激活。等价于 PollFd() >= 0,语义更清晰用于 perf 统计。
    bool PidfdActive() const { return pidfd_ >= 0; }

    // 当前监控的 pid;Watch 之前或 Reset 之后返 -1。
    pid_t Pid() const { return pid_; }

    // 非阻塞查 child 是否已退出。若 child 已死且本次 reap 成功,exit_status_
    // 被填,返 true;子后续调用直接返 true,不再 syscall。
    bool HasExited();

    // 阻塞最多 timeout_ms 等 child 退出。返 true=已退出,false=超时。
    // pidfd 路径用 poll(POLLIN, timeout_ms);fallback 路径用 waitpid 轮询。
    bool WaitFor(uint32_t timeout_ms);

    // ChildExited()/WaitFor() 返 true 后才有意义的 wstatus(可喂
    // WIFEXITED/WIFSIGNALED 等宏)。
    int ExitStatus() const { return exit_status_; }

    // 关 pidfd,清状态;Pid() 之后返 -1。
    void Reset();

private:
    // Try reap with WNOHANG. Returns true if child reaped this call (sets
    // exit_status_ + exited_) or if already reaped earlier.
    bool TryReap();

    pid_t pid_ = -1;
    int pidfd_ = -1;
    int exit_status_ = 0;
    bool exited_ = false;
};

} // namespace refuzz::worker::topology
