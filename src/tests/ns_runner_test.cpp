// Test: NsRunnerSupervisor — D12 ns-runner layer 单元测试。
//
// 8 个子测试,host non-root 跑(unshare(NEWPID) 通常 EPERM 静默 fallback;
// ns_runner.cpp 内部已写"unshare 失败仍 fork loop_child"的兜底语义):
//
//   1. Spawn + IPC echo + Stop 干净
//      验:daemon 写 ready_w → loop_child read 到 → 写 done_w → daemon 读到。
//      Stop 后 fd 全 -1,pid -1。
//
//   2. Respawn 多次
//      验:连续 Respawn 5 次,每次新 pid 不同,IPC 每次仍工作。这是 D12
//      最核心的不变量 —— 每次新 ns-runner 进程,unshare 永远是"首次",
//      不再撞 D11 修的 EINVAL。
//
//   3. loop_child 主动 exit → daemon 收到 EOF + ns-runner 退出
//      loop_child 入口立即 _exit(7) → ns-runner waitpid → _exit(7) →
//      daemon HasExited()=true,ExitStatus 解出 WEXITSTATUS == 7。done
//      pipe daemon 端读应当返 0(EOF)。
//
//   4. Stop() 是 idempotent
//      未 Spawn 调 Stop → no-op;Spawn + Stop + Stop 第二次 Stop 也 no-op。
//
//   5. Spawn 失败时 Spawn 不留半态
//      故意 spawn 第一次成功 → 不 Stop → 第二次 Spawn 应当 fail-fast
//      (already spawned 路径)。
//
//   6. StopDomainHandle 使用单一 absolute deadline
//      每阶段配置 5s，但总 deadline 50ms；验证不会串加阶段预算，且 failed
//      handle 仍可由下一次统一 Stop 重试。
//
//   7. partial startup without loop pidfd never claims forced cleanup.
//
//   8. group kill covers a loop descendant and ns-runner has an isolated PGID.

#include "worker/topology/ns_runner.hpp"
#include "worker/log/log_macros.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

volatile sig_atomic_t g_running = 1;

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace tp = refuzz::worker::topology;

namespace {

// Echo entry: loop_child read ready_r → write 同样字节到 done_w,直到 EOF。
void EchoEntry(int ready_r, int done_w, void* /*user*/)
{
    uint8_t buf[64];
    while (true) {
        ssize_t n;
        do {
            n = ::read(ready_r, buf, sizeof(buf));
        } while (n < 0 && errno == EINTR);
        if (n <= 0) _exit(0);   // EOF / error

        size_t off = 0;
        while (off < static_cast<size_t>(n)) {
            ssize_t w = ::write(done_w, buf + off, static_cast<size_t>(n) - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                _exit(11);
            }
            off += static_cast<size_t>(w);
        }
    }
}

// Exit-7 entry: 立即 _exit(7);测 daemon 检测 ns-runner 退出 + 拿 ExitStatus。
void ExitSevenEntry(int /*ready_r*/, int /*done_w*/, void* /*user*/)
{
    _exit(7);
}

struct GroupTreeArgs {
    int status_w = -1;
};

void GroupTreeEntry(int /*ready_r*/, int done_w, void* user)
{
    auto* args = static_cast<GroupTreeArgs*>(user);
    const pid_t descendant = ::fork();
    if (descendant < 0) {
        _exit(21);
    }
    if (descendant == 0) {
        for (;;) {
            ::pause();
        }
    }
    ssize_t written;
    do {
        written = ::write(done_w, &descendant, sizeof(descendant));
    } while (written < 0 && errno == EINTR);
    if (written != static_cast<ssize_t>(sizeof(descendant))) {
        _exit(22);
    }
    const uint8_t ready = 1;
    if (args != nullptr && args->status_w >= 0) {
        (void)::write(args->status_w, &ready, sizeof(ready));
    }
    for (;;) {
        ::pause();
    }
}

bool DoEchoOnce(tp::NsRunnerSupervisor& sup, const char* tag)
{
    const char msg[] = "abc";
    ssize_t w = ::write(sup.ReadyWriteFd(), msg, sizeof(msg));
    if (w != static_cast<ssize_t>(sizeof(msg))) {
        std::fprintf(stderr, "FAIL[%s]: write ready_w n=%zd errno=%d\n",
                     tag, w, errno);
        return false;
    }
    char rbuf[16] = {};
    ssize_t r;
    do {
        r = ::read(sup.DoneReadFd(), rbuf, sizeof(rbuf));
    } while (r < 0 && errno == EINTR);
    if (r != static_cast<ssize_t>(sizeof(msg))) {
        std::fprintf(stderr, "FAIL[%s]: read done_r n=%zd errno=%d\n",
                     tag, r, errno);
        return false;
    }
    if (std::memcmp(rbuf, msg, sizeof(msg)) != 0) {
        std::fprintf(stderr, "FAIL[%s]: echo mismatch got=%.*s\n",
                     tag, static_cast<int>(r), rbuf);
        return false;
    }
    return true;
}

bool TestSpawnEchoStop()
{
    tp::NsRunnerSupervisor sup;
    if (sup.Spawn(&EchoEntry, nullptr) != 0) {
        std::fprintf(stderr, "FAIL: Spawn returned non-zero\n");
        return false;
    }
    if (sup.NsRunnerPid() <= 0 ||
        sup.PollFd() < 0 ||
        sup.LoopPollFd() < 0 ||
        sup.ReadyWriteFd() < 0 ||
        sup.DoneReadFd() < 0) {
        std::fprintf(stderr, "FAIL: bad state after Spawn pid=%d r=%d d=%d\n",
                     sup.NsRunnerPid(),
                     sup.ReadyWriteFd(), sup.DoneReadFd());
        return false;
    }
    if ((::fcntl(sup.LoopPollFd(), F_GETFD) & FD_CLOEXEC) == 0 ||
        sup.LoopHasExited()) {
        std::fprintf(stderr, "FAIL: transferred loop pidfd flags/liveness invalid\n");
        return false;
    }
    if (!DoEchoOnce(sup, "spawn-echo")) return false;

    if (sup.Stop() != tp::DomainStopResult::kForced) {
        std::fprintf(stderr, "FAIL: active Stop did not report forced cleanup\n");
        return false;
    }

    if (sup.NsRunnerPid() != -1 ||
        sup.ReadyWriteFd() != -1 ||
        sup.DoneReadFd() != -1) {
        std::fprintf(stderr, "FAIL: state not cleared after Stop pid=%d r=%d d=%d\n",
                     sup.NsRunnerPid(),
                     sup.ReadyWriteFd(), sup.DoneReadFd());
        return false;
    }
    std::fprintf(stderr, "PASS: Spawn + echo + Stop\n");
    return true;
}

bool TestRespawnMany()
{
    tp::NsRunnerSupervisor sup;
    pid_t prev = -1;
    for (int i = 0; i < 5; ++i) {
        int rc = (i == 0) ? sup.Spawn(&EchoEntry, nullptr)
                          : sup.Respawn(&EchoEntry, nullptr);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL: iter=%d (Re)spawn rc=%d\n", i, rc);
            return false;
        }
        pid_t cur = sup.NsRunnerPid();
        if (cur <= 0) {
            std::fprintf(stderr, "FAIL: iter=%d invalid pid=%d\n", i, cur);
            return false;
        }
        if (cur == prev) {
            std::fprintf(stderr,
                         "FAIL: iter=%d pid=%d reused (kernel 应当给新 pid)\n",
                         i, cur);
            return false;
        }
        if (!DoEchoOnce(sup, "respawn-echo")) {
            std::fprintf(stderr, "FAIL: iter=%d echo failed\n", i);
            return false;
        }
        prev = cur;
    }
    sup.Stop();
    std::fprintf(stderr, "PASS: Respawn 5 times, each new pid + IPC works\n");
    return true;
}

bool TestLoopChildExit()
{
    tp::NsRunnerSupervisor sup;
    if (sup.Spawn(&ExitSevenEntry, nullptr) != 0) {
        std::fprintf(stderr, "FAIL: Spawn (exit-7 entry) rc != 0\n");
        return false;
    }

    // 等 ns-runner 死 + reap。
    if (!sup.WaitFor(2000)) {
        std::fprintf(stderr, "FAIL: WaitFor(2000ms) didn't see ns-runner exit\n");
        sup.Stop();
        return false;
    }
    if (!sup.HasExited()) {
        std::fprintf(stderr, "FAIL: HasExited() false after WaitFor true\n");
        sup.Stop();
        return false;
    }
    if (!sup.LoopHasExited()) {
        std::fprintf(stderr, "FAIL: loop pidfd did not independently report exit\n");
        sup.Stop();
        return false;
    }

    const int status = sup.ExitStatus();
    // ns-runner _exit(WEXITSTATUS(loop_child_wstatus)) = _exit(7)。
    // 允许 ChildWaiter fallback ECHILD path 丢 status(已知边界,见
    // child_waiter_test TestChildKilledBySignal)。
    if (status != 0 && (!WIFEXITED(status) || WEXITSTATUS(status) != 7)) {
        std::fprintf(stderr,
                     "FAIL: ExitStatus=0x%x (expected WIFEXITED 7 or 0)\n",
                     status);
        sup.Stop();
        return false;
    }

    // done pipe 应当 EOF(loop_child 死,ns-runner close 所有 fd,daemon 端
    // read 拿 0)。
    char buf[8];
    ssize_t r = ::read(sup.DoneReadFd(), buf, sizeof(buf));
    if (r != 0) {
        std::fprintf(stderr,
                     "FAIL: expected EOF on done pipe, read returned %zd errno=%d\n",
                     r, errno);
        sup.Stop();
        return false;
    }

    sup.Stop();
    std::fprintf(stderr,
                 "PASS: loop_child _exit(7) → ns-runner exit propagated (status=0x%x)\n",
                 status);
    return true;
}

bool TestStopIdempotent()
{
    tp::NsRunnerSupervisor sup;

    // 未 spawn 直接 Stop:no-op,不该崩。
    sup.Stop();
    if (sup.NsRunnerPid() != -1) {
        std::fprintf(stderr, "FAIL: Stop on unspawned shouldn't set pid\n");
        return false;
    }

    if (sup.Spawn(&EchoEntry, nullptr) != 0) {
        std::fprintf(stderr, "FAIL: Spawn rc != 0\n");
        return false;
    }
    if (sup.Stop() != tp::DomainStopResult::kForced ||
        sup.Stop() != tp::DomainStopResult::kClean) {
        std::fprintf(stderr, "FAIL: Stop result is not forced then clean\n");
        return false;
    }
    if (sup.NsRunnerPid() != -1 || sup.ReadyWriteFd() != -1) {
        std::fprintf(stderr, "FAIL: double Stop didn't keep cleared state\n");
        return false;
    }
    std::fprintf(stderr, "PASS: Stop idempotent\n");
    return true;
}

bool TestDoubleSpawnGuard()
{
    tp::NsRunnerSupervisor sup;
    if (sup.Spawn(&EchoEntry, nullptr) != 0) {
        std::fprintf(stderr, "FAIL: first Spawn rc != 0\n");
        return false;
    }
    // 不 Stop 再 Spawn 应当 fail。
    if (sup.Spawn(&EchoEntry, nullptr) == 0) {
        std::fprintf(stderr,
                     "FAIL: second Spawn without Stop should fail (already spawned guard)\n");
        sup.Stop();
        return false;
    }
    sup.Stop();
    std::fprintf(stderr, "PASS: double-Spawn guarded\n");
    return true;
}

bool TestAbsoluteStopDeadline()
{
    int exited_loop_fds[2] = {-1, -1};
    int child_ready_fds[2] = {-1, -1};
    if (::pipe2(exited_loop_fds, O_CLOEXEC) != 0 ||
        ::pipe2(child_ready_fds, O_CLOEXEC) != 0) {
        std::perror("pipe2");
        if (exited_loop_fds[0] >= 0) {
            ::close(exited_loop_fds[0]);
        }
        if (exited_loop_fds[1] >= 0) {
            ::close(exited_loop_fds[1]);
        }
        if (child_ready_fds[0] >= 0) {
            ::close(child_ready_fds[0]);
        }
        if (child_ready_fds[1] >= 0) {
            ::close(child_ready_fds[1]);
        }
        return false;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        std::perror("fork");
        ::close(exited_loop_fds[0]);
        ::close(exited_loop_fds[1]);
        ::close(child_ready_fds[0]);
        ::close(child_ready_fds[1]);
        return false;
    }
    if (pid == 0) {
        ::close(exited_loop_fds[0]);
        ::close(exited_loop_fds[1]);
        ::close(child_ready_fds[0]);
        const uint8_t ready = 1;
        (void)::write(child_ready_fds[1], &ready, sizeof(ready));
        ::close(child_ready_fds[1]);
        for (;;) {
            ::pause();
        }
    }
    ::close(exited_loop_fds[1]);
    ::close(child_ready_fds[1]);
    uint8_t child_ready = 0;
    const ssize_t child_ready_size =
        ::read(child_ready_fds[0], &child_ready, sizeof(child_ready));
    ::close(child_ready_fds[0]);
    if (child_ready_size != static_cast<ssize_t>(sizeof(child_ready)) ||
        child_ready != 1) {
        (void)::kill(pid, SIGKILL);
        (void)::waitpid(pid, nullptr, 0);
        ::close(exited_loop_fds[0]);
        std::fprintf(stderr, "FAIL: stop deadline child did not become ready\n");
        return false;
    }

    tp::DomainHandle handle{};
    handle.pid = pid;
    handle.loop_pidfd = exited_loop_fds[0];
    handle.separate_runner = true;

    tp::DomainStopPlan long_plan = tp::StartupCleanupStopPlan();
    long_plan.kill_timeout_ms = 5000;
    long_plan.runner_timeout_ms = 5000;
    long_plan.reap_timeout_ms = 5000;
    const auto started = std::chrono::steady_clock::now();
    const auto result = tp::StopDomainHandle(
        handle, now_us() + 50'000ULL, long_plan);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    tp::DomainStopResult cleanup_result = result;
    if (result == tp::DomainStopResult::kFailed) {
        tp::DomainStopPlan cleanup = tp::StartupCleanupStopPlan();
        cleanup.kill_timeout_ms = 1000;
        cleanup.runner_timeout_ms = 1000;
        cleanup.reap_timeout_ms = 1000;
        cleanup_result = tp::StopDomainHandle(
            handle, tp::DomainStopDeadlineUs(cleanup), cleanup);
    }
    if (cleanup_result == tp::DomainStopResult::kFailed) {
        if (handle.pid > 0) {
            (void)::kill(handle.pid, SIGKILL);
            (void)::waitpid(handle.pid, nullptr, 0);
        }
        if (handle.loop_pidfd >= 0) {
            ::close(handle.loop_pidfd);
        }
    }

    if (elapsed_ms >= 1000 || result == tp::DomainStopResult::kClean ||
        cleanup_result == tp::DomainStopResult::kFailed || handle.pid != -1) {
        std::fprintf(stderr,
                     "FAIL: absolute stop deadline elapsed=%lld result=%u cleanup=%u pid=%d\n",
                     static_cast<long long>(elapsed_ms),
                     static_cast<unsigned>(result),
                     static_cast<unsigned>(cleanup_result), handle.pid);
        return false;
    }
    std::fprintf(stderr,
                 "PASS: absolute StopDomainHandle deadline bounded elapsed=%lldms\n",
                 static_cast<long long>(elapsed_ms));
    return true;
}

// 7. partial startup（loop pidfd handoff 未到达，loop_pidfd == -1）时，
//    StopDomainHandle 不得谎报 kForced：
//    - ns-runner 是被杀/异常死亡（非 WIFEXITED）→ loop 命运未知 → kFailed；
//    - ns-runner 自行干净退出 → 其失败/正常路径保证 loop 已清或从未 fork
//      → kForced 安全。
bool TestPartialStartupStopDoesNotClaimForced()
{
    auto make_paused_child = [](pid_t& child) {
        int ready_fds[2] = {-1, -1};
        if (::pipe(ready_fds) != 0) {
            return false;
        }
        child = ::fork();
        if (child < 0) {
            ::close(ready_fds[0]);
            ::close(ready_fds[1]);
            return false;
        }
        if (child == 0) {
            ::close(ready_fds[0]);
            const uint8_t ready = 1;
            (void)::write(ready_fds[1], &ready, sizeof(ready));
            ::close(ready_fds[1]);
            for (;;) ::pause();
        }
        ::close(ready_fds[1]);
        uint8_t ready = 0;
        ssize_t n;
        do {
            n = ::read(ready_fds[0], &ready, sizeof(ready));
        } while (n < 0 && errno == EINTR);
        ::close(ready_fds[0]);
        return n == static_cast<ssize_t>(sizeof(ready)) && ready == 1;
    };

    // case A: ns-runner 存活中被杀 → loop 命运未知 → kFailed
    {
        pid_t child = -1;
        if (!make_paused_child(child)) {
            std::fprintf(stderr, "FAIL: partial-stop child setup failed\n");
            return false;
        }
        tp::DomainHandle handle{};
        handle.pid = child;
        handle.loop_pidfd = -1;
        handle.separate_runner = true;

        tp::DomainStopPlan plan = tp::StartupCleanupStopPlan();
        const auto result = tp::StopDomainHandle(
            handle, tp::DomainStopDeadlineUs(plan), plan);
        if (result != tp::DomainStopResult::kFailed) {
            std::fprintf(stderr,
                         "FAIL: partial startup without pidfd claimed "
                         "result=%u (want kFailed)\n",
                         static_cast<unsigned>(result));
            return false;
        }
    }

    // case B: ns-runner 自行干净退出（loop 已清/从未 fork）→ kForced 安全
    {
        const pid_t child = ::fork();
        if (child < 0) {
            return false;
        }
        if (child == 0) {
            _exit(7);
        }
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 7) {
            std::fprintf(stderr, "FAIL: self-exit child status=0x%x\n",
                         status);
            return false;
        }
        tp::DomainHandle handle{};
        handle.pid = child;
        handle.direct_child_reaped = true;
        handle.direct_child_status_known = true;
        handle.direct_child_status = status;
        handle.loop_pidfd = -1;
        handle.separate_runner = true;

        tp::DomainStopPlan plan = tp::StartupCleanupStopPlan();
        const auto result = tp::StopDomainHandle(
            handle, tp::DomainStopDeadlineUs(plan), plan);
        if (result != tp::DomainStopResult::kForced) {
            std::fprintf(stderr,
                         "FAIL: self-exited ns-runner with no loop was not "
                         "reclaimed result=%u (want kForced) "
                         "reaped=%d status_known=%d status=0x%x\n",
                         static_cast<unsigned>(result),
                         handle.direct_child_reaped ? 1 : 0,
                         handle.direct_child_status_known ? 1 : 0,
                         handle.direct_child_status);
            return false;
        }
    }

    std::fprintf(stderr,
                 "PASS: partial startup stop does not claim kForced\n");
    return true;
}

bool TestGroupKillCoversDescendant()
{
    int status_fds[2] = {-1, -1};
    if (::pipe2(status_fds, O_CLOEXEC) != 0) {
        std::perror("pipe2");
        return false;
    }
    GroupTreeArgs args{status_fds[1]};
    tp::NsRunnerSupervisor sup;
    if (sup.Spawn(&GroupTreeEntry, &args) != 0) {
        ::close(status_fds[0]);
        ::close(status_fds[1]);
        std::fprintf(stderr, "FAIL: group-tree Spawn failed\n");
        return false;
    }
    ::close(status_fds[1]);

    pid_t descendant = -1;
    ssize_t read_size;
    do {
        read_size = ::read(sup.DoneReadFd(), &descendant, sizeof(descendant));
    } while (read_size < 0 && errno == EINTR);
    uint8_t ready = 0;
    const ssize_t ready_size = ::read(status_fds[0], &ready, sizeof(ready));
    if (read_size != static_cast<ssize_t>(sizeof(descendant)) ||
        descendant <= 0 || ready_size != static_cast<ssize_t>(sizeof(ready)) ||
        ready != 1 || ::getpgid(sup.NsRunnerPid()) != sup.NsRunnerPid()) {
        sup.Stop();
        ::close(status_fds[0]);
        std::fprintf(stderr,
                     "FAIL: group-tree setup descendant=%d read=%zd ready=%zd "
                     "runner=%d errno=%d\n",
                     descendant, read_size, ready_size, sup.NsRunnerPid(), errno);
        return false;
    }

    const auto result = sup.Stop();
    pollfd descriptor{};
    descriptor.fd = status_fds[0];
    descriptor.events = POLLIN;
    const int poll_result = ::poll(&descriptor, 1, 1000);
    char byte = 0;
    const ssize_t eof = ::read(status_fds[0], &byte, sizeof(byte));
    ::close(status_fds[0]);
    if (result != tp::DomainStopResult::kForced || poll_result <= 0 ||
        eof != 0) {
        (void)::kill(descendant, SIGKILL);
        std::fprintf(stderr,
                     "FAIL: group kill did not reap descendant result=%u "
                     "poll=%d eof=%zd errno=%d\n",
                     static_cast<unsigned>(result), poll_result, eof, errno);
        return false;
    }
    std::fprintf(stderr,
                 "PASS: isolated PGID kill covered loop descendant\n");
    return true;
}

} // namespace

int main()
{
    refuzz::worker::log::WorkerLogFdStorage() = STDERR_FILENO;
    refuzz::worker::log::EnableWorkerLog();
    // Host has live FUSE connections (gvfs/vmhgfs); stop-path escalation must
    // not abort them. Production VMs never set this.
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    int failed = 0;
    if (!TestSpawnEchoStop())    failed++;
    if (!TestRespawnMany())      failed++;
    if (!TestLoopChildExit())    failed++;
    if (!TestStopIdempotent())   failed++;
    if (!TestDoubleSpawnGuard()) failed++;
    if (!TestAbsoluteStopDeadline()) failed++;
    if (!TestPartialStartupStopDoesNotClaimForced()) failed++;
    if (!TestGroupKillCoversDescendant()) failed++;
    if (failed > 0) {
        std::fprintf(stderr, "FAILED: %d of 8 subtests\n", failed);
        return 1;
    }
    std::fprintf(stderr, "ALL 8 subtests passed\n");
    return 0;
}
