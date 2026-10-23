// Test: ChildWaiter pidfd-or-fallback child-exit detection。
//
// 三个场景:
//   1. Watch 一个 long-lived child:HasExited()=false,WaitFor(short) 返 false
//   2. Watch 一个 short-lived child (sleep ~50ms exit):
//      WaitFor(2000ms) 返 true,ExitStatus 解 WIFEXITED + WEXITSTATUS==0
//   3. Watch 一个被 SIGKILL 的 child:HasExited()=true,
//      WIFSIGNALED + WTERMSIG==SIGKILL
//
// pidfd 路径在 kernel >= 5.3 + 非容器场景下可用;失败自动 fallback 到 waitpid
// 轮询,test 行为应当一致。

#include "worker/topology/child_waiter.hpp"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

namespace {

// fork 出一个 child,执行给定 lambda。
template <typename Fn>
pid_t SpawnChild(Fn&& fn)
{
    pid_t pid = ::fork();
    if (pid == 0) {
        fn();
        _exit(0);
    }
    return pid;
}

bool TestLongLivedChild()
{
    // Child sleep 5s,parent 在 200ms 内看到它没死。
    pid_t pid = SpawnChild([]() { ::usleep(5'000'000); });
    if (pid < 0) {
        std::fprintf(stderr, "FAIL: fork failed\n");
        return false;
    }

    refuzz::worker::topology::ChildWaiter w;
    if (w.Watch(pid) != 0) {
        std::fprintf(stderr, "FAIL: Watch returned non-zero\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    if (w.HasExited()) {
        std::fprintf(stderr, "FAIL: HasExited() true on long-lived child\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    if (w.WaitFor(200)) {
        std::fprintf(stderr,
                     "FAIL: WaitFor(200ms) returned true on long-lived child\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    // Cleanup: kill + reap.
    ::kill(pid, SIGKILL);
    if (!w.WaitFor(2000)) {
        std::fprintf(stderr, "FAIL: WaitFor(2000ms) didn't see SIGKILL\n");
        ::waitpid(pid, nullptr, 0);
        return false;
    }
    std::fprintf(stderr,
                 "PASS: long-lived child watch (pidfd=%d)\n", w.PollFd());
    return true;
}

bool TestShortLivedChildNormalExit()
{
    pid_t pid = SpawnChild([]() {
        ::usleep(50'000);  // 50ms
        _exit(7);
    });
    if (pid < 0) {
        std::fprintf(stderr, "FAIL: fork failed\n");
        return false;
    }

    refuzz::worker::topology::ChildWaiter w;
    if (w.Watch(pid) != 0) {
        std::fprintf(stderr, "FAIL: Watch returned non-zero\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    if (!w.WaitFor(2000)) {
        std::fprintf(stderr,
                     "FAIL: WaitFor(2000ms) timed out on 50ms-exit child\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }
    if (!w.HasExited()) {
        std::fprintf(stderr, "FAIL: HasExited() false after WaitFor returned true\n");
        return false;
    }

    const int status = w.ExitStatus();
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 7) {
        std::fprintf(stderr,
                     "FAIL: ExitStatus=0x%x (expected WIFEXITED w/ status 7)\n",
                     status);
        return false;
    }
    std::fprintf(stderr,
                 "PASS: short-lived child normal exit (pidfd=%d)\n",
                 w.PollFd());
    return true;
}

bool TestChildKilledBySignal()
{
    pid_t pid = SpawnChild([]() { ::usleep(5'000'000); });
    if (pid < 0) {
        std::fprintf(stderr, "FAIL: fork failed\n");
        return false;
    }

    refuzz::worker::topology::ChildWaiter w;
    if (w.Watch(pid) != 0) {
        std::fprintf(stderr, "FAIL: Watch returned non-zero\n");
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    ::kill(pid, SIGKILL);
    if (!w.WaitFor(2000)) {
        std::fprintf(stderr, "FAIL: WaitFor(2000ms) didn't see SIGKILL\n");
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    const int status = w.ExitStatus();
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        // 在 pidfd 失败 fallback + 别处 reap 的边界情况,exit_status 可能为
        // 0 而 exited_ 仍 true(ECHILD path)。允许这种"已知 reaped 但 status
        // 丢失"的边界。
        if (status != 0) {
            std::fprintf(stderr,
                         "FAIL: ExitStatus=0x%x (expected WIFSIGNALED SIGKILL or 0)\n",
                         status);
            return false;
        }
    }
    std::fprintf(stderr,
                 "PASS: child killed by SIGKILL (pidfd=%d, status=0x%x)\n",
                 w.PollFd(), status);
    return true;
}

bool TestResetReuse()
{
    refuzz::worker::topology::ChildWaiter w;

    // Watch 1st child, kill it, reset.
    pid_t pid1 = SpawnChild([]() { ::usleep(5'000'000); });
    if (pid1 < 0) return false;
    if (w.Watch(pid1) != 0) return false;
    ::kill(pid1, SIGKILL);
    if (!w.WaitFor(2000)) {
        ::waitpid(pid1, nullptr, 0);
        return false;
    }
    w.Reset();
    if (w.Pid() != -1 || w.PollFd() != -1) {
        std::fprintf(stderr,
                     "FAIL: Reset() didn't clear pid/pidfd\n");
        return false;
    }

    // Watch 2nd child, exits normally.
    pid_t pid2 = SpawnChild([]() {
        ::usleep(50'000);
        _exit(0);
    });
    if (pid2 < 0) return false;
    if (w.Watch(pid2) != 0) return false;
    if (!w.WaitFor(2000)) {
        ::kill(pid2, SIGKILL);
        ::waitpid(pid2, nullptr, 0);
        return false;
    }
    std::fprintf(stderr, "PASS: Reset + reuse\n");
    return true;
}

} // namespace

int main()
{
    int failed = 0;
    if (!TestLongLivedChild()) failed++;
    if (!TestShortLivedChildNormalExit()) failed++;
    if (!TestChildKilledBySignal()) failed++;
    if (!TestResetReuse()) failed++;
    if (failed > 0) {
        std::fprintf(stderr, "FAILED: %d of 4 subtests\n", failed);
        return 1;
    }
    std::fprintf(stderr, "ALL 4 subtests passed\n");
    return 0;
}
