#include "worker/engine/fork_server_reaper.hpp"
#include "worker/perf/worker_perf.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using refuzz::worker::engine::ForkServerReaper;
using refuzz::worker::engine::ForkServerWaitResult;

void Check(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::abort();
    }
}

void WaitForMain(ForkServerReaper* reaper)
{
    for (int i = 0; i < 200; ++i) {
        const auto result = reaper->WaitFor(10);
        Check(result != ForkServerWaitResult::kError,
              "fork-server reaper returned an error");
        if (result == ForkServerWaitResult::kMainExited) {
            return;
        }
    }
    Check(false, "main child did not exit within 2 seconds");
}

void TestMainStatusSurvivesWaitAny()
{
    const pid_t main_pid = ::fork();
    Check(main_pid >= 0, "fork main child failed");
    if (main_pid == 0) {
        const pid_t descendant = ::fork();
        if (descendant == 0) {
            _exit(0);
        }
        if (descendant < 0) {
            _exit(90);
        }
        ::usleep(50'000);
        _exit(7);
    }

    ForkServerReaper reaper(main_pid);
    WaitForMain(&reaper);
    Check(WIFEXITED(reaper.MainStatus()), "main status is not WIFEXITED");
    Check(WEXITSTATUS(reaper.MainStatus()) == 7,
          "wait-any lost the main child's real exit code");
    Check(reaper.Stats().descendants_reaped >= 1,
          "exited descendant was not reaped");
}

void TestStoppedResidueSignaledWithoutSynchronousWait()
{
    int ready[2] = {-1, -1};
    Check(::pipe(ready) == 0, "pipe failed");

    const pid_t main_pid = ::fork();
    Check(main_pid >= 0, "fork main child failed");
    if (main_pid == 0) {
        ::close(ready[0]);
        const pid_t descendant = ::fork();
        if (descendant == 0) {
            const char marker = 'x';
            (void)::write(ready[1], &marker, 1);
            ::raise(SIGSTOP);
            _exit(0);
        }
        if (descendant < 0) {
            _exit(91);
        }
        ::close(ready[1]);
        _exit(0);
    }

    ::close(ready[1]);
    char marker = 0;
    Check(::read(ready[0], &marker, 1) == 1,
          "stopped descendant did not reach the synchronization point");
    ::close(ready[0]);

    ForkServerReaper reaper(main_pid);
    WaitForMain(&reaper);
    Check(reaper.SignalStoppedDescendants(),
          "stopped descendant signaling failed");
    Check(reaper.Stats().stopped_children_killed == 1,
          "stopped descendant was not killed exactly once");

    std::uint64_t later_reaped = 0;
    bool all_reaped = false;
    for (int i = 0; i < 200; ++i) {
        errno = 0;
        const pid_t reaped = ::waitpid(-1, nullptr, WNOHANG | __WALL);
        if (reaped > 0) {
            ++later_reaped;
            continue;
        }
        if (reaped < 0 && errno == ECHILD) {
            all_reaped = true;
            break;
        }
        ::usleep(1'000);
    }
    Check(all_reaped, "signaled descendant did not become reapable");
    Check(reaper.Stats().descendants_reaped + later_reaped >= 1,
          "stopped descendant was neither reaped immediately nor later");
}

void TestMainPtraceStopIsNotExit()
{
    const pid_t main_pid = ::fork();
    Check(main_pid >= 0, "fork ptrace-stop child failed");
    if (main_pid == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
            _exit(92);
        }
        ::raise(SIGSTOP);
        _exit(9);
    }

    ForkServerReaper reaper(main_pid);
    const auto stopped = reaper.WaitFor(50);
    if (stopped == ForkServerWaitResult::kMainExited &&
        WIFEXITED(reaper.MainStatus()) &&
        WEXITSTATUS(reaper.MainStatus()) == 92) {
        return;
    }
    Check(stopped == ForkServerWaitResult::kPending,
          "ptrace stop was misclassified as main exit");
    Check(!reaper.MainExited(), "stopped main child marked exited");
    Check(::ptrace(PTRACE_CONT, main_pid, nullptr, nullptr) == 0,
          "failed to continue ptrace-stopped main child");
    WaitForMain(&reaper);
    Check(WIFEXITED(reaper.MainStatus()), "continued main status is not exited");
    Check(WEXITSTATUS(reaper.MainStatus()) == 9,
          "continued main exit status was not preserved");
}

void TestBlockingMainWaitPreservesStatus()
{
    const pid_t main_pid = ::fork();
    Check(main_pid >= 0, "fork blocking-wait child failed");
    if (main_pid == 0) {
        ::usleep(20'000);
        _exit(11);
    }

    ForkServerReaper reaper(main_pid);
    Check(reaper.WaitForMainBlocking(), "blocking main wait failed");
    Check(WIFEXITED(reaper.MainStatus()), "blocking wait status is not exited");
    Check(WEXITSTATUS(reaper.MainStatus()) == 11,
          "blocking wait lost main exit status");
}

void TestPerfLedgerFollowsWorkerPerfSwitch()
{
    auto check_mode = [](bool enabled) {
        refuzz::worker::perf::Configure(enabled, 1, 1);
        const pid_t child = ::fork();
        Check(child >= 0, "fork perf-ledger child failed");
        if (child == 0) {
            _exit(0);
        }
        ForkServerReaper reaper(child);
        WaitForMain(&reaper);
        Check(reaper.MainRusageValid() == enabled,
              enabled
                  ? "enabled worker_perf did not collect child rusage"
                  : "disabled worker_perf still collected child rusage");
        Check((reaper.MainReapTsUs() != 0) == enabled,
              enabled
                  ? "enabled worker_perf did not collect reap timestamp"
                  : "disabled worker_perf still collected reap timestamp");
    };

    check_mode(false);
    check_mode(true);
    refuzz::worker::perf::Configure(false, 1, 1);
}

} // namespace

int main()
{
    Check(::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0,
          "PR_SET_CHILD_SUBREAPER failed");
    TestMainStatusSurvivesWaitAny();
    TestStoppedResidueSignaledWithoutSynchronousWait();
    TestMainPtraceStopIsNotExit();
    TestBlockingMainWaitPreservesStatus();
    TestPerfLedgerFollowsWorkerPerfSwitch();
    std::fprintf(stdout, "OK\n");
    return 0;
}
