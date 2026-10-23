#pragma once

#include <cstdint>
#include <sys/resource.h>
#include <sys/types.h>
#include <vector>

namespace refuzz::worker::engine {

enum class ForkServerWaitResult : std::uint8_t {
    kPending = 0,
    kMainExited,
    kError,
    // [early-publish ordering] Returned only when WaitFor() was given a
    // non-negative extra_fd and that fd was observed readable. DrainReady()
    // was deliberately NOT called yet on this return -- the caller must react
    // to the extra-fd signal first (e.g. read a commit-notification eventfd
    // and publish a result), THEN call Drain() to perform the deferred reap.
    // This makes "act on the signal before reaping" a structural guarantee
    // (enforced by control flow) instead of a timing accident: even if the
    // main child died and became reapable within the same poll() call, this
    // return defers that reap to a separate, later step the caller controls.
    kExtraFdReady,
};

enum class ForkServerReapError : std::uint8_t {
    kNone = 0,
    kMainStatusLost,
    kWaitFailed,
};

struct ForkServerReaperStats {
    std::uint64_t descendants_reaped = 0;
    std::uint64_t stopped_children_killed = 0;
    std::uint64_t outer_fork_eagain = 0;
    std::uint64_t harness_fatal = 0;
};

// ForkingProgramExecutor-only child owner. It combines pidfd wakeups for the
// main program child with wait-any draining for all descendants, so no second
// waiter can steal the main child's exit status.
class ForkServerReaper {
public:
    explicit ForkServerReaper(pid_t main_pid);
    ~ForkServerReaper();

    ForkServerReaper(const ForkServerReaper&) = delete;
    ForkServerReaper& operator=(const ForkServerReaper&) = delete;

    // extra_fd (default -1 = none): an additional fd polled alongside pidfd_
    // in the SAME poll() call. When it becomes readable, WaitFor returns
    // kExtraFdReady immediately WITHOUT draining/reaping (see the enum
    // comment) and sets *extra_fd_ready = true; the caller must call Drain()
    // afterward to actually consume any now-ready child status. Passing -1
    // (the default) reproduces the exact prior behavior: poll pidfd only,
    // then unconditionally drain -- existing callers are unaffected.
    ForkServerWaitResult WaitFor(std::uint32_t timeout_ms,
                                 int extra_fd = -1,
                                 bool* extra_fd_ready = nullptr);

    // Non-blocking reap drain only (no poll). Exposed so a caller that just
    // handled a kExtraFdReady wakeup can perform the deferred reap in the same
    // iteration, preserving "act on the signal, then reap" ordering without
    // waiting for the next poll tick.
    bool Drain();

    // Syzkaller-style post-kill wait. Blocks until the main program child is
    // reaped while continuing to consume ready adopted descendants. The daemon
    // owns the outer execution-domain watchdog and may terminate this loop.
    bool WaitForMainBlocking();

    // Called only after MainExited(). Reaps descendants that are already
    // terminal and sends SIGKILL to stopped adopted descendants. It never
    // waits for a killed descendant to exit; later wait-any passes reap it.
    // Descendant cleanup syscall failures are diagnostic only and defer to the
    // outer-fork fail-stop boundary. False means the main-child precondition or
    // ownership invariant was violated.
    bool SignalStoppedDescendants();

    bool MainExited() const noexcept { return main_exited_; }
    int MainStatus() const noexcept { return main_status_; }
    // [ExecTL] optional worker_perf accounting harvested at reap time via wait4:
    // rusage (utime+stime = CPU the whole child consumed, nivcsw =
    // involuntary preemptions, minflt = COW faults) plus the CLOCK_MONOTONIC
    // us stamp of the moment the main child's status was consumed.
    bool MainRusageValid() const noexcept { return main_rusage_valid_; }
    const struct rusage& MainRusage() const noexcept { return main_rusage_; }
    std::uint64_t MainReapTsUs() const noexcept { return main_reap_ts_us_; }
    bool PidfdActive() const noexcept { return pidfd_ >= 0; }
    ForkServerReapError Error() const noexcept { return error_; }
    int ErrorNumber() const noexcept { return error_number_; }
    const ForkServerReaperStats& Stats() const noexcept { return stats_; }

private:
    bool DrainReady();
    bool ConsumeStatus(pid_t pid, int status, const struct rusage* ru = nullptr);
    void RememberStoppedDescendant(pid_t pid);
    bool KillStoppedDescendant(pid_t pid);
    bool ScanAndSignalStopped(std::vector<pid_t>* signaled);
    void SetError(ForkServerReapError error, int error_number);

    pid_t main_pid_ = -1;
    int pidfd_ = -1;
    int main_status_ = 0;
    bool main_exited_ = false;
    ForkServerReapError error_ = ForkServerReapError::kNone;
    int error_number_ = 0;
    ForkServerReaperStats stats_{};
    struct rusage main_rusage_ {};
    bool main_rusage_valid_ = false;
    std::uint64_t main_reap_ts_us_ = 0;
    std::vector<pid_t> observed_stopped_descendants_;
};

} // namespace refuzz::worker::engine
