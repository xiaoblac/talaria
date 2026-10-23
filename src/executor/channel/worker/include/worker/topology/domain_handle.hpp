#pragma once

#include "worker/topology/process_topology.hpp"

#include <cstdint>
#include <sys/types.h>

namespace refuzz::worker::topology {

// Daemon-owned process/fd identity for one execution domain. The same shape is
// used while startup is partial and after ownership moves into a topology.
struct DomainHandle {
    pid_t pid = -1;
    // loop pid in the daemon's PID namespace, used only for process-group
    // signaling. Ns-runner passes this value with the pidfd handoff. The stop
    // path can still recover it from /proc/self/fdinfo/<loop_pidfd> for older
    // or partially initialized handles.
    pid_t loop_pid = -1;
    int ns_runner_pidfd = -1;
    int loop_pidfd = -1;
    int ready_pipe_w = -1;
    int done_pipe_r = -1;
    bool separate_runner = false;
    bool direct_child_reaped = false;
    bool direct_child_status_known = false;
    int direct_child_status = 0;
};

uint64_t DomainStopDeadlineUs(const DomainStopPlan& plan);

// Executes the complete graceful-close/SIGKILL/runner/reap chain against one
// absolute deadline. Clean/forced success consumes the handle. When explicitly
// allowed, a loop that survives its reaped ns-runner is detached as
// kAbandoned; all other failures retain enough identity to retry.
DomainStopResult StopDomainHandle(DomainHandle& handle,
                                  uint64_t absolute_deadline_us,
                                  const DomainStopPlan& plan);

bool DomainHandleExecutionExited(const DomainHandle& handle);

} // namespace refuzz::worker::topology
