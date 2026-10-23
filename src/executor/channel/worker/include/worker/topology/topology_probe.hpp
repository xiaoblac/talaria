#pragma once

#include <cstdint>
#include <sys/types.h>

namespace refuzz::worker::topology {

bool TopologyProbeEnabled();

void EmitTopologyProbeSelf(const char* role,
                           std::uint32_t worker_id,
                           std::uint64_t executor_id,
                           std::uint32_t dispatch_gen);

void EmitTopologyProbeCgroup(const char* role,
                             std::uint32_t worker_id,
                             std::uint32_t proc_id,
                             std::uint64_t executor_id,
                             std::uint32_t dispatch_gen,
                             int max_procs);

// Fatal-only snapshot bypasses REFUZZ_TOPOLOGY_PROBE so an unrecoverable
// fork-server failure always records cgroup PID/state evidence once.
void EmitTopologyFatalCgroupSnapshot(const char* role,
                                     std::uint32_t worker_id,
                                     std::uint32_t proc_id,
                                     std::uint64_t executor_id,
                                     std::uint32_t dispatch_gen,
                                     int max_procs);

void EmitTopologyProbeProgramFork(const char* role,
                                  std::uint32_t worker_id,
                                  std::uint64_t executor_id,
                                  std::uint32_t dispatch_gen,
                                  pid_t program_pid);

void EmitTopologyProbeCleanupSummary(const char* role,
                                     std::uint32_t worker_id,
                                     std::uint64_t executor_id,
                                     std::uint32_t dispatch_gen,
                                     pid_t program_pid,
                                     bool timed_out,
                                     bool timeout_reaped,
                                     int wait_status,
                                     int reaped_children,
                                     int stopped_children_killed,
                                     int wait_errno);

} // namespace refuzz::worker::topology
