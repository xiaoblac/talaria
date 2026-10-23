#pragma once

#include "worker/engine/loop_worker_boot_config.hpp"

namespace refuzz::worker::engine {

[[noreturn]] void RunExecLoop(const LoopWorkerBootConfig& config,
                              int backing_fd,
                              int ready_fd,
                              int done_fd,
                              int startup_ack_fd);

} // namespace refuzz::worker::engine
