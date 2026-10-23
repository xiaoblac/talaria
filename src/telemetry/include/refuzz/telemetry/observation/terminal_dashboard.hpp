#pragma once

#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <thread>

namespace refuzz::telemetry {

struct TerminalDashboardConfig {
    bool enable = true;
    std::chrono::milliseconds refresh_interval{500};
    size_t max_events = 6;
    bool use_alternate_screen = true;
    bool hide_cursor = true;
    int fd = 2;
};

class TerminalDashboard {
public:
    explicit TerminalDashboard(const RunStateStore& store,
                               TerminalDashboardConfig config = {});
    ~TerminalDashboard();

    bool Start();
    void Stop();
    bool Active() const;

private:
    int ResolveRenderFd();
    void CloseRenderFd();
    void RenderLoop();
    void EnterTerminal();
    void RestoreTerminal();
    void RenderFrame();

    const RunStateStore& store_;
    TerminalDashboardConfig config_{};
    std::mutex wait_mu_;
    std::condition_variable wait_cv_;
    std::thread thread_;
    int render_fd_ = -1;
    bool owns_render_fd_ = false;
    std::atomic<bool> running_{false};
    std::atomic<bool> active_{false};
};

} // namespace refuzz::telemetry
