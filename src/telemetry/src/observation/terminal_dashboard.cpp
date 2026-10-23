#include "refuzz/telemetry/observation/terminal_dashboard.hpp"

#include "refuzz/telemetry/observation/run_state_renderer.hpp"

#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace refuzz::telemetry {
namespace {

struct TerminalSize {
    size_t rows = 24;
    size_t cols = 120;
};

bool IsTerminalUsable(int fd)
{
    if (fd < 0 || ::isatty(fd) == 0) {
        return false;
    }
    const char* term = std::getenv("TERM");
    return term != nullptr && std::string_view(term) != "dumb";
}

TerminalSize QueryTerminalSize(int fd)
{
    winsize ws{};
    if (fd >= 0 && ::ioctl(fd, TIOCGWINSZ, &ws) == 0) {
        TerminalSize size;
        if (ws.ws_row > 0) {
            size.rows = ws.ws_row;
        }
        if (ws.ws_col > 0) {
            size.cols = ws.ws_col;
        }
        return size;
    }
    return {};
}

void WriteAll(int fd, std::string_view content)
{
    if (fd < 0 || content.empty()) {
        return;
    }
    const char* data = content.data();
    size_t remaining = content.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd, data, remaining);
        if (written <= 0) {
            return;
        }
        data += written;
        remaining -= static_cast<size_t>(written);
    }
}

std::string TrimLineToWidth(std::string_view line, size_t cols)
{
    if (cols == 0 || line.size() <= cols) {
        return std::string(line);
    }
    if (cols <= 3) {
        return std::string(line.substr(0, cols));
    }
    std::string out(line.substr(0, cols - 3));
    out += "...";
    return out;
}

std::string FitToTerminal(std::string_view content, size_t rows, size_t cols)
{
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start <= content.size()) {
        const size_t end = content.find('\n', start);
        if (end == std::string_view::npos) {
            lines.push_back(content.substr(start));
            break;
        }
        lines.push_back(content.substr(start, end - start));
        start = end + 1;
    }

    if (rows == 0) {
        rows = lines.size();
    }

    std::ostringstream out;
    const size_t visible = std::min(lines.size(), rows);
    if (visible == 0) {
        return out.str();
    }

    for (size_t idx = 0; idx < visible; ++idx) {
        if (idx + 1 == visible && lines.size() > rows && rows > 0) {
            std::ostringstream truncated;
            truncated << "... truncated " << (lines.size() - rows + 1) << " lines";
            out << TrimLineToWidth(truncated.str(), cols);
        } else {
            out << TrimLineToWidth(lines[idx], cols);
        }
        if (idx + 1 < visible) {
            out << '\n';
        }
    }
    return out.str();
}

std::string BuildFrame(const RunStateStore& store,
                       const TerminalDashboardConfig& config,
                       int fd)
{
    const TerminalSize size = QueryTerminalSize(fd);

    std::ostringstream content;
    content << "reFuzz Dashboard"
            << "  refresh_ms=" << config.refresh_interval.count()
            << "  events=" << config.max_events
            << "  ctrl_c=exit"
            << '\n';
    content << RenderRuntimePanel(store, "", config.max_events);

    std::ostringstream frame;
    frame << "\x1b[H\x1b[2J";
    frame << FitToTerminal(content.str(), size.rows, size.cols);
    frame << "\x1b[" << size.rows << ";1H";
    return frame.str();
}

} // namespace

TerminalDashboard::TerminalDashboard(const RunStateStore& store,
                                     TerminalDashboardConfig config)
    : store_(store)
    , config_(std::move(config))
{}

TerminalDashboard::~TerminalDashboard()
{
    Stop();
}

int TerminalDashboard::ResolveRenderFd()
{
    int tty_fd = ::open("/dev/tty", O_WRONLY | O_CLOEXEC);
    if (IsTerminalUsable(tty_fd)) {
        owns_render_fd_ = true;
        return tty_fd;
    }
    if (tty_fd >= 0) {
        ::close(tty_fd);
    }

    if (IsTerminalUsable(config_.fd)) {
        owns_render_fd_ = false;
        return config_.fd;
    }
    return -1;
}

void TerminalDashboard::CloseRenderFd()
{
    if (owns_render_fd_ && render_fd_ >= 0) {
        ::close(render_fd_);
    }
    render_fd_ = -1;
    owns_render_fd_ = false;
}

bool TerminalDashboard::Start()
{
    if (running_.load(std::memory_order_acquire)) {
        return active_.load(std::memory_order_acquire);
    }
    if (!config_.enable) {
        active_.store(false, std::memory_order_release);
        return false;
    }

    render_fd_ = ResolveRenderFd();
    if (render_fd_ < 0) {
        active_.store(false, std::memory_order_release);
        return false;
    }

    EnterTerminal();
    active_.store(true, std::memory_order_release);
    running_.store(true, std::memory_order_release);
    thread_ = std::thread([this]() { RenderLoop(); });
    return true;
}

void TerminalDashboard::Stop()
{
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        if (active_.exchange(false, std::memory_order_acq_rel)) {
            RestoreTerminal();
        }
        CloseRenderFd();
        return;
    }

    wait_cv_.notify_one();
    if (thread_.joinable()) {
        thread_.join();
    }
    if (active_.exchange(false, std::memory_order_acq_rel)) {
        RestoreTerminal();
    }
    CloseRenderFd();
}

bool TerminalDashboard::Active() const
{
    return active_.load(std::memory_order_acquire);
}

void TerminalDashboard::EnterTerminal()
{
    std::string control;
    if (config_.use_alternate_screen) {
        control += "\x1b[?1049h";
    }
    if (config_.hide_cursor) {
        control += "\x1b[?25l";
    }
    control += "\x1b[H\x1b[2J";
    WriteAll(render_fd_, control);
}

void TerminalDashboard::RestoreTerminal()
{
    std::string control;
    control += "\x1b[H\x1b[2J";
    if (config_.hide_cursor) {
        control += "\x1b[?25h";
    }
    if (config_.use_alternate_screen) {
        control += "\x1b[?1049l";
    }
    WriteAll(render_fd_, control);
}

void TerminalDashboard::RenderFrame()
{
    WriteAll(render_fd_, BuildFrame(store_, config_, render_fd_));
}

void TerminalDashboard::RenderLoop()
{
    while (running_.load(std::memory_order_acquire)) {
        RenderFrame();
        std::unique_lock<std::mutex> lock(wait_mu_);
        wait_cv_.wait_for(lock, config_.refresh_interval, [this]() {
            return !running_.load(std::memory_order_acquire);
        });
    }
}

} // namespace refuzz::telemetry
