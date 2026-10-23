#pragma once

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <sstream>
#include <type_traits>
#include <utility>
#include <vector>

namespace refuzz::logging {

struct HostLogField {
    std::string key;
    std::string value;
};

// [v3.G] HostLogger 输出语义（tee 语义，非 either/or）：
//   enabled=false            → 完全关闭，不写文件也不写 stdout
//   stream_to_stdout=true    → 每条记录 **额外** 写到 stdout（"tee"）
//   path 非空 且 enabled=true → 写到该文件
//   path=""  且 stream_to_stdout=true → 只写 stdout（诊断/前台模式）
//   path=""  且 stream_to_stdout=false → 等价 enabled=false
//
// 这样 telemetry.logging.stream=true 不再掩盖 host_events.txt，而是并行输出。
struct HostLoggerConfig {
    bool enabled = true;
    bool stream_to_stdout = false;
    std::string path;
    std::chrono::milliseconds flush_interval{250};
    bool console_summary = true;
    // 0 disables per-task/per-event hot-path logs.
    // 1 logs every hot-path record; N logs records whose stable key is divisible by N.
    uint32_t hot_path_sample_rate = 0;
    // Independent sampling rate for the compact per-task performance trace.
    // Same semantics as hot_path_sample_rate (0=off, 1=every task,
    // N=every Nth by executor_id) but kept as a separate knob: per-task
    // trace rows are far larger and typically want a much lower rate than
    // the per-event hot-path log lines.
    uint32_t task_trace_sample_rate = 0;
};


class HostLineBuilder {
public:
    HostLineBuilder(std::string component, std::string event);
    ~HostLineBuilder();

    template <typename T>
    HostLineBuilder& operator<<(const T& value)
    {
        if (enabled_) {
            stream_ << value;
        }
        return *this;
    }

    HostLineBuilder& operator<<(std::ostream& (*manip)(std::ostream&))
    {
        if (enabled_) {
            manip(stream_);
        }
        return *this;
    }

private:
    std::string component_;
    std::string event_;
    bool enabled_ = false;
    std::ostringstream stream_;
};

class HostLogger {
public:
    static HostLogger& Instance();

    void Initialize(HostLoggerConfig config);
    void Shutdown();
    bool Enabled() const noexcept;
    bool ShouldLogHotPath(uint64_t sample_key) const noexcept;
    bool ShouldSampleTaskTrace(uint64_t sample_key) const noexcept;

    void Log(std::string component,
             std::string event,
             std::initializer_list<HostLogField> fields = {});
    void Log(std::string component,
             std::string event,
             const std::vector<HostLogField>& fields);
    void Log(std::string component,
             std::string event,
             std::vector<HostLogField>&& fields);

private:
    HostLogger();
    ~HostLogger();
    HostLogger(const HostLogger&) = delete;
    HostLogger& operator=(const HostLogger&) = delete;

    struct Impl;
    Impl* impl_;
};

std::string ToLogValue(const std::string& value);
std::string ToLogValue(const char* value);
std::string ToLogValue(std::string_view value);
std::string ToLogValue(bool value);

template <typename T>
std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, std::string>
ToLogValue(T value)
{
    return std::to_string(value);
}

template <typename T>
std::enable_if_t<std::is_floating_point_v<T>, std::string>
ToLogValue(T value)
{
    return std::to_string(value);
}

template <typename T>
HostLogField Field(std::string key, T value)
{
    return HostLogField{std::move(key), ToLogValue(value)};
}

} // namespace refuzz::logging
