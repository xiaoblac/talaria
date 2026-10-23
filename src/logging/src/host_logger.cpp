#include "refuzz/logging/host_logger.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace refuzz::logging {
namespace {
std::string TextEscape(std::string_view input)
{
    std::string out;
    out.reserve(input.size() + 8);
    for (const char ch : input) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(ch); break;
        }
    }
    return out;
}

uint64_t NowWallUs()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

uint64_t NowMonoUs()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64_t ThreadIdValue()
{
    return static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

struct Record {
    uint64_t seq = 0;
    uint64_t wall_ts_us = 0;
    uint64_t mono_ts_us = 0;
    uint64_t tid = 0;
    std::string component;
    std::string event;
    std::vector<HostLogField> fields;
};


std::string Serialize(const Record& record)
{
    std::ostringstream out;
    out << "seq=" << record.seq
        << '\t' << "wall_us=" << record.wall_ts_us
        << '\t' << "mono_us=" << record.mono_ts_us
        << '\t' << "tid=" << record.tid
        << '\t' << "comp=" << TextEscape(record.component)
        << '\t' << "evt=" << TextEscape(record.event);
    for (const auto& field : record.fields) {
        out << '\t' << TextEscape(field.key) << '=' << TextEscape(field.value);
    }
    out << '\n';
    return out.str();
}
} // namespace

struct HostLogger::Impl {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<Record> queue;
    std::thread writer;
    std::ofstream stream;
    std::atomic<uint64_t> next_seq{1};
    std::atomic<bool> enabled_fast{false};
    std::atomic<uint32_t> hot_path_sample_rate{0};
    std::atomic<uint32_t> task_trace_sample_rate{0};
    bool running = false;
    bool stop_requested = false;
    HostLoggerConfig config;

    void Run()
    {
        std::unique_lock<std::mutex> lock(mu);
        while (running || !queue.empty()) {
            if (queue.empty()) {
                cv.wait_for(lock, config.flush_interval, [&]() {
                    return stop_requested || !queue.empty();
                });
            }
            std::deque<Record> batch;
            batch.swap(queue);
            const bool should_stop = stop_requested;
            // [v3.G] tee 语义:文件和 stdout 不再是二选一,二者按条件独立打开。
            const bool want_stdout = config.stream_to_stdout;
            const bool want_file   = stream.is_open();
            lock.unlock();
            for (const auto& record : batch) {
                auto line = Serialize(record);
                if (want_file) {
                    stream << line;
                }
                if (want_stdout) {
                    std::cout << line;
                }
            }
            if (!batch.empty() || should_stop) {
                if (want_file)   stream.flush();
                if (want_stdout) std::cout.flush();
            }
            lock.lock();
            if (should_stop && queue.empty()) {
                running = false;
            }
        }
    }
};


HostLineBuilder::HostLineBuilder(std::string component, std::string event)
    : component_(std::move(component))
    , event_(std::move(event))
    , enabled_(HostLogger::Instance().Enabled())
{}

HostLineBuilder::~HostLineBuilder()
{
    if (!enabled_) {
        return;
    }
    auto message = stream_.str();
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
        message.pop_back();
    }
    HostLogger::Instance().Log(component_, event_, {Field("message", message)});
}

HostLogger& HostLogger::Instance()
{
    static HostLogger logger;
    return logger;
}

HostLogger::HostLogger()
    : impl_(new Impl())
{}

HostLogger::~HostLogger()
{
    Shutdown();
    delete impl_;
    impl_ = nullptr;
}

void HostLogger::Initialize(HostLoggerConfig config)
{
    Shutdown();
    // [v1 old-approach — ROLLBACK: uncomment below and remove v2]
    // std::filesystem::path path(config.path);
    // std::filesystem::create_directories(path.parent_path());
    // impl_->config = std::move(config);
    // impl_->stream.open(impl_->config.path, std::ios::out | std::ios::trunc);

    // [v3.G] tee 语义:
    //   enabled=false                     → 不写任何 sink,不启 writer
    //   path 非空                          → 打开文件
    //   stream_to_stdout=true              → Run() 里顺带写 stdout(tee)
    //   path 为空 且 stream_to_stdout=false → 没有 sink,等价 disabled
    impl_->config = std::move(config);
    impl_->enabled_fast.store(false, std::memory_order_release);
    impl_->hot_path_sample_rate.store(
        impl_->config.hot_path_sample_rate, std::memory_order_release);
    impl_->task_trace_sample_rate.store(
        impl_->config.task_trace_sample_rate, std::memory_order_release);
    if (!impl_->config.enabled) {
        impl_->next_seq.store(1, std::memory_order_release);
        impl_->stop_requested = false;
        impl_->running = false;
        return;
    }
    if (!impl_->config.path.empty()) {
        std::filesystem::path path(impl_->config.path);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        impl_->stream.open(impl_->config.path, std::ios::out | std::ios::trunc);
    }
    // 若既没有文件 sink 又没有 stdout sink,早退:等价 disabled
    if (!impl_->stream.is_open() && !impl_->config.stream_to_stdout) {
        impl_->next_seq.store(1, std::memory_order_release);
        impl_->hot_path_sample_rate.store(0, std::memory_order_release);
        impl_->task_trace_sample_rate.store(0, std::memory_order_release);
        impl_->stop_requested = false;
        impl_->running = false;
        return;
    }
    impl_->next_seq.store(1, std::memory_order_release);
    impl_->stop_requested = false;
    impl_->running = true;
    impl_->writer = std::thread([this]() { impl_->Run(); });
    impl_->enabled_fast.store(true, std::memory_order_release);
}

void HostLogger::Shutdown()
{
    if (impl_ == nullptr) {
        return;
    }
    impl_->enabled_fast.store(false, std::memory_order_release);
    impl_->hot_path_sample_rate.store(0, std::memory_order_release);
    impl_->task_trace_sample_rate.store(0, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        if (!impl_->running && !impl_->writer.joinable()) {
            if (impl_->stream.is_open()) {
                impl_->stream.close();
            }
            return;
        }
        impl_->stop_requested = true;
    }
    impl_->cv.notify_one();
    if (impl_->writer.joinable()) {
        impl_->writer.join();
    }
    if (impl_->stream.is_open()) {
        impl_->stream.flush();
        impl_->stream.close();
    }
    impl_->stop_requested = false;
    impl_->running = false;
}

bool HostLogger::Enabled() const noexcept
{
    return impl_ != nullptr &&
           impl_->enabled_fast.load(std::memory_order_acquire);
}

bool HostLogger::ShouldLogHotPath(uint64_t sample_key) const noexcept
{
    if (!Enabled()) {
        return false;
    }
    const uint32_t rate =
        impl_->hot_path_sample_rate.load(std::memory_order_relaxed);
    if (rate == 0) {
        return false;
    }
    if (rate == 1) {
        return true;
    }
    return sample_key % rate == 0;
}

bool HostLogger::ShouldSampleTaskTrace(uint64_t sample_key) const noexcept
{
    if (!Enabled()) {
        return false;
    }
    const uint32_t rate =
        impl_->task_trace_sample_rate.load(std::memory_order_relaxed);
    if (rate == 0) {
        return false;
    }
    if (rate == 1) {
        return true;
    }
    return sample_key % rate == 0;
}

void HostLogger::Log(std::string component,
                     std::string event,
                     std::initializer_list<HostLogField> fields)
{
    if (!Enabled()) {
        return;
    }
    Log(std::move(component), std::move(event), std::vector<HostLogField>(fields));
}

void HostLogger::Log(std::string component,
                     std::string event,
                     const std::vector<HostLogField>& fields)
{
    if (!Enabled()) {
        return;
    }
    Log(std::move(component), std::move(event), std::vector<HostLogField>(fields));
}

void HostLogger::Log(std::string component,
                     std::string event,
                     std::vector<HostLogField>&& fields)
{
    if (!Enabled()) {
        return;
    }
    Record record;
    record.seq = impl_->next_seq.fetch_add(1, std::memory_order_acq_rel);
    record.wall_ts_us = NowWallUs();
    record.mono_ts_us = NowMonoUs();
    record.tid = ThreadIdValue();
    record.component = std::move(component);
    record.event = std::move(event);
    record.fields = std::move(fields);
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->queue.push_back(std::move(record));
    }
    impl_->cv.notify_one();
}

std::string ToLogValue(const std::string& value) { return value; }
std::string ToLogValue(const char* value) { return value != nullptr ? std::string(value) : std::string(); }
std::string ToLogValue(std::string_view value) { return std::string(value); }
std::string ToLogValue(bool value) { return value ? "1" : "0"; }

} // namespace refuzz::logging
