#include "refuzz/control/request_stream_sink.hpp"

#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace refuzz::control {
namespace {

// Minimal JSON string escaper. Program text is syzlang: it carries newlines,
// quotes and arbitrary byte escapes, so it cannot be dropped into a JSON string
// unescaped. Non-ASCII bytes go out as \u00XX rather than raw, because the
// converter reads these lines with a standard JSON parser that expects valid
// UTF-8 and syzlang string literals routinely contain raw high bytes.
//
// Runs on the writer thread. It expands every non-ASCII byte sixfold, and
// reFuzz program text is mostly ANYBLOB hex and SEGS payload, so this is the
// single most expensive step per record -- which is exactly why it is not on
// the dispatch path.
void AppendJsonString(std::string& out, std::string_view s)
{
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20 || c >= 0x7f) {
                static const char kHex[] = "0123456789abcdef";
                out += "\\u00";
                out.push_back(kHex[(c >> 4) & 0xf]);
                out.push_back(kHex[c & 0xf]);
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out.push_back('"');
}

// Bounds in-memory records so a stalled writer invalidates the capture instead
// of exhausting memory. A safety ceiling, not a steady-state size: a healthy
// writer keeps the queue near-empty. Records here are whole program texts and
// reFuzz's run to hundreds of KB, so this is set far below syzkaller's 1<<20
// record cap -- 4096 records is already ~1GB of backlog in the worst case.
constexpr std::size_t kDefaultMaxBacklog = 4096;

} // namespace

// The sink mirrors pkg/rpcserver/request_stream_sink.go, which is the reference
// implementation of this contract on the syzkaller side:
//
//   - Hot path (Record): encode the program to canonical text, hand the
//     already-built record to the writer, signal, return. Encoding stays on the
//     dispatch path for the same reason syzkaller keeps req.Prog.Serialize()
//     there -- the stream must carry canonical TEXT, and the artifact is only
//     guaranteed to be alive and immutable for the duration of the call. Nothing
//     else happens here: no JSON escaping, no buffering, no file I/O.
//   - Fail-closed: a full backlog or a write error invalidates the WHOLE
//     capture. A stream that silently lost records is worse than no stream,
//     because nothing downstream can tell the difference.
//   - Atomic publish: records go to a same-directory temp file that is fsynced
//     and renamed on graceful Close. An aborted run leaves no final file behind,
//     so a stale partial capture can never be mistaken for a complete one.
class RequestStreamSink::Impl {
public:
    Impl(RequestStreamSinkConfig cfg, const program::syz::Target& target)
        : cfg_(std::move(cfg)), encoder_(target)
    {
        // Refuse to overwrite, mirroring newRequestStreamSink's os.Stat check:
        // silently truncating a previous run's capture is how a re-run destroys
        // the artifact it was supposed to preserve.
        if (std::FILE* existing = std::fopen(cfg_.path.c_str(), "rb")) {
            std::fclose(existing);
            Fail("path_exists");
            return;
        }
        tmp_path_ = cfg_.path + ".partial";
        file_ = std::fopen(tmp_path_.c_str(), "wb");
        if (file_ == nullptr) {
            Fail("open_failed");
            return;
        }
        buf_.reserve(1 << 20);
        writer_ = std::thread([this] { Run(); });
        logging::HostLogger::Instance().Log(
            "RequestStreamSink", "opened",
            {logging::Field("path", cfg_.path),
             logging::Field("exec_env_flags", static_cast<int64_t>(cfg_.exec_env_flags)),
             logging::Field("base_exec_flags", static_cast<int64_t>(cfg_.base_exec_flags))});
    }

    ~Impl() { Close(); }

    // Control thread only, matching TrySubmit.
    void Record(const job::Request& req)
    {
        if (!writer_.joinable()) {
            return;
        }
        if (!req.artifact) {
            ++skipped_;
            return;
        }
        auto prog = req.artifact->As<program::syz::Prog>();
        if (!prog) {
            ++skipped_;
            return;
        }
        std::string text = encoder_.encode(*prog);
        if (text.empty()) {
            ++skipped_;
            return;
        }

        // reFuzz's per-task flag is a reFuzz enum; only the two bits that have a
        // flatrpc counterpart translate back (the exact inverse of
        // fixed_input_producer_job.cpp's TranslateExecFlags). Everything else in
        // exec_flags comes from base_exec_flags -- see the header on why those
        // are asserted rather than left zero.
        constexpr std::uint32_t kRfzCollectComps  = 1U << 0;   // proto::kExecFlagCollectComps
        constexpr std::uint32_t kRfzIntraThreaded = 1U << 1;   // proto::kExecFlagIntraThreaded
        constexpr std::uint64_t kFlatRpcCollectComps = 1ULL << 3;
        constexpr std::uint64_t kFlatRpcThreaded     = 1ULL << 4;
        std::uint64_t exec_flags = cfg_.base_exec_flags;
        const auto rfz_flags = static_cast<std::uint32_t>(req.opts.flags);
        if ((rfz_flags & kRfzCollectComps) != 0) {
            exec_flags |= kFlatRpcCollectComps;
        }
        if ((rfz_flags & kRfzIntraThreaded) != 0) {
            exec_flags |= kFlatRpcThreaded;
        }

        std::lock_guard<std::mutex> lock(mu_);
        if (failed_ || draining_) {
            return;
        }
        if (queue_.size() >= kDefaultMaxBacklog) {
            // Fail-closed: never drop a record from a stream that will still be
            // published.
            FailLocked("backlog_exceeded");
            return;
        }
        queue_.push_back(Pending{std::move(text), exec_flags});
        if (queue_.size() > max_depth_) {
            max_depth_ = queue_.size();
        }
        cv_.notify_one();
    }

    void Close()
    {
        if (!writer_.joinable()) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mu_);
            draining_ = true;
            cv_.notify_one();
        }
        writer_.join();

        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            ok = !failed_;
        }
        if (ok) {
            Flush();
            ok = std::fflush(file_) == 0 && ::fsync(::fileno(file_)) == 0;
        }
        std::fclose(file_);
        file_ = nullptr;
        if (ok && std::rename(tmp_path_.c_str(), cfg_.path.c_str()) != 0) {
            ok = false;
        }
        if (!ok) {
            std::remove(tmp_path_.c_str());
        }
        logging::HostLogger::Instance().Log(
            "RequestStreamSink", ok ? "closed" : "invalidated",
            {logging::Field("path", cfg_.path),
             logging::Field("written", static_cast<int64_t>(written_)),
             logging::Field("skipped", static_cast<int64_t>(skipped_)),
             logging::Field("max_queue_depth", static_cast<int64_t>(max_depth_))});
    }

    std::uint64_t written() const noexcept { return written_; }
    std::uint64_t skipped() const noexcept { return skipped_; }

private:
    struct Pending {
        std::string   text;
        std::uint64_t exec_flags;
    };

    // Writer thread. Everything expensive lives here.
    void Run()
    {
        std::deque<Pending> batch;
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [this] { return !queue_.empty() || draining_ || failed_; });
                if (failed_) {
                    return;
                }
                if (queue_.empty()) {
                    if (draining_) {
                        return;
                    }
                    continue;
                }
                batch.swap(queue_);
            }
            for (const Pending& rec : batch) {
                line_.clear();
                line_ += "{\"prog_text\":";
                AppendJsonString(line_, rec.text);
                line_ += ",\"exec_env_flags\":" + std::to_string(cfg_.exec_env_flags);
                line_ += ",\"exec_flags\":" + std::to_string(rec.exec_flags);
                line_ += ",\"sandbox_arg\":" + std::to_string(cfg_.sandbox_arg);
                line_ += ",\"request_flags\":" + std::to_string(cfg_.request_flags);
                line_ += "}\n";
                buf_ += line_;
                ++written_;
                if (buf_.size() >= (1u << 20) && !Flush()) {
                    std::lock_guard<std::mutex> lock(mu_);
                    FailLocked("write_failed");
                    return;
                }
            }
            batch.clear();
        }
    }

    bool Flush()
    {
        if (file_ == nullptr || buf_.empty()) {
            return true;
        }
        const bool ok = std::fwrite(buf_.data(), 1, buf_.size(), file_) == buf_.size();
        buf_.clear();
        return ok;
    }

    void Fail(const char* reason)
    {
        logging::HostLogger::Instance().Log(
            "RequestStreamSink", "capture_invalidated",
            {logging::Field("path", cfg_.path), logging::Field("reason", std::string(reason))});
    }

    void FailLocked(const char* reason)
    {
        if (failed_) {
            return;
        }
        failed_ = true;
        cv_.notify_all();
        Fail(reason);
    }

    RequestStreamSinkConfig   cfg_;
    program::syz::TextEncoder encoder_;
    std::string               tmp_path_;
    std::FILE*                file_ = nullptr;

    std::mutex              mu_;
    std::condition_variable cv_;
    std::deque<Pending>     queue_;
    std::size_t             max_depth_ = 0;
    bool                    draining_  = false;
    bool                    failed_    = false;
    std::thread             writer_;

    // Writer-thread only.
    std::string   buf_;
    std::string   line_;
    std::uint64_t written_ = 0;
    // Control-thread only.
    std::uint64_t skipped_ = 0;
};

RequestStreamSink::RequestStreamSink(RequestStreamSinkConfig cfg,
                                     const program::syz::Target& target)
    : impl_(std::make_unique<Impl>(std::move(cfg), target))
{
}

RequestStreamSink::~RequestStreamSink() = default;

void RequestStreamSink::Record(const job::Request& req) { impl_->Record(req); }
void RequestStreamSink::Close() { impl_->Close(); }
std::uint64_t RequestStreamSink::written() const noexcept { return impl_->written(); }
std::uint64_t RequestStreamSink::skipped() const noexcept { return impl_->skipped(); }

} // namespace refuzz::control
