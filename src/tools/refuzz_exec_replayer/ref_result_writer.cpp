#include "ref_result_writer.hpp"

#include <chrono>
#include <cstring>

namespace refuzz::oracle::replayer {

namespace {

constexpr const char* kRefResultMagic = "REFUZRR";
constexpr uint32_t    kRefResultVersion = 1;
constexpr size_t      kRefResultHeaderLen = 64;

void AppendU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
void AppendU32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
void AppendU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
void AppendStr16(std::vector<uint8_t>& out, const std::string& s) {
    std::string t = s.size() > 65535 ? s.substr(0, 65535) : s;
    AppendU16(out, static_cast<uint16_t>(t.size()));
    out.insert(out.end(), t.begin(), t.end());
}
void AppendBytes32(std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
    AppendU32(out, static_cast<uint32_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

} // namespace

uint64_t NowNs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

RefResultWriter::~RefResultWriter() { (void)Close(); }

bool RefResultWriter::Open(const std::string& path, const std::string& git_rev) {
    std::lock_guard<std::mutex> lk(mu_);
    write_failed_.store(false, std::memory_order_relaxed);
    fp_ = std::fopen(path.c_str(), "wb");
    if (fp_ == nullptr) {
        write_failed_.store(true, std::memory_order_relaxed);
        return false;
    }
    path_ = path;

    uint8_t hdr[kRefResultHeaderLen] = {};
    std::memcpy(hdr, kRefResultMagic, std::strlen(kRefResultMagic));
    // hdr[7] stays 0 (null terminator inside the 8-byte magic field).
    uint32_t version = kRefResultVersion;
    std::memcpy(hdr + 8, &version, 4);
    uint64_t now_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    std::memcpy(hdr + 12, &now_ns, 8);
    auto gr = git_rev.size() > 40 ? git_rev.substr(0, 40) : git_rev;
    std::memcpy(hdr + 20, gr.data(), gr.size());
    // hdr[60..64] reserved (zero).

    if (std::fwrite(hdr, 1, kRefResultHeaderLen, fp_) != kRefResultHeaderLen) {
        std::fclose(fp_);
        fp_ = nullptr;
        write_failed_.store(true, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool RefResultWriter::Close() {
    std::lock_guard<std::mutex> lk(mu_);
    if (fp_ != nullptr) {
        if (std::fflush(fp_) != 0 || std::ferror(fp_) != 0) {
            write_failed_.store(true, std::memory_order_relaxed);
        }
        if (std::fclose(fp_) != 0) {
            write_failed_.store(true, std::memory_order_relaxed);
        }
        fp_ = nullptr;
    }
    return ok();
}

bool RefResultWriter::WriteRecord(uint8_t rec_type, uint64_t seq, std::vector<uint8_t> body) {
    std::lock_guard<std::mutex> lk(mu_);
    if (fp_ == nullptr || !ok()) {
        write_failed_.store(true, std::memory_order_relaxed);
        return false;
    }
    uint64_t ts = NowNs();
    uint32_t rec_size = static_cast<uint32_t>(1 + 8 + 8 + body.size());
    uint8_t hdr[4 + 1 + 8 + 8];
    std::memcpy(hdr, &rec_size, 4);
    hdr[4] = rec_type;
    std::memcpy(hdr + 5, &seq, 8);
    std::memcpy(hdr + 13, &ts, 8);
    if (std::fwrite(hdr, 1, sizeof(hdr), fp_) != sizeof(hdr)) {
        write_failed_.store(true, std::memory_order_relaxed);
        return false;
    }
    if (!body.empty() && std::fwrite(body.data(), 1, body.size(), fp_) != body.size()) {
        write_failed_.store(true, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool RefResultWriter::WriteSessionOpen(uint64_t trace_session_id,
                                       uint32_t vm_index,
                                       uint64_t file_created_unix_ns,
                                       const std::string& source_trace_path) {
    std::vector<uint8_t> body;
    AppendU64(body, trace_session_id);
    AppendU32(body, vm_index);
    AppendU64(body, file_created_unix_ns);
    AppendStr16(body, source_trace_path);
    return WriteRecord(kRecReplaySessionOpen, 0, std::move(body));
}

bool RefResultWriter::WriteSessionClose(uint8_t reason, uint64_t dropped_count,
                                        const std::string& note) {
    std::vector<uint8_t> body;
    body.push_back(reason);
    AppendU64(body, dropped_count);
    AppendStr16(body, note);
    return WriteRecord(kRecReplaySessionClose, 0, std::move(body));
}

bool RefResultWriter::WriteOutcome(uint64_t seq,
                                    uint64_t executor_id,
                                    int64_t  req_id,
                                    uint8_t  outcome_kind,
                                    uint8_t  abnormal_kind,
                                    uint64_t submit_ns,
                                    uint64_t complete_ns,
                                    const std::vector<uint8_t>& output) {
    std::vector<uint8_t> body;
    AppendU64(body, executor_id);
    AppendU64(body, static_cast<uint64_t>(req_id));
    body.push_back(outcome_kind);
    body.push_back(abnormal_kind);
    AppendU64(body, submit_ns);
    AppendU64(body, complete_ns);
    AppendBytes32(body, output);
    return WriteRecord(kRecReplayOutcome, seq, std::move(body));
}

bool RefResultWriter::WriteSkip(uint64_t seq,
                                 int64_t  req_id,
                                 uint8_t  skip_reason,
                                 uint64_t exec_env_flags,
                                 uint64_t exec_exec_flags) {
    std::vector<uint8_t> body;
    AppendU64(body, static_cast<uint64_t>(req_id));
    body.push_back(skip_reason);
    AppendU64(body, exec_env_flags);
    AppendU64(body, exec_exec_flags);
    return WriteRecord(kRecReplaySkip, seq, std::move(body));
}

} // namespace refuzz::oracle::replayer
