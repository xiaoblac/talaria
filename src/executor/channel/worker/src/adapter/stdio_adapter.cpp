// Copyright 2026 reFuzz project author -------youngkk.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/adapter/stdio_adapter.hpp"

#include "refuzz/feedback/kcov/digest.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/backend/syz_exec_runner.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <linux/memfd.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace refuzz::worker {
namespace {

constexpr std::size_t kSharedHeaderAlign = 16;

std::size_t AlignUp(std::size_t n, std::size_t align)
{
    return (n + align - 1) & ~(align - 1);
}

std::string JsonEscape(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char ch : s) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                              static_cast<unsigned>(static_cast<unsigned char>(ch)));
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

std::string ErrorJson(const std::string& msg, std::vector<uint64_t> pcs = {})
{
    // [K3] error path 也带 pcs_hex,保 Go side 一致 schema (即便 err 时通常
    // pcs 是空)。FNV digest + pcs_hex 并行 emit。
    std::string pcs_hex;
    const std::string digest =
        refuzz::feedback::kcov::compute_kcov_digest_and_pcs_hex(pcs, &pcs_hex);
    return "{\"status\":\"err\",\"msg\":\"" + JsonEscape(msg) +
           "\",\"kcov_digest\":\"" + digest +
           "\",\"kcov_pcs_hex\":\"" + pcs_hex + "\"}";
}

std::size_t FeedbackBodyBytes(const refuzz::proto::WorkerFeedbackHeader& hdr)
{
    const auto kind = static_cast<refuzz::proto::FeedbackKind>(hdr.kind);
    switch (kind) {
    case refuzz::proto::FeedbackKind::kCoverageKcov:
        return static_cast<std::size_t>(hdr.entry_count) * sizeof(uint64_t);
    case refuzz::proto::FeedbackKind::kCoverageKcovCmp:
        return static_cast<std::size_t>(hdr.entry_count) * 4u * sizeof(uint64_t);
    case refuzz::proto::FeedbackKind::kNone:
    default:
        return 0;
    }
}

std::vector<uint64_t> ExtractKcovPcs(const uint8_t* output,
                                     std::size_t output_len,
                                     uint32_t n_calls)
{
    // 优先用 SyzExecResult.cover_offset/count 聚合 per-call PC slice。
    // 这就是当前 contract:普通 PC coverage 只经
    //   [SyzExecResult × n_calls][uint64 × coverage_tail]
    // 返回,语义对齐 syzkaller stdio patch 的
    // `stdio_prog_pcs.insert(pcs, pcs + th->cov.size)`。
    //
    // 输出 layout (KernelWireDriver):
    //   [SyzExecResult × n_calls] [uint64 × tail (per-call cov entries)] [...]
    //   ↑ head 区                  ↑ tail 区,SyzExecResult.cover_offset 是
    //                                此区 uint64 entry index
    //
    // 兼容旧输出/混版本 harness:
    //   - 旧 worker 可能仍在尾部 append task-end kCoverageKcov packet
    //   - 更老的输出可能只有 raw uint64 tail,没有 cover_offset/count
    // 这些 fallback 只用于 decode 历史产物,不属于当前 PC-mode 主路径。
    std::vector<uint64_t> pcs;
    if (output == nullptr) {
        return pcs;
    }

    const std::size_t head_bytes =
        static_cast<std::size_t>(n_calls) * sizeof(SyzExecResult);

    // ---- 路径 A: 当前 contract 的 per-call slice 聚合 ----
    if (output_len >= head_bytes) {
        bool saw_any_per_call = false;
        const std::size_t tail_uint64_cap =
            (output_len - head_bytes) / sizeof(uint64_t);
        const uint8_t* tail = output + head_bytes;
        for (uint32_t i = 0; i < n_calls; ++i) {
            SyzExecResult res{};
            std::memcpy(&res,
                        output + static_cast<std::size_t>(i) * sizeof(SyzExecResult),
                        sizeof(res));
            if (res.cover_count == 0) {
                continue;
            }
            saw_any_per_call = true;
            const std::size_t off = static_cast<std::size_t>(res.cover_offset);
            const std::size_t cnt = static_cast<std::size_t>(res.cover_count);
            if (off > tail_uint64_cap || cnt > tail_uint64_cap - off) {
                // corrupt cover_offset/count — skip this call slice。
                continue;
            }
            pcs.reserve(pcs.size() + cnt);
            for (std::size_t k = 0; k < cnt; ++k) {
                uint64_t pc = 0;
                std::memcpy(&pc, tail + (off + k) * sizeof(uint64_t), sizeof(uint64_t));
                pcs.push_back(pc);
            }
        }
        if (saw_any_per_call) {
            return pcs;
        }
    }

    // ---- 路径 B (legacy fallback): scan WorkerFeedbackHeader from tail ----
    std::size_t cursor = output_len;
    constexpr std::size_t kHeaderBytes = sizeof(refuzz::proto::WorkerFeedbackHeader);
    while (cursor >= kHeaderBytes) {
        refuzz::proto::WorkerFeedbackHeader hdr{};
        std::memcpy(&hdr, output + cursor - kHeaderBytes, kHeaderBytes);
        if (hdr.magic != refuzz::proto::kWorkerFeedbackMagic ||
            hdr.version != refuzz::proto::kWorkerFeedbackVersion) {
            break;
        }

        const std::size_t body_bytes = FeedbackBodyBytes(hdr);
        if (cursor < kHeaderBytes + body_bytes) {
            break;
        }
        const std::size_t body_begin = cursor - kHeaderBytes - body_bytes;

        if (static_cast<refuzz::proto::FeedbackKind>(hdr.kind) ==
            refuzz::proto::FeedbackKind::kCoverageKcov) {
            const uint8_t* body = output + body_begin;
            for (uint32_t i = 0; i < hdr.entry_count; ++i) {
                uint64_t pc = 0;
                std::memcpy(&pc, body + static_cast<std::size_t>(i) * sizeof(pc), sizeof(pc));
                pcs.push_back(pc);
            }
        }

        cursor = body_begin;
    }

    if (!pcs.empty()) {
        return pcs;
    }

    // ---- 路径 C (older legacy fallback): raw uint64 tail dump ----
    if (cursor <= head_bytes) {
        return pcs;
    }
    const std::size_t tail_bytes = cursor - head_bytes;
    if ((tail_bytes % sizeof(uint64_t)) != 0) {
        return pcs;
    }
    const uint8_t* tail = output + head_bytes;
    const std::size_t n = tail_bytes / sizeof(uint64_t);
    pcs.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        uint64_t pc = 0;
        std::memcpy(&pc, tail + i * sizeof(pc), sizeof(pc));
        pcs.push_back(pc);
    }
    return pcs;
}

std::string ExtractPerCallKcovPcsHex(const uint8_t* output,
                                     std::size_t output_len,
                                     uint32_t n_calls,
                                     uint32_t call_index)
{
    if (output == nullptr) {
        return {};
    }
    const std::size_t head_bytes =
        static_cast<std::size_t>(n_calls) * sizeof(SyzExecResult);
    if (output_len < head_bytes || call_index >= n_calls) {
        return {};
    }

    SyzExecResult res{};
    std::memcpy(&res,
                output + static_cast<std::size_t>(call_index) * sizeof(SyzExecResult),
                sizeof(res));
    if (res.cover_count == 0) {
        return {};
    }

    const std::size_t tail_uint64_cap =
        (output_len - head_bytes) / sizeof(uint64_t);
    const std::size_t off = static_cast<std::size_t>(res.cover_offset);
    const std::size_t cnt = static_cast<std::size_t>(res.cover_count);
    if (off > tail_uint64_cap || cnt > tail_uint64_cap - off) {
        return {};
    }

    std::vector<uint64_t> pcs;
    pcs.reserve(cnt);
    const uint8_t* tail = output + head_bytes;
    for (std::size_t k = 0; k < cnt; ++k) {
        uint64_t pc = 0;
        std::memcpy(&pc, tail + (off + k) * sizeof(uint64_t), sizeof(uint64_t));
        pcs.push_back(pc);
    }
    std::string pcs_hex;
    (void)refuzz::feedback::kcov::compute_kcov_digest_and_pcs_hex(pcs, &pcs_hex);
    return pcs_hex;
}

std::string StatusMessage(const TaskResult& result)
{
    if (result.completion_status == COMP_STATUS_PARTIAL) {
        return "partial completion";
    }
    if (result.completion_status == COMP_STATUS_HUNG) {
        return "task hung";
    }
    if (result.completion_status == COMP_STATUS_TIMEOUT ||
        result.error_code == ERR_TIMEOUT) {
        return "timeout";
    }
    if (result.completion_status == COMP_STATUS_CANCELLED ||
        result.cancel_observed) {
        return "cancelled";
    }
    if (result.completion_status == COMP_STATUS_CHILD_ABORTED) {
        if (result.crash_signal != 0) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "child signal %u", result.crash_signal);
            return buf;
        }
        return "child aborted";
    }
    if (result.completion_status == COMP_STATUS_HARNESS_FATAL) {
        return "harness fatal";
    }
    if (result.completion_status == COMP_STATUS_HARNESS_RECOVERED) {
        return "harness failure recovered";
    }
    if (result.completion_status == COMP_STATUS_CRASHED ||
        result.error_code == ERR_WORKER_CRASHED) {
        if (result.crash_signal != 0) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "worker crash signal %u", result.crash_signal);
            return buf;
        }
        return "worker crashed";
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "driver rc=%d", result.status);
    return buf;
}

bool IsSuccessCompletionStatus(uint32_t status)
{
    return status == COMP_STATUS_OK || status == COMP_STATUS_PARTIAL;
}

} // namespace

struct StdioWorkerAdapter::SharedState {
    uint32_t output_len = 0;
    uint32_t reserved = 0;
};

StdioWorkerAdapter::StdioWorkerAdapter()
    : StdioWorkerAdapter(Config{})
{
}

StdioWorkerAdapter::StdioWorkerAdapter(Config config)
    : config_(config)
{
}

StdioWorkerAdapter::~StdioWorkerAdapter()
{
    Cleanup();
}

int StdioWorkerAdapter::Init()
{
    const std::size_t header_bytes =
        AlignUp(sizeof(SharedState), kSharedHeaderAlign);
    shared_size_ = header_bytes +
        static_cast<std::size_t>(config_.max_input_size) +
        static_cast<std::size_t>(config_.output_size);
    shared_fd_ = static_cast<int>(::syscall(SYS_memfd_create,
                                            "refuzz-stdio-domain",
                                            MFD_CLOEXEC));
    if (shared_fd_ < 0 ||
        ::ftruncate(shared_fd_, static_cast<off_t>(shared_size_)) != 0) {
        if (shared_fd_ >= 0) {
            ::close(shared_fd_);
            shared_fd_ = -1;
        }
        shared_size_ = 0;
        return -1;
    }
    void* mem = mmap(nullptr, shared_size_, PROT_READ | PROT_WRITE,
                     MAP_SHARED, shared_fd_, 0);
    if (mem == MAP_FAILED) {
        shared_ = nullptr;
        ::close(shared_fd_);
        shared_fd_ = -1;
        shared_size_ = 0;
        return -1;
    }
    shared_ = static_cast<SharedState*>(mem);
    shared_->output_len = 0;
    return 0;
}

StdioWorkerAdapter::ReadStatus StdioWorkerAdapter::ReadExact(void* buf, std::size_t n)
{
    auto* p = static_cast<uint8_t*>(buf);
    std::size_t got = 0;
    while (got < n) {
        const ssize_t r = read(config_.input_fd, p + got, n - got);
        if (r == 0) {
            return (got == 0) ? ReadStatus::kCleanEof : ReadStatus::kTruncated;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ReadStatus::kError;
        }
        got += static_cast<std::size_t>(r);
    }
    return ReadStatus::kOk;
}

std::optional<WorkerIO> StdioWorkerAdapter::WaitTask(std::chrono::milliseconds timeout)
{
    (void)timeout;
    if (shared_ == nullptr || eof_ || exit_code_ != 0) {
        return std::nullopt;
    }

    uint32_t size_le = 0;
    const ReadStatus len_status = ReadExact(&size_le, sizeof(size_le));
    if (len_status == ReadStatus::kCleanEof) {
        eof_ = true;
        return std::nullopt;
    }
    if (len_status != ReadStatus::kOk) {
        EmitProtocolError("truncated length");
        return std::nullopt;
    }
    if (size_le == 0 || size_le > config_.max_input_size) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "bad size %u", size_le);
        EmitProtocolError(buf);
        return std::nullopt;
    }

    const ReadStatus body_status = ReadExact(InputBuffer(), size_le);
    if (body_status != ReadStatus::kOk) {
        EmitProtocolError("truncated body");
        return std::nullopt;
    }

    current_n_calls_ = 0;
    auto decoded = refuzz::program::syz::decode_exec_wire(
        std::span<const uint8_t>(InputBuffer(), size_le));
    if (decoded) {
        current_n_calls_ = static_cast<uint32_t>(decoded->num_calls);
    }

    shared_->output_len = 0;
    current_executor_id_ = next_executor_id_++;
    ++current_dispatch_gen_;

    WorkerIO io{};
    io.input_buf = InputBuffer();
    io.input_len = size_le;
    io.output_buf = OutputBuffer();
    io.output_cap = config_.output_size;
    ::refuzz::worker::log::WorkerLog(
        "[KCOV] stdio WaitTask: output_cap=%u (config_.output_size=%u)\n",
        io.output_cap, config_.output_size);
    io.crash_output_len = &shared_->output_len;
    io.executor_id = current_executor_id_;
    io.dispatch_gen = current_dispatch_gen_;
    io.timeout_ms = config_.exec_timeout_ms;
    io.flags = 0;
    io.target_proc_id = PROC_ID_ANY;
    io.cancel_requested = false;
    io.buffers.source = ProgramBufferSource::kLinearSharedMemory;
    io.buffers.worker_id = config_.worker_id;
    io.buffers.input_offset = AlignUp(sizeof(SharedState), kSharedHeaderAlign);
    io.buffers.output_offset =
        io.buffers.input_offset + config_.max_input_size;
    io.buffers.result_page_offset = 0;
    return io;
}

void StdioWorkerAdapter::ReportDone(const TaskResult& result)
{
    if (shared_ == nullptr) {
        return;
    }
    shared_->output_len = result.output_len;
    EmitJsonLine(BuildResultJson(result));
    current_executor_id_ = 0;
    current_n_calls_ = 0;
}

void StdioWorkerAdapter::Cleanup()
{
    if (shared_ != nullptr) {
        munmap(shared_, shared_size_);
        shared_ = nullptr;
        shared_size_ = 0;
    }
    if (shared_fd_ >= 0) {
        ::close(shared_fd_);
        shared_fd_ = -1;
    }
}

void StdioWorkerAdapter::ResetOutputLen()
{
    if (shared_ != nullptr) {
        shared_->output_len = 0;
    }
}

uint32_t StdioWorkerAdapter::GetCrashOutputLen() const
{
    return (shared_ != nullptr) ? shared_->output_len : 0;
}

bool StdioWorkerAdapter::GetExecutionDomainTransport(
    ExecutionDomainTransport* out) const
{
    if (out == nullptr || shared_ == nullptr || shared_fd_ < 0) {
        return false;
    }
    const uint64_t input_offset = AlignUp(sizeof(SharedState), kSharedHeaderAlign);
    out->backing_fd = shared_fd_;
    out->mapping.source = ProgramBufferSource::kLinearSharedMemory;
    out->mapping.worker_id = config_.worker_id;
    out->mapping.local_base = reinterpret_cast<uint8_t*>(shared_);
    out->mapping.resource_offset = 0;
    out->mapping.mapped_size = shared_size_;
    out->mapping.input_offset = input_offset;
    out->mapping.input_size = config_.max_input_size;
    out->mapping.output_offset = input_offset + config_.max_input_size;
    out->mapping.output_size = config_.output_size;
    out->mapping.result_page_offset = 0;
    out->mapping.result_page_size = 0;
    out->step_ring_offset = 0;
    out->step_ring_size = 0;
    out->step_ring_capacity = 0;
    return true;
}

void StdioWorkerAdapter::EmitProtocolError(const std::string& msg)
{
    exit_code_ = 1;
    EmitJsonLine(ErrorJson(msg));
}

void StdioWorkerAdapter::EmitJsonLine(const std::string& line)
{
    std::string out = line;
    out.push_back('\n');
    const char* p = out.data();
    std::size_t n = out.size();
    while (n > 0) {
        const ssize_t w = write(config_.output_fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            exit_code_ = 1;
            return;
        }
        p += w;
        n -= static_cast<std::size_t>(w);
    }
}

AdapterLifecycleState StdioWorkerAdapter::LifecycleState() const
{
    if (exit_code_ != 0 || shared_ == nullptr) {
        return AdapterLifecycleState::kFailed;
    }
    return eof_ ? AdapterLifecycleState::kCleanShutdown
                : AdapterLifecycleState::kRunning;
}

std::string StdioWorkerAdapter::BuildResultJson(const TaskResult& result) const
{
    const uint32_t output_len =
        (result.output_len <= config_.output_size) ? result.output_len : config_.output_size;
    std::vector<uint64_t> pcs =
        ExtractKcovPcs(OutputBuffer(), output_len, current_n_calls_);

    if (result.status != 0 ||
        !IsSuccessCompletionStatus(result.completion_status)) {
        return ErrorJson(StatusMessage(result), std::move(pcs));
    }

    const std::size_t head_bytes =
        static_cast<std::size_t>(current_n_calls_) * sizeof(SyzExecResult);
    if (output_len < head_bytes) {
        return ErrorJson("short result", std::move(pcs));
    }

    // [K3] 两路并行 emit:digest 仍走 FNV-1a byte-equal,新加 pcs_hex 是
    // sort+dedupe 后的 uint64 list continuous 16-hex 序列,Go side 解析后算
    // Jaccard。 pcs 在 compute_kcov_digest_and_pcs_hex 内被 sort+dedupe
    // (而非 move),保 hash+hex 共用同一最终集合。
    std::string pcs_hex;
    const std::string digest =
        refuzz::feedback::kcov::compute_kcov_digest_and_pcs_hex(pcs, &pcs_hex);
    std::string json;
    json.reserve(96 + static_cast<std::size_t>(current_n_calls_) * 64u +
                 pcs_hex.size());
    json += "{\"status\":\"ok\",\"results\":[";
    const uint8_t* output = OutputBuffer();
    for (uint32_t i = 0; i < current_n_calls_; ++i) {
        SyzExecResult res{};
        std::memcpy(&res,
                    output + static_cast<std::size_t>(i) * sizeof(SyzExecResult),
                    sizeof(res));
        if (i != 0) {
            json.push_back(',');
        }
        const std::string call_pcs_hex =
            ExtractPerCallKcovPcsHex(output, output_len, current_n_calls_, i);
        json += "{\"ret\":";
        json += std::to_string(static_cast<long long>(res.ret));
        json += ",\"err\":";
        json += std::to_string(res.err);
        json += ",\"kcov_pcs_hex\":\"";
        json += call_pcs_hex;
        json += "\"}";
    }
    json += "],\"kcov_digest\":\"";
    json += digest;
    json += "\",\"kcov_pcs_hex\":\"";
    json += pcs_hex;
    json += "\"}";
    return json;
}

uint8_t* StdioWorkerAdapter::InputBuffer()
{
    return const_cast<uint8_t*>(static_cast<const StdioWorkerAdapter*>(this)->InputBuffer());
}

const uint8_t* StdioWorkerAdapter::InputBuffer() const
{
    const std::size_t header_bytes =
        AlignUp(sizeof(SharedState), kSharedHeaderAlign);
    return reinterpret_cast<const uint8_t*>(shared_) + header_bytes;
}

uint8_t* StdioWorkerAdapter::OutputBuffer()
{
    return const_cast<uint8_t*>(static_cast<const StdioWorkerAdapter*>(this)->OutputBuffer());
}

const uint8_t* StdioWorkerAdapter::OutputBuffer() const
{
    return InputBuffer() + config_.max_input_size;
}

} // namespace refuzz::worker
