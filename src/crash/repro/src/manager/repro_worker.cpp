#include "refuzz/crash/repro/manager/repro_worker.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "refuzz/logging/host_logger.hpp"
#include <sstream>

namespace refuzz::crash {
namespace {

const char* CompletionStatusToString(ReproCompletionStatus status)
{
    switch (status) {
    case ReproCompletionStatus::kCompleted: return "completed";
    case ReproCompletionStatus::kInterrupted: return "interrupted";
    case ReproCompletionStatus::kFailed: return "failed";
    }
    return "unknown";
}

const char* ReproStageToString(ReproStage stage)
{
    switch (stage) {
    case ReproStage::kNone: return "none";
    case ReproStage::kExtract: return "extract";
    case ReproStage::kMinimize: return "minimize";
    case ReproStage::kReliability: return "reliability";
    case ReproStage::kSymbolize: return "symbolize";
    case ReproStage::kProduceCSource: return "produce_csource";
    }
    return "unknown";
}

const char* CompletionReasonToString(ReproCompletionReason reason)
{
    switch (reason) {
    case ReproCompletionReason::kNone: return "none";
    case ReproCompletionReason::kStopRequested: return "stop_requested";
    case ReproCompletionReason::kExtractFailed: return "extract_failed";
    case ReproCompletionReason::kChannelNotReady: return "channel_not_ready";
    case ReproCompletionReason::kRecoveryFailed: return "recovery_failed";
    case ReproCompletionReason::kMinimizeFailed: return "minimize_failed";
    case ReproCompletionReason::kReliabilityBelowThreshold: return "reliability_below_threshold";
    case ReproCompletionReason::kReproduceFailed: return "reproduce_failed";
    case ReproCompletionReason::kCReproNoMinimizedArtifact: return "c_repro_no_minimized_artifact";
    case ReproCompletionReason::kCReproUnsupportedByEpic4:  return "c_repro_unsupported_by_epic4";
    case ReproCompletionReason::kCReproWriteFailed:         return "c_repro_write_failed";
    case ReproCompletionReason::kCReproBuildFailed:         return "c_repro_build_failed";
    }
    return "unknown";
}

std::string Hex16(uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

std::string JsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 16);
    for (char ch : value) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::trunc);
    if (!out) { return false; }
    out << text;
    out.flush();
    return out.good();
}

bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { return false; }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    out.flush();
    return out.good();
}

std::string BuildReproReport(const CrashContext& ctx, const ReproResult& result)
{
    std::ostringstream out;
    out << "incident_id: " << result.incident_id << "\n";
    out << "crash_title: " << result.crash_title << "\n";
    out << "completion: " << CompletionStatusToString(result.completion) << "\n";
    out << "last_stage: " << ReproStageToString(result.last_completed_stage) << "\n";
    out << "completion_reason: " << CompletionReasonToString(result.completion_reason) << "\n";
    out << "reproduced: " << (result.reproduced ? "true" : "false") << "\n";
    out << "reliability: " << result.reliability << "\n";
    out << "total_attempts: " << result.total_attempts << "\n";
    out << "crash_attempts: " << result.crash_attempts << "\n";
    out << "original_call_count: " << result.original_call_count << "\n";
    out << "minimized_call_count: " << result.minimized_call_count << "\n";
    out << "minimize_attempts: " << result.minimize_attempts << "\n";
    out << "minimize_commits: " << result.minimize_commits << "\n";
    out << "minimize_stage: " << result.minimize_stage << "\n";
    out << "extract_source: " << result.extract_source << "\n";
    out << "program_log_count: " << result.program_log_count << "\n";
    out << "crash_hash: " << Hex16(ctx.crash_hash) << "\n";
    out << "channel_id: " << ctx.channel_id << "\n";
    out << "crash_signal: " << ctx.crash_signal << "\n";

    if (!result.symbolized_report.empty()) {
        out << "\n[symbolized_report]\n" << result.symbolized_report;
    }
    if (!ctx.console_log.empty()) {
        out << "\n[console_log]\n";
        if (ctx.console_log.size() > 8192) {
            out << ctx.console_log.substr(0, 8192) << "\n... (truncated)\n";
        } else {
            out << ctx.console_log;
            if (ctx.console_log.back() != '\n') { out << "\n"; }
        }
    }

    return out.str();
}

std::string BuildReproMetaJson(const CrashContext& ctx, const ReproResult& result)
{
    std::vector<uint64_t> coverage_hashes;
    for (const auto& entry : ctx.program_log) {
        coverage_hashes.insert(coverage_hashes.end(),
                               entry.coverage_hashes.begin(),
                               entry.coverage_hashes.end());
    }
    std::sort(coverage_hashes.begin(), coverage_hashes.end());
    coverage_hashes.erase(std::unique(coverage_hashes.begin(), coverage_hashes.end()),
                          coverage_hashes.end());

    std::ostringstream out;
    out << "{\n";
    out << "  \"incident_id\": " << result.incident_id << ",\n";
    out << "  \"crash_title\": \"" << JsonEscape(result.crash_title) << "\",\n";
    out << "  \"target\": \"" << JsonEscape(ctx.target) << "\",\n";
    out << "  \"origin\": \"" << JsonEscape(ctx.origin) << "\",\n";
    out << "  \"completion\": \"" << CompletionStatusToString(result.completion) << "\",\n";
    out << "  \"last_stage\": \"" << ReproStageToString(result.last_completed_stage) << "\",\n";
    out << "  \"completion_reason\": \"" << CompletionReasonToString(result.completion_reason) << "\",\n";
    out << "  \"reproduced\": " << (result.reproduced ? "true" : "false") << ",\n";
    out << "  \"reliability\": " << result.reliability << ",\n";
    out << "  \"total_attempts\": " << result.total_attempts << ",\n";
    out << "  \"crash_attempts\": " << result.crash_attempts << ",\n";
    out << "  \"original_call_count\": " << result.original_call_count << ",\n";
    out << "  \"minimized_call_count\": " << result.minimized_call_count << ",\n";
    out << "  \"extract_source\": \"" << JsonEscape(result.extract_source) << "\",\n";
    out << "  \"program_log_count\": " << result.program_log_count << ",\n";
    out << "  \"crash_hash\": \"" << Hex16(ctx.crash_hash) << "\",\n";
    out << "  \"minimized_payload_size\": " << result.minimized_payload.size() << ",\n";
    out << "  \"coverage_hash_count\": " << coverage_hashes.size() << ",\n";
    out << "  \"coverage_hashes\": [";
    for (size_t i = 0; i < coverage_hashes.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << Hex16(coverage_hashes[i]) << "\"";
    }
    out << "],\n";
    out << "  \"pseudo_trace\": [";
    for (size_t i = 0; i < ctx.pseudo_trace.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << JsonEscape(ctx.pseudo_trace[i]) << "\"";
    }
    out << "],\n";
    out << "  \"unsupported_features\": [";
    for (size_t i = 0; i < ctx.unsupported_features.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << JsonEscape(ctx.unsupported_features[i]) << "\"";
    }
    out << "]\n";
    out << "}\n";
    return out.str();
}

} // namespace

ReproWorker::ReproWorker(IReproQueue& queue,
                         ReproManager& manager,
                         std::string repros_dir,
                         std::chrono::milliseconds pop_timeout)
    : queue_(queue)
    , manager_(manager)
    , repros_dir_(std::move(repros_dir))
    , pop_timeout_(pop_timeout)
{
    std::filesystem::create_directories(repros_dir_);
}

ReproWorker::~ReproWorker()
{
    Stop();
}

void ReproWorker::Start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;
    }
    stop_requested_.store(false, std::memory_order_release);
    thread_ = std::thread([this]() { Worker(); });
}

void ReproWorker::Stop()
{
    if (!running_.load(std::memory_order_acquire) && !thread_.joinable()) {
        return;
    }

    stop_requested_.store(true, std::memory_order_release);
    manager_.RequestStop();
    queue_.Close();

    if (thread_.joinable()) {
        thread_.join();
    }

    running_.store(false, std::memory_order_release);

    refuzz::logging::HostLineBuilder("ReproWorker", "stopped") << "processed=" << processed_count_.load()
              << " reproduced=" << reproduced_count_.load() << "\n";
}

uint64_t ReproWorker::ProcessedCount() const
{
    return processed_count_.load(std::memory_order_relaxed);
}

uint64_t ReproWorker::ReproducedCount() const
{
    return reproduced_count_.load(std::memory_order_relaxed);
}

void ReproWorker::Worker()
{
    while (true) {
        auto ctx = queue_.Pop(pop_timeout_);
        if (!ctx.has_value()) {
            if (stop_requested_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        refuzz::logging::HostLineBuilder("ReproWorker", "dequeue")
                  << " incident=" << ctx->incident_id
                  << " title=" << (ctx->title.empty() ? "-" : ctx->title)
                  << " crash_kind=" << CrashKindName(ctx->crash_kind)
                  << " programs=" << ctx->program_log.size()
                  << " crash_idx=" << ctx->crash_program_index
                  << "\n";

        // [async-crash-reproduction Phase 2] kernel crashes (serial-pattern, often
        // async/deferred) need the thorough extract — history-scan + bisect +
        // concat + more attempts + a race-friendly reliability gate. Auto-select
        // the "deep" policy for them; other crash kinds keep the configured policy.
        if (ctx->crash_kind == CrashKind::kKernelCrash) {
            manager_.SwitchPolicyByName("deep");
        }

        auto result = manager_.Run(*ctx);
        processed_count_.fetch_add(1, std::memory_order_relaxed);

        if (result.reproduced) {
            reproduced_count_.fetch_add(1, std::memory_order_relaxed);
        }

        refuzz::logging::HostLineBuilder("ReproWorker", "complete")
                  << " incident=" << result.incident_id
                  << " reproduced=" << (result.reproduced ? 1 : 0)
                  << " completion_reason=" << CompletionReasonToString(result.completion_reason)
                  << " extract_source=" << (result.extract_source.empty() ? "-" : result.extract_source)
                  << " attempts=" << result.total_attempts
                  << "\n";

        PersistResult(*ctx, result);
    }

    running_.store(false, std::memory_order_release);
}

void ReproWorker::PersistResult(const CrashContext& ctx, const ReproResult& result)
{
    if (repros_dir_.empty()) {
        return;
    }

    const std::string dir_name = "repro_" + std::to_string(result.incident_id) +
                                 "_" + Hex16(ctx.crash_hash);
    const auto dir = std::filesystem::path(repros_dir_) / dir_name;

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        refuzz::logging::HostLineBuilder("ReproWorker", "create_dir_failed") << dir.string()
                  << ": " << ec.message() << "\n";
        return;
    }

    WriteTextFile(dir / "description", ctx.title + "\n");
    WriteTextFile(dir / "report", BuildReproReport(ctx, result));
    WriteTextFile(dir / "meta.json", BuildReproMetaJson(ctx, result));

    if (!result.minimized_payload.empty()) {
        WriteBinaryFile(dir / "minimized_prog.bin", result.minimized_payload);
    }

    if (ctx.crash_program_index >= 0 &&
        ctx.crash_program_index < static_cast<int32_t>(ctx.program_log.size())) {
        WriteBinaryFile(dir / "original_prog.bin",
                         ctx.program_log[ctx.crash_program_index].payload);
    }

    if (!result.symbolized_report.empty()) {
        WriteTextFile(dir / "symbolized_report.txt", result.symbolized_report);
    }

    // [async-crash-reproduction Phase 3] persist the C reproducer (the upstream
    // deliverable) + any build error. Non-empty when ReproConfig.produce_c_reproducer
    // is on and a minimized typed artifact was available (Phase 1/1.5).
    if (!result.c_reproducer_source.empty()) {
        WriteTextFile(dir / "repro.c", result.c_reproducer_source);
    }
    if (!result.c_reproducer_build_err.empty()) {
        WriteTextFile(dir / "repro_build.err", result.c_reproducer_build_err);
    }

    if (!ctx.console_log.empty()) {
        WriteTextFile(dir / "console_output.txt", ctx.console_log);
    }

    refuzz::logging::HostLineBuilder("ReproWorker", "persisted") << "incident=" << result.incident_id
              << " reproduced=" << (result.reproduced ? 1 : 0)
              << " to " << dir.string() << "\n";
}

} // namespace refuzz::crash
