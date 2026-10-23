#include "refuzz/crash/infra/diagnostic_store.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

namespace refuzz::crash {

namespace {
constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t Fnv1a64Fold(uint64_t hash, const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= kFnvPrime;
    }
    return hash;
}

uint64_t Fnv1a64(const std::string& value)
{
    uint64_t hash = kFnvOffset;
    for (unsigned char ch : value) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= kFnvPrime;
    }
    return hash;
}

std::string Hex16Impl(uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

const char* KindDirectory(CrashKind kind)
{
    return CrashKindName(kind);
}

const char* KindName(CrashKind kind)
{
    return CrashKindName(kind);
}

const char* ResultCodeName(refuzz::proto::ResultCode code)
{
    switch (code) {
    case refuzz::proto::ResultCode::kOk: return "ok";
    case refuzz::proto::ResultCode::kExecError: return "exec_error";
    case refuzz::proto::ResultCode::kTimeout: return "timeout";
    case refuzz::proto::ResultCode::kCrashed: return "crashed";
    case refuzz::proto::ResultCode::kRestarted: return "restarted";
    case refuzz::proto::ResultCode::kDropped: return "dropped";
    case refuzz::proto::ResultCode::kResourceLeak: return "resource_leak";
    case refuzz::proto::ResultCode::kContractViolation: return "contract_violation";
    case refuzz::proto::ResultCode::kPriorityInversion: return "priority_inversion";
    case refuzz::proto::ResultCode::kStackOverflow: return "stack_overflow";
    }
    return "unknown";
}

const char* InfraErrorName(refuzz::proto::InfraError error)
{
    switch (error) {
    case refuzz::proto::InfraError::kNone: return "none";
    case refuzz::proto::InfraError::kTimeout: return "timeout";
    case refuzz::proto::InfraError::kWorkerCrashed: return "worker_crashed";
    case refuzz::proto::InfraError::kInvalidInput: return "invalid_input";
    case refuzz::proto::InfraError::kOutputTooLarge: return "output_too_large";
    case refuzz::proto::InfraError::kExecutorError: return "executor_error";
    }
    return "unknown";
}

const char* FaultReasonName(refuzz::proto::FaultReason reason)
{
    switch (reason) {
    case refuzz::proto::FaultReason::kWorkerHeartbeatLost: return "worker_heartbeat_lost";
    case refuzz::proto::FaultReason::kKernelCrash: return "kernel_crash";
    case refuzz::proto::FaultReason::kVmDead: return "vm_dead";
    case refuzz::proto::FaultReason::kGenerationReset: return "generation_reset";
    case refuzz::proto::FaultReason::kInflightStale: return "inflight_stale";
    case refuzz::proto::FaultReason::kSubmitFailed: return "submit_failed";
    case refuzz::proto::FaultReason::kAbnormalExit: return "abnormal_exit";
    case refuzz::proto::FaultReason::kUnknown: return "unknown";
    case refuzz::proto::FaultReason::kNoOutput: return "no_output";
    }
    return "unknown";
}

const char* FaultSourceName(refuzz::proto::FaultSource source)
{
    switch (source) {
    case refuzz::proto::FaultSource::kHealthMonitor: return "health_monitor";
    case refuzz::proto::FaultSource::kInflightSweep: return "inflight_sweep";
    case refuzz::proto::FaultSource::kSubmitPath: return "submit_path";
    case refuzz::proto::FaultSource::kChannelInternal: return "channel_internal";
    case refuzz::proto::FaultSource::kAbnormalCompletion: return "abnormal_completion";
    case refuzz::proto::FaultSource::kUnknown: return "unknown";
    }
    return "unknown";
}

// [v2 PR-D fault_origin 字段持久化 — 当前版本]
const char* FaultOriginName(refuzz::proto::FaultOrigin origin)
{
    switch (origin) {
    case refuzz::proto::FaultOrigin::kHeartbeat:          return "heartbeat";
    case refuzz::proto::FaultOrigin::kSerialEof:          return "serial_eof";
    case refuzz::proto::FaultOrigin::kSerialPattern:      return "serial_pattern";
    case refuzz::proto::FaultOrigin::kVmLiveness:         return "vm_liveness";
    case refuzz::proto::FaultOrigin::kHealthInternal:     return "health_internal";
    case refuzz::proto::FaultOrigin::kInflightSweep:      return "inflight_sweep";
    case refuzz::proto::FaultOrigin::kSubmitPath:         return "submit_path";
    case refuzz::proto::FaultOrigin::kChannelInternal:    return "channel_internal";
    case refuzz::proto::FaultOrigin::kUnknown:            return "unknown";
    case refuzz::proto::FaultOrigin::kAbnormalCompletion: return "abnormal_completion";
    }
    return "unknown";
}

const char* SanitizerModeName(refuzz::channel::worker::WorkerSanitizerMode mode)
{
    switch (mode) {
    case refuzz::channel::worker::WorkerSanitizerMode::kKasan: return "kasan";
    case refuzz::channel::worker::WorkerSanitizerMode::kKcsan: return "kcsan";
    case refuzz::channel::worker::WorkerSanitizerMode::kUbsan: return "ubsan";
    case refuzz::channel::worker::WorkerSanitizerMode::kNone:
    default:
        return "none";
    }
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
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                std::ostringstream hex;
                hex << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(ch));
                out += hex.str();
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

std::string BuildDescription(const DiagnosticArtifact& artifact, uint64_t hash)
{
    if (!artifact.description.empty()) {
        return artifact.description;
    }
    if (!artifact.fragment.title.empty()) {
        return artifact.fragment.title;
    }
    return std::string(KindName(artifact.kind)) + "-" + Hex16Impl(hash);
}

std::string BuildDirectoryName(uint64_t hash)
{
    return Hex16Impl(hash);
}

std::string BuildKey(CrashKind kind, uint64_t hash)
{
    return std::string(KindDirectory(kind)) + ":" + BuildDirectoryName(hash);
}

std::string BuildKey(CrashKind kind, const std::string& directory_name)
{
    return std::string(KindDirectory(kind)) + ":" + directory_name;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        return false;
    }
    out << text;
    out.flush();
    return out.good();
}

bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    out.flush();
    return out.good();
}

std::string BuildReport(const DiagnosticArtifact& artifact,
                        const std::string& description,
                        uint64_t hash)
{
    std::ostringstream out;
    out << "description: " << description << "\n";
    out << "kind: " << KindName(artifact.kind) << "\n";
    out << "hash: " << Hex16Impl(hash) << "\n";
    if (!artifact.fragment.title.empty()) {
        out << "title: " << artifact.fragment.title << "\n";
    }
    if (artifact.timestamp.time_since_epoch().count() != 0) {
        const auto ts = std::chrono::system_clock::to_time_t(artifact.timestamp);
        out << "timestamp: " << static_cast<long long>(ts) << "\n";
    }
    out << "executor_id: " << artifact.metadata.executor_id << "\n";
    out << "seed_id: " << artifact.metadata.seed_id << "\n";
    out << "has_completed_result: " << (artifact.metadata.has_completed_result ? "true" : "false") << "\n";
    out << "worker_id: " << artifact.metadata.worker_id << "\n";
    out << "result_code: " << ResultCodeName(artifact.metadata.result_code) << "\n";
    out << "infra_error: " << InfraErrorName(artifact.metadata.infra_error) << "\n";
    out << "start_ts_us: " << artifact.metadata.start_ts_us << "\n";
    out << "finish_ts_us: " << artifact.metadata.finish_ts_us << "\n";
    out << "crash_signal: " << artifact.metadata.crash_signal << "\n";
    // [XiUOS leak 一等公民化 Phase 1] dedicated leak magnitude (bytes).
    out << "leak_bytes: " << artifact.metadata.leak_bytes << "\n";
    // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16).
    out << "resource_residue: " << artifact.metadata.resource_residue << "\n";
    out << "fault_incident_id: " << artifact.metadata.fault_incident_id << "\n";
    out << "channel_id: " << artifact.metadata.channel_id << "\n";
    out << "slot_id: " << artifact.metadata.slot_id << "\n";
    out << "generation: " << artifact.metadata.generation << "\n";
    out << "sanitizer_mode: " << SanitizerModeName(artifact.metadata.sanitizer_mode) << "\n";
    // [v1 fault 字段仅在 incident_id != 0 时输出 — ROLLBACK: revert to v1 above]
    // [v2 PR-D 始终输出 fault_reason/source/origin — 当前版本]
    // 旧 gate 用 incident_id != 0 判定;abnormal path 的 incident_id 来自 event_id
    // 通常非 0,gate 等于无效,反而把默认值印出来误导用户。现在始终输出三字段(包含
    // 新增的 fault_origin),配合 PR-D BuildContextOp 第二分支显式赋值,meta.json
    // 里能区分 abnormal path / fault path / 各 health sensor 来源。
    out << "fault_reason: " << FaultReasonName(artifact.metadata.fault_reason) << "\n";
    out << "fault_source: " << FaultSourceName(artifact.metadata.fault_source) << "\n";
    out << "fault_origin: " << FaultOriginName(artifact.metadata.fault_origin) << "\n";
    out << "program_size: " << artifact.program_payload.size() << "\n";
    out << "output_size: " << artifact.output_payload.size() << "\n";
    out << "coverage_hash_count: " << artifact.coverage_hashes.size() << "\n";
    if (!artifact.fragment.console_output.empty()) {
        out << "\n[console]\n" << artifact.fragment.console_output;
        if (artifact.fragment.console_output.back() != '\n') {
            out << "\n";
        }
    }
    if (!artifact.serial_log_tail.empty()) {
        out << "\n[serial_log_tail]\n" << artifact.serial_log_tail;
        if (artifact.serial_log_tail.back() != '\n') {
            out << "\n";
        }
    }
    if (!artifact.symbolized_report.empty()) {
        out << "\n[symbolized_report]\n" << artifact.symbolized_report;
        if (artifact.symbolized_report.back() != '\n') {
            out << "\n";
        }
    }
    return out.str();
}

std::string BuildMetaJson(const DiagnosticArtifact& artifact,
                          const std::string& description,
                          uint64_t hash)
{
    std::ostringstream out;
    out << "{\n";
    out << "  \"description\": \"" << JsonEscape(description) << "\",\n";
    out << "  \"kind\": \"" << KindName(artifact.kind) << "\",\n";
    out << "  \"hash\": \"" << Hex16Impl(hash) << "\",\n";
    out << "  \"title\": \"" << JsonEscape(artifact.fragment.title) << "\",\n";
    out << "  \"target\": \"" << JsonEscape(artifact.target) << "\",\n";
    out << "  \"origin\": \"" << JsonEscape(artifact.origin) << "\",\n";
    out << "  \"executor_id\": " << artifact.metadata.executor_id << ",\n";
    out << "  \"seed_id\": " << artifact.metadata.seed_id << ",\n";
    out << "  \"has_completed_result\": "
        << (artifact.metadata.has_completed_result ? "true" : "false") << ",\n";
    out << "  \"worker_id\": " << artifact.metadata.worker_id << ",\n";
    out << "  \"result_code\": \"" << ResultCodeName(artifact.metadata.result_code) << "\",\n";
    out << "  \"infra_error\": \"" << InfraErrorName(artifact.metadata.infra_error) << "\",\n";
    out << "  \"start_ts_us\": " << artifact.metadata.start_ts_us << ",\n";
    out << "  \"finish_ts_us\": " << artifact.metadata.finish_ts_us << ",\n";
    out << "  \"crash_signal\": " << artifact.metadata.crash_signal << ",\n";
    // [XiUOS leak 一等公民化 Phase 1] dedicated leak magnitude (bytes). For
    // resource-leak findings this holds N and crash_signal stays 0.
    out << "  \"leak_bytes\": " << artifact.metadata.leak_bytes << ",\n";
    // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16);
    // for resource leaks decode as waitq=&0xff, victim=>>8&0xff, delay=>>16&0xff.
    out << "  \"resource_residue\": " << artifact.metadata.resource_residue << ",\n";
    out << "  \"fault_incident_id\": " << artifact.metadata.fault_incident_id << ",\n";
    out << "  \"channel_id\": " << artifact.metadata.channel_id << ",\n";
    out << "  \"slot_id\": " << artifact.metadata.slot_id << ",\n";
    out << "  \"generation\": " << artifact.metadata.generation << ",\n";
    out << "  \"sanitizer_mode\": \"" << SanitizerModeName(artifact.metadata.sanitizer_mode) << "\",\n";
    // [v1 fault 字段仅在 incident_id != 0 时输出 — ROLLBACK: revert to gated version]
    // [v2 PR-D 始终输出 fault_reason/source/origin — 当前版本]
    // 同 BuildReport: 旧 gate 反而把 default 值漏出去误导用户;现在始终输出。
    out << "  \"fault_reason\": \"" << FaultReasonName(artifact.metadata.fault_reason) << "\",\n";
    out << "  \"fault_source\": \"" << FaultSourceName(artifact.metadata.fault_source) << "\",\n";
    out << "  \"fault_origin\": \"" << FaultOriginName(artifact.metadata.fault_origin) << "\",\n";
    out << "  \"program_size\": " << artifact.program_payload.size() << ",\n";
    out << "  \"output_size\": " << artifact.output_payload.size() << ",\n";
    // [crash-execution-history-ring] number of history{i}.bin files (recent
    // execution sequence preceding the crash program, oldest first).
    out << "  \"history_count\": " << artifact.history_payloads.size() << ",\n";
    out << "  \"coverage_hash_count\": " << artifact.coverage_hashes.size() << ",\n";
    out << "  \"coverage_hashes\": [";
    for (size_t i = 0; i < artifact.coverage_hashes.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << Hex16Impl(artifact.coverage_hashes[i]) << "\"";
    }
    out << "],\n";
    out << "  \"pseudo_trace\": [";
    for (size_t i = 0; i < artifact.pseudo_trace.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << JsonEscape(artifact.pseudo_trace[i]) << "\"";
    }
    out << "],\n";
    out << "  \"unsupported_features\": [";
    for (size_t i = 0; i < artifact.unsupported_features.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << JsonEscape(artifact.unsupported_features[i]) << "\"";
    }
    out << "]\n";
    out << "}\n";
    return out.str();
}

std::string BuildCoverageHashesText(const std::vector<uint64_t>& coverage_hashes)
{
    std::ostringstream out;
    for (uint64_t value : coverage_hashes) {
        out << Hex16Impl(value) << "\n";
    }
    return out.str();
}

constexpr CrashKind kPersistedKinds[] = {
    CrashKind::kKernelCrash,
    CrashKind::kWorkerDead,
    CrashKind::kVmDead,
    CrashKind::kExecutionTimeout,
    CrashKind::kExecError,
    CrashKind::kUnknownIncident,
    CrashKind::kResourceLeak,    // [XiUOS leak 一等公民化 Phase 1]
    CrashKind::kStateViolation,  // [XiUOS leak 一等公民化 Phase 2]
    CrashKind::kContractViolation,  // [Contract oracle §3.1]
    CrashKind::kPriorityInversion,  // [Priority-inversion detector]
    CrashKind::kStackOverflow,      // [Stack-overflow detector]
    CrashKind::kNoOutput,
};

} // namespace

uint64_t HashDiagnosticArtifact(CrashKind kind,
                                const std::string& description,
                                const std::vector<uint8_t>& program_payload,
                                const std::vector<uint8_t>& output_payload)
{
    uint64_t hash = Fnv1a64(KindName(kind));
    hash = Fnv1a64Fold(hash,
                       reinterpret_cast<const uint8_t*>(description.data()),
                       description.size());
    if (!program_payload.empty()) {
        hash = Fnv1a64Fold(hash, program_payload.data(), program_payload.size());
    }
    if (!output_payload.empty()) {
        hash = Fnv1a64Fold(hash, output_payload.data(), output_payload.size());
    }
    return hash;
}

DiagnosticStore::DiagnosticStore(std::string root_dir)
    : root_dir_(std::move(root_dir))
{
    for (CrashKind kind : kPersistedKinds) {
        std::filesystem::create_directories(std::filesystem::path(root_dir_) / KindDirectory(kind));
    }
    LoadExistingArtifacts();
}

SaveStatus DiagnosticStore::SaveArtifact(const DiagnosticArtifact& artifact)
{
    std::lock_guard<std::mutex> lock(mu_);
    uint64_t hash = artifact.artifact_hash;
    const std::string description = BuildDescription(artifact, hash);
    if (hash == 0) {
        hash = HashDiagnosticArtifact(artifact.kind,
                                      description,
                                      artifact.program_payload,
                                      artifact.output_payload);
    }

    const std::string key = BuildKey(artifact.kind, hash);
    if (seen_keys_.count(key) > 0) {
        return SaveStatus::kDuplicate;
    }

    const auto dir = std::filesystem::path(root_dir_) /
                     KindDirectory(artifact.kind) /
                     BuildDirectoryName(hash);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return SaveStatus::kIOError;
    }

    if (!WriteTextFile(dir / "description", description + "\n")) {
        return SaveStatus::kIOError;
    }
    if (!WriteTextFile(dir / "report0", BuildReport(artifact, description, hash))) {
        return SaveStatus::kIOError;
    }
    if (!WriteTextFile(dir / "meta.json", BuildMetaJson(artifact, description, hash))) {
        return SaveStatus::kIOError;
    }
    if (!WriteBinaryFile(dir / "prog0.bin", artifact.program_payload)) {
        return SaveStatus::kIOError;
    }
    if (!WriteBinaryFile(dir / "output0.bin", artifact.output_payload)) {
        return SaveStatus::kIOError;
    }
    // [crash-execution-history-ring] persist the recent execution history that
    // preceded the crash program (oldest first) as history0.bin .. historyN.bin,
    // so async/deferred-trigger context survives to disk for offline analysis.
    for (std::size_t i = 0; i < artifact.history_payloads.size(); ++i) {
        if (!WriteBinaryFile(dir / ("history" + std::to_string(i) + ".bin"),
                             artifact.history_payloads[i])) {
            return SaveStatus::kIOError;
        }
    }
    if (!artifact.coverage_hashes.empty() &&
        !WriteTextFile(dir / "coverage_hashes.txt", BuildCoverageHashesText(artifact.coverage_hashes))) {
        return SaveStatus::kIOError;
    }
    if (!artifact.serial_log_tail.empty() &&
        !WriteTextFile(dir / "serial_log_tail.txt", artifact.serial_log_tail)) {
        return SaveStatus::kIOError;
    }
    if (!artifact.symbolized_report.empty() &&
        !WriteTextFile(dir / "symbolized_report.txt", artifact.symbolized_report)) {
        return SaveStatus::kIOError;
    }

    seen_keys_.insert(key);
    return SaveStatus::kSaved;
}

bool DiagnosticStore::IsDuplicate(CrashKind kind, uint64_t hash) const
{
    std::lock_guard<std::mutex> lock(mu_);
    return seen_keys_.count(BuildKey(kind, hash)) > 0;
}

size_t DiagnosticStore::Count() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return seen_keys_.size();
}

void DiagnosticStore::LoadExistingArtifacts()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (CrashKind kind : kPersistedKinds) {
        const auto bucket_dir = std::filesystem::path(root_dir_) / KindDirectory(kind);
        std::error_code ec;
        if (!std::filesystem::exists(bucket_dir, ec) || ec) {
            continue;
        }
        for (std::filesystem::directory_iterator it(bucket_dir, ec), end; !ec && it != end; it.increment(ec)) {
            if (!it->is_directory()) {
                continue;
            }
            if (!std::filesystem::exists(it->path() / "description", ec) || ec) {
                ec.clear();
                continue;
            }
            seen_keys_.insert(BuildKey(kind, it->path().filename().string()));
        }
    }
}

std::string DiagnosticStore::Hex16(uint64_t value)
{
    return Hex16Impl(value);
}

} // namespace refuzz::crash
