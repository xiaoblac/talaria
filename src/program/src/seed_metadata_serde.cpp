// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedMetadataSerdeRegistry 实现 + 4 种 builtin durable seed metadata 类型的
// JSON serde free function:
//   - TriageStableSignalMetadata
//   - SeedAuditMetadata
//   - SeedSourceMetadata
//   - [v2 batch 3 G6] SeedAdmissionStateMetadata
//
// 详 hpp 头注释 + docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-W3 + §3.G6。

#include "refuzz/program/seed_metadata_serde.hpp"

#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/seed_metadata.hpp"

#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <utility>

namespace refuzz::fuzzer {

// ─── SeedMetadataSerdeRegistry ────────────────────────────────────────────────

SeedMetadataSerdeRegistry& SeedMetadataSerdeRegistry::Instance()
{
    static SeedMetadataSerdeRegistry inst;
    return inst;
}

void SeedMetadataSerdeRegistry::Register(std::string json_key,
                                          WriteFn     write_fn,
                                          ReadFn      read_fn)
{
    std::lock_guard<std::mutex> lk(mu_);
    RegisterOrReplaceUnlocked(std::move(json_key),
                              std::move(write_fn),
                              std::move(read_fn));
}

void SeedMetadataSerdeRegistry::RegisterOrReplaceUnlocked(std::string json_key,
                                                          WriteFn     write_fn,
                                                          ReadFn      read_fn)
{
    // 幂等:同 json_key replace-in-place;新 key append。
    for (auto& e : entries_) {
        if (e.json_key == json_key) {
            e.write_fn = std::move(write_fn);
            e.read_fn  = std::move(read_fn);
            return;
        }
    }
    entries_.push_back(Entry{std::move(json_key), std::move(write_fn), std::move(read_fn)});
}

void SeedMetadataSerdeRegistry::WriteAll(const refuzz::core::MetadataMap& meta,
                                          nlohmann::json&                  root) const
{
    std::vector<Entry> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        snapshot = entries_;
    }
    for (const auto& e : snapshot) {
        if (e.write_fn) {
            e.write_fn(meta, root);
        }
    }
}

void SeedMetadataSerdeRegistry::ReadAll(const nlohmann::json&       root,
                                         refuzz::core::MetadataMap&  meta) const
{
    std::vector<Entry> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        snapshot = entries_;
    }
    for (const auto& e : snapshot) {
        if (e.read_fn) {
            e.read_fn(root, meta);
        }
    }
}

void SeedMetadataSerdeRegistry::ResetForTest()
{
    std::lock_guard<std::mutex> lk(mu_);
    entries_.clear();
    builtins_registered_ = false;
}

std::size_t SeedMetadataSerdeRegistry::Size() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.size();
}

// ─── JSON util(从 corpus_disk_io 移过来,本 file 内部用)─────────────────────

namespace {

std::string Hex64(std::uint64_t value)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

void WriteU64Array(nlohmann::json& obj,
                   const char* key,
                   const std::vector<std::uint64_t>& values)
{
    auto arr = nlohmann::json::array();
    for (std::uint64_t v : values) {
        arr.push_back(Hex64(v));
    }
    obj[key] = std::move(arr);
}

std::vector<std::uint64_t> ReadU64Array(const nlohmann::json& obj, const char* key)
{
    std::vector<std::uint64_t> out;
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_array()) {
        return out;
    }
    for (const auto& item : obj[key]) {
        try {
            if (item.is_string()) {
                out.push_back(std::stoull(item.get<std::string>(), nullptr, 16));
            } else if (item.is_number_unsigned()) {
                out.push_back(item.get<std::uint64_t>());
            }
        } catch (...) {
        }
    }
    return out;
}

std::vector<std::string> ReadStringArray(const nlohmann::json& obj, const char* key)
{
    std::vector<std::string> out;
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_array()) {
        return out;
    }
    for (const auto& item : obj[key]) {
        if (item.is_string()) {
            out.push_back(item.get<std::string>());
        }
    }
    return out;
}

// ─── TriageStableSignalMetadata serde ────────────────────────────────────────

void WriteTriageStableSignal(const refuzz::core::MetadataMap& meta,
                              nlohmann::json&                  root)
{
    if (const auto* stable = meta.Get<TriageStableSignalMetadata>()) {
        nlohmann::json stable_json;
        WriteU64Array(stable_json, "hashes", stable->hashes);
        if (stable->guilty_call_index >= 0) {
            stable_json["guilty_call_index"] = stable->guilty_call_index;
        }
        if (!stable->guilty_call_hashes.empty()) {
            WriteU64Array(stable_json, "guilty_call_hashes",
                          stable->guilty_call_hashes);
        }
        if (stable->exec_status.has_value()) {
            stable_json["exec_status"] =
                static_cast<std::uint8_t>(*stable->exec_status);
        }
        if (stable->guilty_errno_value.has_value()) {
            stable_json["guilty_errno_value"] = *stable->guilty_errno_value;
        }
        if (stable->guilty_syscall_id.has_value()) {
            stable_json["guilty_syscall_id"] = *stable->guilty_syscall_id;
        }
        root["triage_stable_signal"] = std::move(stable_json);
    }
}

void ReadTriageStableSignal(const nlohmann::json&       root,
                             refuzz::core::MetadataMap&  meta)
{
    if (!root.is_object() || !root.contains("triage_stable_signal") ||
        !root["triage_stable_signal"].is_object()) {
        return;
    }
    TriageStableSignalMetadata stable;
    const auto& stable_json = root["triage_stable_signal"];
    stable.hashes = ReadU64Array(stable_json, "hashes");
    if (stable_json.contains("guilty_call_index") &&
        stable_json["guilty_call_index"].is_number_integer()) {
        stable.guilty_call_index = stable_json["guilty_call_index"].get<int>();
    }
    stable.guilty_call_hashes = ReadU64Array(stable_json, "guilty_call_hashes");
    if (stable_json.contains("exec_status") &&
        stable_json["exec_status"].is_number_integer()) {
        stable.exec_status = static_cast<refuzz::proto::ResultCode>(
            stable_json["exec_status"].get<std::uint8_t>());
    }
    if (stable_json.contains("guilty_errno_value") &&
        stable_json["guilty_errno_value"].is_number_integer()) {
        stable.guilty_errno_value =
            stable_json["guilty_errno_value"].get<std::int32_t>();
    }
    if (stable_json.contains("guilty_syscall_id") &&
        stable_json["guilty_syscall_id"].is_number_unsigned()) {
        stable.guilty_syscall_id =
            stable_json["guilty_syscall_id"].get<std::uint32_t>();
    }
    meta.Set(std::move(stable));
}

// ─── SeedAuditMetadata serde ─────────────────────────────────────────────────

void WriteSeedAudit(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* audit = meta.Get<SeedAuditMetadata>()) {
        nlohmann::json audit_json;
        audit_json["target"]      = audit->target;
        audit_json["origin"]      = audit->origin;
        audit_json["crash_title"] = audit->crash_title;
        WriteU64Array(audit_json, "coverage_hashes", audit->coverage_hashes);
        audit_json["pseudo_trace"]         = audit->pseudo_trace;
        audit_json["unsupported_features"] = audit->unsupported_features;
        root["audit"] = std::move(audit_json);
    }
}

void ReadSeedAudit(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("audit") || !root["audit"].is_object()) {
        return;
    }
    const auto& a = root["audit"];
    SeedAuditMetadata audit;
    if (a.contains("target") && a["target"].is_string()) {
        audit.target = a["target"].get<std::string>();
    }
    if (a.contains("origin") && a["origin"].is_string()) {
        audit.origin = a["origin"].get<std::string>();
    }
    if (a.contains("crash_title") && a["crash_title"].is_string()) {
        audit.crash_title = a["crash_title"].get<std::string>();
    }
    audit.coverage_hashes      = ReadU64Array(a, "coverage_hashes");
    audit.pseudo_trace         = ReadStringArray(a, "pseudo_trace");
    audit.unsupported_features = ReadStringArray(a, "unsupported_features");
    meta.Set(std::move(audit));
}

// ─── SeedSourceMetadata serde ───────────────────────────────────────────────

const char* SeedSourceToString(SeedSource source)
{
    switch (source) {
        case SeedSource::kBootCorpus:    return "boot_corpus";
        case SeedSource::kMutation:      return "mutation";
        case SeedSource::kReplayHistory: return "replay_history";
        case SeedSource::kFaultHistory:  return "fault_history";
    }
    return nullptr;
}

std::optional<SeedSource> SeedSourceFromString(const std::string& name)
{
    if (name == "boot_corpus")    return SeedSource::kBootCorpus;
    if (name == "mutation")       return SeedSource::kMutation;
    if (name == "replay_history") return SeedSource::kReplayHistory;
    if (name == "fault_history")  return SeedSource::kFaultHistory;
    return std::nullopt;
}

void WriteSeedSource(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* src = meta.Get<SeedSourceMetadata>()) {
        const char* source_name = SeedSourceToString(src->source);
        if (source_name == nullptr) {
            refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_seed_source")
                << "value=" << static_cast<unsigned>(src->source) << "\n";
            return;
        }
        nlohmann::json src_json;
        src_json["source"]  = source_name;
        src_json["attempt"] = src->attempt;
        root["seed_source"] = std::move(src_json);
    }
}

void ReadSeedSource(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("seed_source") ||
        !root["seed_source"].is_object()) {
        return;
    }
    const auto& s = root["seed_source"];
    if (!s.contains("source") || !s["source"].is_string()) {
        refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_seed_source")
            << "reason=missing_or_non_string_source\n";
        return;
    }
    const auto source_name = s["source"].get<std::string>();
    auto source = SeedSourceFromString(source_name);
    if (!source.has_value()) {
        refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_seed_source")
            << "value=" << source_name << "\n";
        return;
    }
    SeedSourceMetadata src;
    src.source = *source;
    if (s.contains("attempt") && s["attempt"].is_number_unsigned()) {
        src.attempt = s["attempt"].get<std::uint32_t>();
    }
    meta.Set(std::move(src));
}

// ─── SeedAdmissionStateMetadata serde ───────────────────────────────────────

const char* SeedAdmissionStateToString(SeedAdmissionState state)
{
    switch (state) {
        case SeedAdmissionState::kActive:   return "active";
        case SeedAdmissionState::kInactive: return "inactive";
    }
    return nullptr;
}

std::optional<SeedAdmissionState> SeedAdmissionStateFromString(const std::string& name)
{
    if (name == "active")   return SeedAdmissionState::kActive;
    if (name == "inactive") return SeedAdmissionState::kInactive;
    return std::nullopt;
}

void WriteSeedAdmissionState(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* admit = meta.Get<SeedAdmissionStateMetadata>()) {
        const char* state_name = SeedAdmissionStateToString(admit->state);
        if (state_name == nullptr) {
            refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_admission_state")
                << "value=" << static_cast<unsigned>(admit->state) << "\n";
            return;
        }
        nlohmann::json admit_json;
        admit_json["state"]           = state_name;
        admit_json["inactive_reason"] = admit->inactive_reason;
        admit_json["verify_attempts"] = admit->verify_attempts;
        root["seed_admission_state"]  = std::move(admit_json);
    }
}

void ReadSeedAdmissionState(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("seed_admission_state") ||
        !root["seed_admission_state"].is_object()) {
        return;
    }
    const auto& s = root["seed_admission_state"];
    if (!s.contains("state") || !s["state"].is_string()) {
        refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_admission_state")
            << "reason=missing_or_non_string_state\n";
        return;
    }
    const auto state_name = s["state"].get<std::string>();
    auto state = SeedAdmissionStateFromString(state_name);
    if (!state.has_value()) {
        refuzz::logging::HostLineBuilder("SeedMetadataSerde", "invalid_admission_state")
            << "value=" << state_name << "\n";
        return;
    }
    SeedAdmissionStateMetadata admit;
    admit.state = *state;
    if (s.contains("inactive_reason") && s["inactive_reason"].is_string()) {
        admit.inactive_reason = s["inactive_reason"].get<std::string>();
    }
    if (s.contains("verify_attempts") && s["verify_attempts"].is_number_unsigned()) {
        admit.verify_attempts = s["verify_attempts"].get<std::uint32_t>();
    }
    meta.Set(std::move(admit));
}

// ─── CorpusCoverageMetadata serde (Task A) ──────────────────────────────────

void WriteCorpusCoverage(const refuzz::core::MetadataMap& meta, nlohmann::json& root)
{
    if (const auto* cc = meta.Get<CorpusCoverageMetadata>()) {
        if (!cc->cover_hashes.empty()) {
            nlohmann::json cc_json;
            WriteU64Array(cc_json, "cover_hashes", cc->cover_hashes);
            root["corpus_coverage"] = std::move(cc_json);
        }
    }
}

void ReadCorpusCoverage(const nlohmann::json& root, refuzz::core::MetadataMap& meta)
{
    if (!root.is_object() || !root.contains("corpus_coverage") ||
        !root["corpus_coverage"].is_object()) {
        return;  // no fallback: absence means "cover unknown", not "empty corpus"
    }
    CorpusCoverageMetadata cc;
    cc.cover_hashes = ReadU64Array(root["corpus_coverage"], "cover_hashes");
    if (!cc.cover_hashes.empty()) {
        meta.Set(std::move(cc));
    }
}

}  // namespace

// ─── Builtin registration ────────────────────────────────────────────────────

void SeedMetadataSerdeRegistry::EnsureBuiltinSeedMetadataSerdes()
{
    std::lock_guard<std::mutex> lk(mu_);
    if (builtins_registered_) {
        return;
    }
    RegisterOrReplaceUnlocked("triage_stable_signal",
                              &WriteTriageStableSignal,
                              &ReadTriageStableSignal);
    RegisterOrReplaceUnlocked("audit",
                              &WriteSeedAudit,
                              &ReadSeedAudit);
    RegisterOrReplaceUnlocked("seed_source",
                              &WriteSeedSource,
                              &ReadSeedSource);
    RegisterOrReplaceUnlocked("seed_admission_state",
                              &WriteSeedAdmissionState,
                              &ReadSeedAdmissionState);
    // [Task A / F2] persist corpus-admitted full cover so it survives restart
    // and can be backfill-merged into the corpus-cover store on boot.
    RegisterOrReplaceUnlocked("corpus_coverage",
                              &WriteCorpusCoverage,
                              &ReadCorpusCoverage);
    builtins_registered_ = true;
}

void RegisterBuiltinSeedMetadataSerdes()
{
    SeedMetadataSerdeRegistry::Instance().EnsureBuiltinSeedMetadataSerdes();
}

}  // namespace refuzz::fuzzer
