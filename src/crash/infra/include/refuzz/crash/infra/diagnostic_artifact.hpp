#pragma once

#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/channel/worker/mode.hpp"
#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/proto_domain/fault_event.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::crash {

struct DiagnosticMetadata {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    bool has_completed_result = false;
    uint32_t worker_id = 0;
    refuzz::proto::ResultCode result_code = refuzz::proto::ResultCode::kOk;
    refuzz::proto::InfraError infra_error = refuzz::proto::InfraError::kNone;
    uint64_t start_ts_us = 0;
    uint64_t finish_ts_us = 0;
    uint32_t crash_signal = 0;
    // [XiUOS leak 一等公民化 Phase 1] leak magnitude (bytes). Serialized as
    // `leak_bytes` in meta.json by BuildMetaJson; crash_signal stays 0 for
    // resource-leak findings so the two are never conflated.
    uint32_t leak_bytes = 0;
    // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16).
    // Serialized as `resource_residue` in meta.json; parallel to leak_bytes.
    uint32_t resource_residue = 0;
    uint64_t fault_incident_id = 0;
    uint32_t channel_id = 0;
    uint32_t slot_id = 0;
    uint32_t generation = 0;
    // [v1 默认值同 CrashContext kWorkerHeartbeatLost/kHealthMonitor — ROLLBACK]
    // refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kWorkerHeartbeatLost;
    // refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kHealthMonitor;
    // [v2 PR-D 默认值改 abnormal-shaped — ROLLBACK]
    // refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kAbnormalExit;
    // refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kAbnormalCompletion;
    // [v2 PR-E 默认值改 kUnknown 让漏填路径暴露 — 当前版本]
    // 同 CrashContext::fault_reason/source 注释:不再用合法 enum 值伪装漏填。
    refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kUnknown;
    refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kUnknown;
    // [v2 PR-D 新增 fault_origin 字段持久化 — 当前版本]
    // 旧版本 metadata 不带 fault_origin,落盘 meta.json 没这一字段,无法从落盘
    // 文件区分 abnormal path / fault path / 各 health sensor。PR-D 把字段独立
    // 放进 metadata 一起序列化。
    refuzz::proto::FaultOrigin fault_origin = refuzz::proto::FaultOrigin::kUnknown;
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode =
        refuzz::channel::worker::WorkerSanitizerMode::kNone;
};

struct DiagnosticArtifact {
    CrashKind kind = CrashKind::kUnknownIncident;
    uint64_t artifact_hash = 0;
    std::string description;
    // 中文注释：诊断产物字段改为 health::CrashFragment，彻底去掉兼容层转发。
    refuzz::channel::health::CrashFragment fragment;
    std::string target = "linux/amd64";
    std::string origin;
    std::vector<uint64_t> coverage_hashes;
    std::vector<std::string> pseudo_trace;
    std::vector<std::string> unsupported_features;
    std::vector<uint8_t> program_payload;
    std::vector<uint8_t> output_payload;
    // [crash-execution-history-ring] Layer-2: the recent COMPLETED-program history
    // preceding the crash program (time-ordered, oldest first) — ctx.program_log
    // minus the crash entry (which stays in program_payload -> prog0.bin).
    // Persisted as history0.bin .. historyN.bin so async/deferred-trigger context
    // survives to disk. Empty unless a kernel-crash harvest captured history.
    std::vector<std::vector<uint8_t>> history_payloads;
    std::string serial_log_tail;
    std::string symbolized_report;
    DiagnosticMetadata metadata;
    std::chrono::system_clock::time_point timestamp{};
};

uint64_t HashDiagnosticArtifact(CrashKind kind,
                                const std::string& description,
                                const std::vector<uint8_t>& program_payload = {},
                                const std::vector<uint8_t>& output_payload = {});

} // namespace refuzz::crash
