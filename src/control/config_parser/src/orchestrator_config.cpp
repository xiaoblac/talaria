// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/config_parser/parse_config_from_json.hpp"
#include "refuzz/channel/factory/channel_catalog.hpp"          // channel_backend_id
#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"        // [Stage 3] XiUOS backend
#include "refuzz/channel/factory/ch32_uart_profile.hpp"         // [Phase Q2] CH32 board backend
#include "refuzz/channel/factory/sifive_uart_xiuos_profile.hpp" // app-surface sifive_u backend
#include "refuzz/orchestrator/session_layout.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "util/json.hpp"

#include <algorithm>
#include <initializer_list>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include "refuzz/logging/host_logger.hpp"

namespace refuzz::orchestrator {

namespace {

constexpr uint32_t kDefaultKcovEntries = 512u << 10;
constexpr uint32_t kMinKcovEntries = 1024u;
constexpr uint32_t kMaxKcovEntries = kDefaultKcovEntries;

// ivshmem_size_mb 不再需要：shm 大小由 ShmInfra::Init() 计算并通过
// infra_.total_size() 注入到 RuntimeInstanceConfig.ivshmem_bytes（Boot() 负责）。
// orchestrator 只需提供 n_workers，大小由底层统一管理。

std::string GetString(const nlohmann::json& obj, const char* key, const std::string& default_value = {})
{
    if (obj.contains(key) && obj[key].is_string()) {
        return obj[key].get<std::string>();
    }
    return default_value;
}

uint32_t GetU32(const nlohmann::json& obj, const char* key, uint32_t default_value)
{
    if (!obj.contains(key)) {
        return default_value;
    }
    const auto& value = obj[key];
    if (value.is_number_unsigned()) {
        return value.get<uint32_t>();
    }
    if (value.is_number_integer()) {
        const auto signed_value = value.get<int64_t>();
        if (signed_value >= 0) {
            return static_cast<uint32_t>(signed_value);
        }
    }
    return default_value;
}

uint64_t GetU64(const nlohmann::json& obj, const char* key, uint64_t default_value)
{
    if (!obj.contains(key)) {
        return default_value;
    }
    const auto& value = obj[key];
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
        const auto signed_value = value.get<int64_t>();
        if (signed_value >= 0) {
            return static_cast<uint64_t>(signed_value);
        }
    }
    return default_value;
}

bool GetBool(const nlohmann::json& obj, const char* key, bool default_value)
{
    if (obj.contains(key) && obj[key].is_boolean()) {
        return obj[key].get<bool>();
    }
    return default_value;
}

std::vector<std::string> GetStringArray(const nlohmann::json& obj, const char* key)
{
    std::vector<std::string> out;
    if (obj.contains(key) && obj[key].is_array()) {
        for (const auto& element : obj[key]) {
            if (element.is_string()) {
                out.push_back(element.get<std::string>());
            }
        }
    }
    return out;
}

bool IsMetaKey(std::string_view key)
{
    return !key.empty() && key.front() == '_';
}

bool IsAllowedKey(std::string_view key,
                  std::initializer_list<std::string_view> allowed)
{
    for (const auto candidate : allowed) {
        if (key == candidate) {
            return true;
        }
    }
    return false;
}

bool CheckObjectKeys(const nlohmann::json& obj,
                     std::string_view path,
                     std::initializer_list<std::string_view> allowed)
{
    if (!obj.is_object()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << path << " must be a JSON object\n";
        return false;
    }
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (IsMetaKey(it.key())) {
            continue;
        }
        if (!IsAllowedKey(it.key(), allowed)) {
            refuzz::logging::HostLineBuilder("Config", "unknown_key")
                << "unknown or unsupported config key: "
                << path << "." << it.key() << "\n";
            return false;
        }
    }
    return true;
}

bool CheckChildObjectKeys(const nlohmann::json& parent,
                          const char* key,
                          std::string_view path,
                          std::initializer_list<std::string_view> allowed)
{
    if (!parent.contains(key)) {
        return true;
    }
    if (!parent[key].is_object()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << path << " must be a JSON object\n";
        return false;
    }
    return CheckObjectKeys(parent[key], path, allowed);
}

bool GetObject(const nlohmann::json& parent,
               const char* key,
               std::string_view path,
               nlohmann::json* out)
{
    if (!parent.contains(key)) {
        *out = nlohmann::json::object();
        return true;
    }
    if (!parent[key].is_object()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << path << " must be a JSON object\n";
        return false;
    }
    *out = parent[key];
    return true;
}

bool CheckKnownConfigKeys(const nlohmann::json& root)
{
    if (!CheckObjectKeys(root, "root",
                         {"profile",
                          "work_dir", "state_dir", "retention", "retention_max",
                          "channel", "executor", "fuzzer", "telemetry", "coverage",
                          "target", "persistence", "repro",
                          "phase0_worker_bin", "phase0_vm_id",
                          "phase1_run_limit_mode", "phase1_runtime_seconds",
                          "phase1_total_tasks",
                          "components", "feedback_engine_spec", "stages",
                          // [fixed request stream] see RunMode/ReplayConfig.
                          "run_mode", "replay"})) {
        return false;
    }
    if (!CheckChildObjectKeys(root, "replay", "root.replay",
                              {"stream_path",
                               // [fixed request stream] hold-before-teardown,
                               // see ReplayConfig.
                               "drained_marker_path", "release_path",
                               "hold_timeout_s"})) {
        return false;
    }

    if (!CheckChildObjectKeys(root, "components", "root.components",
                              {"mutator_engine", "scheduler_engine",
                               "corpus_store", "corpus_admission",
                               "feedback_engine", "channel_backend_id",
                               "target_toolkit"})) {
        return false;
    }
    if (!CheckChildObjectKeys(root, "feedback_engine_spec",
                              "root.feedback_engine_spec",
                              {"engine_id", "signal_ids", "aggregator_id",
                               "aggregator_context"})) {
        return false;
    }
    if (root.contains("feedback_engine_spec") &&
        root["feedback_engine_spec"].is_object()) {
        const auto& spec = root["feedback_engine_spec"];
        if (!CheckChildObjectKeys(spec, "aggregator_context",
                                  "root.feedback_engine_spec.aggregator_context",
                                  {"signal_weights", "interesting_threshold"})) {
            return false;
        }
    }
    if (!CheckChildObjectKeys(root, "stages", "root.stages",
                              {"stage_specs", "producer_chain", "consumer_chain"})) {
        return false;
    }

    if (!CheckChildObjectKeys(root, "channel", "root.channel",
                              {"vm", "transport", "health",
                               "fuzz_channel_count",
                               "wait_ready_timeout_ms", "loop_interval_ms",
                               "health_check_interval_ms",
                               "pre_reboot_drain_ms",
                               "input_queue_capacity",
                               // [v2 PR-E — 当前版本] abnormal 路径 console snapshot 行数
                               "abnormal_console_snapshot_lines",
                               // [crash-execution-history-ring] Layer-2 history depth
                               "crash_history_depth"})) {
        return false;
    }
    if (root.contains("channel") && root["channel"].is_object()) {
        const auto& channel = root["channel"];
        if (!CheckChildObjectKeys(channel, "vm", "root.channel.vm",
                                  {"arch", "image", "kernel", "ssh_key",
                                   "ssh_user", "qemu", "workdir"})) {
            return false;
        }
        if (channel.contains("vm") && channel["vm"].is_object()) {
            const auto& vm = channel["vm"];
            if (!CheckChildObjectKeys(vm, "qemu", "root.channel.vm.qemu",
                                      {"qemu", "cpu", "mem", "cmdline",
                                       "snapshot", "snapshot_fuzzing",
                                       "serial_log_path"})) {
                return false;
            }
        }
        if (!CheckChildObjectKeys(channel, "transport",
                                  "root.channel.transport",
                                  {"n_workers", "ivshmem_path",
                                   "ivshmem_mode", "doorbell_socket_path",
                                   "ivshmem_vectors", "wait_ready_poll_us",
                                   "poll_sleep_us",
                                   "wait_ready_timeout_us"})) {
            return false;
        }
        if (!CheckChildObjectKeys(channel, "health", "root.channel.health",
                                  {"enable", "sample_interval_ms",
                                   "heartbeat_timeout_ms",
                                   "heartbeat_miss_threshold",
                                   "workers_per_round",
                                   // [检测器 A / 级联断路 — M5b] 新增 health 调参键，必须
                                   //   在 strict-key allowlist 里登记,否则带这些键的 config
                                   //   被 CheckObjectKeys fail-closed 拒绝(ParseConfigFromJson 失败)。
                                   "vm_dead_timeout_ms",
                                   "recovery_window_base_ms",
                                   "recovery_window_cap_ms",
                                   "cascade_window_ms",
                                   "cascade_reboot_budget"})) {
            return false;
        }
    }

    if (!CheckChildObjectKeys(root, "executor", "root.executor",
                              {"idle_sleep_us", "event_blocking_timeout_us",
                               "submit_wait_for_slot_ms", "dispatch",
                               "event_forward_strategy", "event_drain",
                               "submit_strategy", "timeouts_ms"})) {
        return false;
    }
    if (root.contains("executor") && root["executor"].is_object()) {
        const auto& executor = root["executor"];
        if (!CheckChildObjectKeys(executor, "dispatch",
                                  "root.executor.dispatch",
                                  {"idle_sleep_us"})) {
            return false;
        }
        if (!CheckChildObjectKeys(executor, "event_forward_strategy",
                                  "root.executor.event_forward_strategy",
                                  {"blocking_timeout_ms"})) {
            return false;
        }
        if (!CheckChildObjectKeys(executor, "event_drain",
                                  "root.executor.event_drain",
                                  {"blocking_timeout_us"})) {
            return false;
        }
        if (!CheckChildObjectKeys(executor, "submit_strategy",
                                  "root.executor.submit_strategy",
                                  {"name"})) {
            return false;
        }
        if (!CheckChildObjectKeys(executor, "timeouts_ms",
                                  "root.executor.timeouts_ms",
                                  {"poll", "pop"})) {
            return false;
        }
    }

    if (!CheckChildObjectKeys(root, "fuzzer", "root.fuzzer",
                              // [request-window] high_watermark 已废弃:窗口现由 transport.n_workers
                              //   推导(2×),此键仍被接受但其值被忽略(不破已有 config)。
                              {"high_watermark", "exec_timeout_ms",
                               "shutdown_grace_ms", "worker_log",
                               "worker_perf", "mutator_policy",
                               "scheduling_policy",
                               "mab_time_cap_s",  // [SyzVegas baseline] reward 时间成本截顶
                               // [seed-value signals shadow] opt-in JSONL dump.
                               "seed_value_shadow_enabled",
                               // [seed-future-value] opt-in structural future(seed).
                               "seed_horizon_enabled",
                               // [future_band2] band-② shadow candidate map path.
                               "seed_band2_map_path",
                               // [variant-handler-binding] live per_call map function-block-map path.
                               "variant_handler_map_path",
                               // [belief-graph] static belief prior graph_M.tsv path (shadow).
                               "belief_graph_path",
                               // [request-stream capture] JSONL of every dispatched request.
                               "request_stream_capture_path",
                               "corpus"})) {
        return false;
    }
    if (root.contains("fuzzer") && root["fuzzer"].is_object()) {
        if (!CheckChildObjectKeys(root["fuzzer"], "corpus",
                                  "root.fuzzer.corpus",
                                  {"capacity", "max_drain", "minimize"})) {
            return false;
        }
        // [PR2] validate fuzzer.corpus.minimize sub-keys (strict, like siblings).
        if (root["fuzzer"].contains("corpus") &&
            root["fuzzer"]["corpus"].is_object() &&
            !CheckChildObjectKeys(root["fuzzer"]["corpus"], "minimize",
                                  "root.fuzzer.corpus.minimize",
                                  {"enabled", "floor", "growth_pct", "on_edges"})) {
            return false;
        }
        if (!CheckChildObjectKeys(root["fuzzer"], "worker_log",
                                  "root.fuzzer.worker_log",
                                  {"enable"})) {
            return false;
        }
        if (!CheckChildObjectKeys(root["fuzzer"], "worker_perf",
                                  "root.fuzzer.worker_perf",
                                  {"enable", "sample_rate", "report_every"})) {
            return false;
        }
    }

    if (!CheckChildObjectKeys(root, "telemetry", "root.telemetry",
                              {"policy_monitor", "observability",
                               "dashboard", "logging"})) {
        return false;
    }
    if (root.contains("telemetry") && root["telemetry"].is_object()) {
        const auto& telemetry = root["telemetry"];
        if (!CheckChildObjectKeys(telemetry, "policy_monitor",
                                  "root.telemetry.policy_monitor",
                                  {"min_dwell_seconds", "window_size",
                                   "stall_threshold", "required_windows",
                                   "degraded_channel_ratio"})) {
            return false;
        }
        if (!CheckChildObjectKeys(telemetry, "observability",
                                  "root.telemetry.observability",
                                  {"pull_interval_ms"})) {
            return false;
        }
        if (!CheckChildObjectKeys(telemetry, "dashboard",
                                  "root.telemetry.dashboard",
                                  {"enable", "refresh_interval_ms",
                                   "max_events", "use_alternate_screen"})) {
            return false;
        }
        if (!CheckChildObjectKeys(telemetry, "logging",
                                  "root.telemetry.logging",
                                  {"enable", "stream", "path",
                                   "flush_interval_ms",
                                   "console_summary",
                                   "hot_path_sample_rate",
                                   "task_trace_sample_rate"})) {
            return false;
        }
    }

    // coverage.export sub-object whitelist.
    if (!CheckChildObjectKeys(root, "coverage", "root.coverage",
                              {"kcov", "export"})) {
        return false;
    }
    if (root.contains("coverage") && root["coverage"].is_object()) {
        if (!CheckChildObjectKeys(root["coverage"], "kcov",
                                  "root.coverage.kcov",
                                  {"raw_pc", "cover_edges", "max_pcs_per_exec",
                                   "sample_rate", "output_dir",
                                   "entries",
                                   "filter_signal", "kernel_text_start", "kernel_text_end",
                                   "drain_seconds", "persist_seconds",
                                   "max_inbox_batches"})) {
            return false;
        }
        if (!CheckChildObjectKeys(root["coverage"], "export",
                                  "root.coverage.export",
                                  {"enabled", "corpus_pc_path",
                                   "corpus_signal_path", "all_signal_path",
                                   "edge_series_enabled"})) {
            return false;
        }
    }

    if (!CheckChildObjectKeys(root, "target", "root.target",
                              {"execution_mode", "coverage_mode",
                               "sanitizer_mode", "sandbox_mode",
                               // [syscall-enable-whitelist]
                               "enable_syscalls", "disable_syscalls",
                               "metric_dump_path",
                               // [v2 Epic 7 PR-4.5] worker thread pool size (1..32)
                               "thread_count",
                               // [v2 Epic 7 PR-4.6] global IntraTaskMode toggle
                               "intra_task_mode",
                               // [当前版本 kcov-pool-config / per-call-timeout-config]
                               "kcov_collector_count", "kcov_premap_count",
                               "per_call_timeout_ms",
                               // [debug instrumentation]
                               "debug_smaps", "debug_empty_fork",
                               "debug_mount_timing", "debug_topology_probe",
                               "warmup_devices"})) {
        return false;
    }
    if (!CheckChildObjectKeys(root, "persistence", "root.persistence",
                              {"corpus", "coverage",
                               "crash_repros_as_seeds"})) {
        return false;
    }
    if (root.contains("persistence") && root["persistence"].is_object()) {
        const auto& persistence = root["persistence"];
        if (!CheckChildObjectKeys(persistence, "corpus",
                                  "root.persistence.corpus",
                                  {"enable", "dir", "load_on_start"})) {
            return false;
        }
        if (!CheckChildObjectKeys(persistence, "coverage",
                                  "root.persistence.coverage",
                                  {"enable", "path", "load_on_start"})) {
            return false;
        }
    }

    if (!CheckChildObjectKeys(root, "repro", "root.repro",
                              {"enable", "dedicated_vm_count",
                               "vmlinux_path", "addr2line_binary",
                               "queue_capacity", "execute_timeout_ms"})) {
        return false;
    }

    return true;
}

std::optional<ExecutionMode> ParseExecutionMode(const std::string& value)
{
    if (value == "kernel_syscall") {
        return ExecutionMode::kKernelSyscall;
    }
    if (value == "userspace_harness") {
        return ExecutionMode::kUserspaceHarness;
    }
    if (value == "binary_dbi") {
        return ExecutionMode::kBinaryDbi;
    }
    return std::nullopt;
}

// [fixed request stream] top-level run mode -- see RunMode's doc comment
// (orchestrator_config.hpp) for why this is a separate axis from execution_mode.
std::optional<RunMode> ParseRunMode(const std::string& value)
{
    if (value == "fuzzing") {
        return RunMode::kFuzzing;
    }
    if (value == "replay") {
        return RunMode::kReplay;
    }
    return std::nullopt;
}

std::optional<CoverageMode> ParseCoverageMode(const std::string& value)
{
    if (value == "none") {
        return CoverageMode::kNone;
    }
    if (value == "kcov") {
        return CoverageMode::kKcov;
    }
    return std::nullopt;
}

std::optional<SanitizerMode> ParseSanitizerMode(const std::string& value)
{
    if (value == "none") {
        return SanitizerMode::kNone;
    }
    if (value == "kasan") {
        return SanitizerMode::kKasan;
    }
    if (value == "kcsan") {
        return SanitizerMode::kKcsan;
    }
    if (value == "ubsan") {
        return SanitizerMode::kUbsan;
    }
    return std::nullopt;
}

std::optional<SandboxMode> ParseSandboxMode(const std::string& value)
{
    if (value == "none") {
        return SandboxMode::kNone;
    }
    if (value == "setuid") {
        return SandboxMode::kSetuid;
    }
    if (value == "namespace") {
        return SandboxMode::kNamespace;
    }
    return std::nullopt;
}

std::optional<RunLimitMode> ParseRunLimitMode(const std::string& value)
{
    if (value == "both") {
        return RunLimitMode::kBoth;
    }
    if (value == "task_count" || value == "count") {
        return RunLimitMode::kTaskCount;
    }
    if (value == "runtime" || value == "time") {
        return RunLimitMode::kRuntime;
    }
    return std::nullopt;
}

const char* CoverageModeToArg(refuzz::channel::worker::WorkerCoverageMode mode)
{
    switch (mode) {
    case refuzz::channel::worker::WorkerCoverageMode::kKcov:
        return "kcov";
    case refuzz::channel::worker::WorkerCoverageMode::kNone:
    default:
        return "none";
    }
}

const char* SanitizerModeToArg(refuzz::channel::worker::WorkerSanitizerMode mode)
{
    switch (mode) {
    case refuzz::channel::worker::WorkerSanitizerMode::kKasan:
        return "kasan";
    case refuzz::channel::worker::WorkerSanitizerMode::kKcsan:
        return "kcsan";
    case refuzz::channel::worker::WorkerSanitizerMode::kUbsan:
        return "ubsan";
    case refuzz::channel::worker::WorkerSanitizerMode::kNone:
    default:
        return "none";
    }
}

const char* SandboxModeToArg(refuzz::channel::worker::WorkerSandboxMode mode)
{
    switch (mode) {
    case refuzz::channel::worker::WorkerSandboxMode::kSetuid:
        return "setuid";
    case refuzz::channel::worker::WorkerSandboxMode::kNamespace:
        return "namespace";
    case refuzz::channel::worker::WorkerSandboxMode::kNone:
    default:
        return "none";
    }
}

// [v4 new-approach — 当前版本]
// ExecutorConfig v4 极简化：idle_sleep/event_blocking/submit_wait_for_slot
static bool ParseExecutorConfig(const nlohmann::json& executor_json,
                                refuzz::channeldispatcher::ExecutorConfig* out)
{
    if (!executor_json.is_object()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "executor must be a JSON object\n";
        return false;
    }
    if (executor_json.contains("idle_sleep_us")) {
        out->idle_sleep_us = executor_json["idle_sleep_us"].get<uint64_t>();
    }
    // Legacy flat key: executor.event_blocking_timeout_us.
    if (executor_json.contains("event_blocking_timeout_us")) {
        out->event_blocking_timeout_us =
            executor_json["event_blocking_timeout_us"].get<uint64_t>();
    }
    if (executor_json.contains("submit_wait_for_slot_ms")) {
        out->submit_wait_for_slot_ms =
            executor_json["submit_wait_for_slot_ms"].get<uint64_t>();
    }

    // dispatch 节（v3 遗留）如果存在则只读 idle_sleep_us。
    if (executor_json.contains("dispatch")) {
        const auto& dj = executor_json["dispatch"];
        if (!dj.is_object()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "executor.dispatch must be a JSON object\n";
            return false;
        }
        if (dj.contains("idle_sleep_us")) {
            out->idle_sleep_us = dj["idle_sleep_us"].get<uint64_t>();
        }
    }

    // Legacy nested key from older sample configs.
    if (executor_json.contains("event_drain")) {
        const auto& ed = executor_json["event_drain"];
        if (!ed.is_object()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "executor.event_drain must be a JSON object\n";
            return false;
        }
        if (ed.contains("blocking_timeout_us")) {
            out->event_blocking_timeout_us =
                ed["blocking_timeout_us"].get<uint64_t>();
        }
    }

    if (executor_json.contains("event_forward_strategy")) {
        const auto& es = executor_json["event_forward_strategy"];
        if (!es.is_object()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "executor.event_forward_strategy must be a JSON object\n";
            return false;
        }
        if (es.contains("blocking_timeout_ms")) {
            out->event_blocking_timeout_us =
                es["blocking_timeout_ms"].get<uint64_t>() * 1000ULL;
        }
    }

    if (executor_json.contains("submit_strategy")) {
        const auto& ss = executor_json["submit_strategy"];
        if (!ss.is_object()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "executor.submit_strategy must be a JSON object\n";
            return false;
        }
        const std::string name = GetString(ss, "name", "round_robin");
        if (name != "round_robin") {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "unsupported executor.submit_strategy.name: "
                << name << " (supported: round_robin)\n";
            return false;
        }
        out->submit_strategy = name;
    }
    return true;
}

} // namespace

// [Stage 3 去山头] XiUOS UART backend 专属配置解析。
//
// XiUOS 与 kernel(qemu_ivshmem_linux)是不同 target,config schema 也不同——
// 没有 vm/transport/ivshmem/worker_start_cmd 那套。与其往 kernel 单体 parser 里
// 塞条件分支(strict-key check + worker_start_cmd 组装 + vm kernel 路径校验全部
// 是 kernel-specific,XiUOS 走不通),不如开一条独立、隔离的解析路径,复用本 TU
// 的 file-local helper(GetObject/GetString/GetU*/ParseExecutorConfig/MakeSessionLayout
// /Parse*Mode),只解析 XiUOS 真正需要的字段。
//
// 由 ParseConfigFromJson 在 channel.backend_id == "qemu_uart_xiuos" 时分派进来。
//
// schema(orchestrator-native,区别于 XiuosFuzzSession 私有 phase0 schema):
//   {
//     "profile": "xiuos",
//     "channel": {
//       "backend_id": "qemu_uart_xiuos",
//       "n_workers": 1,                       // 可选,强制归一到 1
//       "wait_ready_timeout_ms": 8000,        // 可选
//       "loop_interval_ms": 5,                // 可选
//       "xiuos": {
//         "qemu_bin": "qemu-system-riscv32",  // 可选
//         "elf_path": "/abs/xiuos.elf",       // 必填非空
//         "serial_host": "127.0.0.1",         // 可选
//         "serial_port": 32500,               // 必填非零
//         "connect_timeout_ms": 10000,        // 可选
//         "frame_timeout_ms": 10000,          // 可选
//         "heartbeat_timeout_ms": 500,        // 可选
//         "poll_slice_ms": 10,                // 可选
//         "program_timeout_ms": 15000,        // 可选: Poll 中的 wedge 预算
//         "shutdown_grace_ms": 2000           // 可选
//       }
//     },
//     "executor": {...},                      // 复用 ParseExecutorConfig
//     "fuzzer": { "exec_timeout_ms":..., "high_watermark":..., "corpus":{...} },
//     "coverage": { "kcov": {...} },
//     "persistence": { "corpus": {...}, "coverage": {...} },
//     "target": { "execution_mode":"kernel_syscall", "coverage_mode":"kcov" },
//     "work_dir":..., "state_dir":...,
//     "worker_bin_host_path": "/abs/xiuos.elf",  // 可选,orchestrator 仅做存在性
//                                                // check;XiUOS worker 编进 ELF,
//                                                // 默认回退到 channel.xiuos.elf_path
//     "phase1_run_limit_mode":..., "phase1_runtime_seconds":..., "phase1_total_tasks":...
//   }
static bool ParseXiuosConfigFromJson(const nlohmann::json& root, OrchestratorConfig& out)
{
    nlohmann::json channel_json;
    nlohmann::json xiuos_json;
    nlohmann::json executor_json;
    nlohmann::json timeouts_json;
    nlohmann::json fuzzer_json;
    nlohmann::json corpus_json;
    nlohmann::json coverage_json;
    nlohmann::json coverage_kcov_json;
    nlohmann::json target_json;
    nlohmann::json persistence_json;
    nlohmann::json corpus_persist_json;
    nlohmann::json coverage_persist_json;
    nlohmann::json logging_json;

    if (!GetObject(root, "channel", "root.channel", &channel_json) ||
        !GetObject(channel_json, "xiuos", "root.channel.xiuos", &xiuos_json) ||
        !GetObject(root, "executor", "root.executor", &executor_json) ||
        !GetObject(executor_json, "timeouts_ms", "root.executor.timeouts_ms", &timeouts_json) ||
        !GetObject(root, "fuzzer", "root.fuzzer", &fuzzer_json) ||
        !GetObject(fuzzer_json, "corpus", "root.fuzzer.corpus", &corpus_json) ||
        !GetObject(root, "coverage", "root.coverage", &coverage_json) ||
        !GetObject(coverage_json, "kcov", "root.coverage.kcov", &coverage_kcov_json) ||
        !GetObject(root, "target", "root.target", &target_json) ||
        !GetObject(root, "persistence", "root.persistence", &persistence_json) ||
        !GetObject(persistence_json, "corpus", "root.persistence.corpus", &corpus_persist_json) ||
        !GetObject(persistence_json, "coverage", "root.persistence.coverage", &coverage_persist_json) ||
        !GetObject(root, "logging", "root.logging", &logging_json)) {
        return false;
    }

    out.profile = GetString(root, "profile", "xiuos");

    // ── target 模式 ──
    const auto execution_mode =
        ParseExecutionMode(GetString(target_json, "execution_mode", "kernel_syscall"));
    const auto coverage_mode =
        ParseCoverageMode(GetString(target_json, "coverage_mode", "kcov"));
    const auto sanitizer_mode =
        ParseSanitizerMode(GetString(target_json, "sanitizer_mode", "none"));
    const auto sandbox_mode =
        ParseSandboxMode(GetString(target_json, "sandbox_mode", "none"));
    if (!execution_mode || !coverage_mode || !sanitizer_mode || !sandbox_mode) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "xiuos: invalid target mode field\n";
        return false;
    }
    out.target.execution_mode = *execution_mode;
    out.target.coverage_mode  = *coverage_mode;
    out.target.sanitizer_mode = *sanitizer_mode;
    out.target.sandbox_mode   = *sandbox_mode;

    // ── executor ──
    if (!ParseExecutorConfig(executor_json, &out.executor)) {
        return false;
    }
    out.pop_timeout  = std::chrono::milliseconds{timeouts_json.value("pop", 5U)};
    out.poll_timeout = std::chrono::microseconds{
        static_cast<uint64_t>(timeouts_json.value("poll", 1U)) * 1000ULL};

    // ── 中性 ChannelConfig(channel_common)──
    out.channel_common.channel_id = 0;  // orchestrator 构造 main channel 时补 1
    uint32_t n_workers = GetU32(channel_json, "n_workers", 1U);
    if (n_workers == 0 || n_workers > 1) {
        n_workers = 1;  // XiUOS 单 worker(assembler 也会归一)
    }
    out.channel_common.n_workers = n_workers;
    out.channel_common.wait_ready_timeout = std::chrono::milliseconds{
        GetU64(channel_json, "wait_ready_timeout_ms",
               static_cast<uint64_t>(out.channel_common.wait_ready_timeout.count()))};
    out.channel_common.loop_interval = std::chrono::milliseconds{
        GetU64(channel_json, "loop_interval_ms",
               static_cast<uint64_t>(out.channel_common.loop_interval.count()))};

    // ── XiUOS backend profile ──
    // 同一 "XiUOS QEMU 家族" 解析路径服务两个 backend:flat virt-rv32(qemu_uart_xiuos)
    // 与 app-surface sifive_u(qemu_uart_sifive_u)。后者 profile 继承 XiuosUartProfile,
    // 多 machine/mem/app_bin_path/app_load_addr 四个字段;backend_id 决定建哪种 + 是否读
    // extras。公共字段一律经 XiuosUartProfile* 基类指针解析。
    const std::string xiuos_backend_id =
        channel_json.value("backend_id", std::string{});
    const bool is_sifive = xiuos_backend_id ==
        std::string(refuzz::channel::channel_backend_id::kQemuUartSifiveU);

    std::unique_ptr<refuzz::channel::factory::XiuosUartProfile> profile;
    refuzz::channel::factory::SifiveUartXiuosProfile* sifive = nullptr;
    if (is_sifive) {
        auto p = std::make_unique<refuzz::channel::factory::SifiveUartXiuosProfile>();
        sifive  = p.get();
        profile = std::move(p);
    } else {
        profile = std::make_unique<refuzz::channel::factory::XiuosUartProfile>();
    }
    profile->qemu_bin    = GetString(xiuos_json, "qemu_bin", profile->qemu_bin);
    profile->elf_path    = GetString(xiuos_json, "elf_path", std::string{});
    profile->serial_host = GetString(xiuos_json, "serial_host", profile->serial_host);
    const uint32_t serial_port = GetU32(xiuos_json, "serial_port", 0U);
    if (profile->elf_path.empty()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "xiuos: channel.xiuos.elf_path is required and must be non-empty\n";
        return false;
    }
    if (serial_port == 0 || serial_port > 0xFFFFU) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "xiuos: channel.xiuos.serial_port must be in (0, 65535], got "
            << serial_port << "\n";
        return false;
    }
    profile->serial_port = static_cast<std::uint16_t>(serial_port);
    profile->connect_timeout = std::chrono::milliseconds{
        GetU64(xiuos_json, "connect_timeout_ms",
               static_cast<uint64_t>(profile->connect_timeout.count()))};
    profile->frame_timeout = std::chrono::milliseconds{
        GetU64(xiuos_json, "frame_timeout_ms",
               static_cast<uint64_t>(profile->frame_timeout.count()))};
    profile->max_queued_frames = static_cast<std::size_t>(
        GetU64(xiuos_json, "max_queued_frames",
               static_cast<uint64_t>(profile->max_queued_frames)));
    profile->heartbeat_timeout = std::chrono::milliseconds{
        GetU64(xiuos_json, "heartbeat_timeout_ms",
               static_cast<uint64_t>(profile->heartbeat_timeout.count()))};
    profile->poll_slice = std::chrono::milliseconds{
        GetU64(xiuos_json, "poll_slice_ms",
               static_cast<uint64_t>(profile->poll_slice.count()))};
    profile->program_timeout = std::chrono::milliseconds{
        GetU64(xiuos_json, "program_timeout_ms",
               fuzzer_json.contains("exec_timeout_ms")
                   ? static_cast<uint64_t>(fuzzer_json.value("exec_timeout_ms", 15000U))
                   : static_cast<uint64_t>(profile->program_timeout.count()))};
    profile->shutdown_grace = std::chrono::milliseconds{
        GetU64(xiuos_json, "shutdown_grace_ms",
               static_cast<uint64_t>(profile->shutdown_grace.count()))};

    // sifive_u(app-surface)专属字段 + 默认值(machine=sifive_u/mem=256M/
    // app_load_addr=0x80101000;qemu_bin 默认已由 SifiveUartXiuosProfile ctor 改 rv64)。
    if (sifive != nullptr) {
        sifive->machine       = GetString(xiuos_json, "machine", sifive->machine);
        sifive->mem           = GetString(xiuos_json, "mem", sifive->mem);
        // app_bin_path optional: empty → flat worker kernel (S1 plumbing); set →
        // separate-compile + U-mode app via `-device loader` (S2 app-surface).
        sifive->app_bin_path  = GetString(xiuos_json, "app_bin_path", std::string{});
        sifive->app_load_addr = GetString(xiuos_json, "app_load_addr", sifive->app_load_addr);
        // [app-surface 重定向 M4] uart0 console sink (wire = uart1). Default "null";
        // set "file:/path" to capture the kernel boot log for debugging/triage.
        sifive->console_endpoint = GetString(xiuos_json, "console_endpoint", sifive->console_endpoint);
    }

    const std::string xiuos_backend_const = is_sifive
        ? std::string(refuzz::channel::channel_backend_id::kQemuUartSifiveU)
        : std::string(refuzz::channel::channel_backend_id::kQemuUartXiuos);
    out.channel_common.backend_id = xiuos_backend_const;
    out.channel_backend_id        = xiuos_backend_const;
    // worker 二进制存在性 check:XiUOS worker 编进 ELF,无独立二进制。
    // orchestrator.cpp 仅做 filesystem::exists()——回退指向 ELF 让它通过。
    out.worker_bin_host_path =
        root.value("worker_bin_host_path",
                   root.value("phase0_worker_bin", profile->elf_path));
    out.vm_id = root.value("phase0_vm_id", 0U);
    out.snapshot_fuzzing = false;  // XiUOS 不支持 snapshot
    out.channel_backend = std::move(profile);

    // ── fuzzer ──
    // [request-window] 窗口 = 2 × n_workers（= syz `2·procs`）；high_watermark 配置键已废弃
    //   （仍被 strict-key 校验接受但不再读取）。xiuos 单 worker → 窗口 = 2。
    out.fuzzer.request_window_limit =
        2 * static_cast<std::size_t>(std::max<uint32_t>(1, out.channel_common.n_workers));
    out.fuzzer.corpus_max_drain = corpus_json.value("max_drain", out.fuzzer.corpus_max_drain);
    // [coverage-ownership bound] fuzzer.corpus.{capacity,minimize.*} 配置键已废弃但仍被
    // strict-key 校验接受(不破已有 config);语料边界由覆盖所有权不变量维护,不再读取。
    out.fuzzer.exec_timeout_ms = fuzzer_json.value("exec_timeout_ms", 5000U);
    out.shutdown_grace_ms = fuzzer_json.value("shutdown_grace_ms", 60000U);
    out.mutator_policy = GetString(fuzzer_json, "mutator_policy", "");
    out.fuzzer.scheduling_policy = GetString(fuzzer_json, "scheduling_policy", "");
    // [seed-value signals shadow] opt-in per-mutation JSONL (default off).
    out.fuzzer.seed_value_shadow_enabled =
        GetBool(fuzzer_json, "seed_value_shadow_enabled", false);
    out.fuzzer.seed_horizon_enabled =
        GetBool(fuzzer_json, "seed_horizon_enabled", false);
    out.fuzzer.seed_band2_map_path =
        fuzzer_json.value("seed_band2_map_path", std::string{});
    out.fuzzer.variant_handler_map_path =
        fuzzer_json.value("variant_handler_map_path", std::string{});
    out.fuzzer.belief_graph_path =
        fuzzer_json.value("belief_graph_path", std::string{});
    // [request-stream capture] Mirror of syz-manager's -request-stream: records every
    // dispatched request as JSONL so reFuzz's own workload can be converted
    // (tools/syz-stream-from-jsonl) and replayed by BOTH systems. Empty = off.
    // Ignored under run_mode=replay -- see orchestrator.cpp.
    out.fuzzer.request_stream_capture_path =
        fuzzer_json.value("request_stream_capture_path", std::string{});

    // ── coverage(xiuos_coverage signal 复用 kcov persistence 出口)──
    out.coverage_raw_pc = coverage_kcov_json.value("raw_pc", true);
    out.coverage_cover_edges = coverage_kcov_json.value("cover_edges", false);
    out.coverage_max_pcs_per_exec = coverage_kcov_json.value("max_pcs_per_exec", 0U);
    // [syz-parity convertCallInfo] kernel-address sanity filter (default off; range = syz amd64).
    out.coverage_filter_signal = coverage_kcov_json.value("filter_signal", false);
    out.coverage_kernel_text_start =
        coverage_kcov_json.value("kernel_text_start", 0xffffffff80000000ULL);
    out.coverage_kernel_text_end =
        coverage_kcov_json.value("kernel_text_end", 0xffffffffff000000ULL);
    out.coverage_sample_rate = coverage_kcov_json.value("sample_rate", 1.0);
    out.coverage_kcov_entries = kDefaultKcovEntries;
    out.coverage_output_dir = coverage_kcov_json.value("output_dir", std::string{});

    // ── persistence ──
    out.corpus_persist_enable = corpus_persist_json.value("enable", true);
    out.corpus_persist_dir = corpus_persist_json.value("dir", std::string{});
    out.corpus_load_on_start = corpus_persist_json.value("load_on_start", true);
    out.coverage_persist_enable = coverage_persist_json.value("enable", true);
    out.coverage_persist_path = coverage_persist_json.value("path", std::string{});
    out.coverage_load_on_start = coverage_persist_json.value("load_on_start", true);
    out.crash_repros_as_seeds = persistence_json.value("crash_repros_as_seeds", true);

    // ── repro 子系统(可选)──
    // 开启后 reFuzz 自带的 repro/minimizer 把 crash(worker_dead / exec_timeout /…)
    // 复现并最小化,产物落 repros_persist_dir。QEMU backend 的 dedicated repro VM 由
    // MakeXiuosProfile().derive_repro_channel_cfg 派生(2nd QEMU,serial_port+offset);
    // 物理板(ch32)derive 返回 null → 不派生 repro VM。默认 enable=false(行为同此前)。
    // ParseXiuos/ParseCh32 与 kernel path 隔离解析,需在此显式读 repro 块。
    {
        const nlohmann::json repro_json =
            (root.contains("repro") && root["repro"].is_object())
                ? root["repro"] : nlohmann::json::object();
        out.repro.enable = GetBool(repro_json, "enable", false);
        out.repro.dedicated_vm_count = GetU32(repro_json, "dedicated_vm_count", 1);
        out.repro.repro_queue_capacity =
            repro_json.value("queue_capacity", static_cast<std::size_t>(64));
        out.repro.execute_timeout = std::chrono::milliseconds{
            GetU32(repro_json, "execute_timeout_ms", 30000U)};
        out.repro.addr2line_binary = GetString(repro_json, "addr2line_binary", "addr2line");
        // Reliability policy: XiUOS findings (timeout-0 wedges, worker-deaths)
        // reproduce deterministically (reliability ~1.0), so default "full" — it
        // runs the minimize stage AND filters flaky one-offs via the 0.15 gate.
        out.repro.policy = GetString(repro_json, "policy", std::string{"full"});
        // Triage policy: XiUOS findings are mostly wedges/worker-deaths, not
        // kKernelCrash, so default "actionable" to enqueue those for repro.
        out.repro.triage_policy =
            GetString(repro_json, "triage_policy", std::string{"actionable"});
    }

    // ── run limit ──
    const auto run_limit_mode =
        ParseRunLimitMode(root.value("phase1_run_limit_mode", std::string{"both"}));
    if (!run_limit_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "xiuos: invalid phase1_run_limit_mode\n";
        return false;
    }
    out.run_limit_mode = *run_limit_mode;
    out.runtime = std::chrono::seconds{root.value("phase1_runtime_seconds", 20ULL)};
    out.total_tasks = root.value("phase1_total_tasks", 5000ULL);

    // ── logging ──
    out.logging.enable = GetBool(logging_json, "enable", out.logging.enable);
    out.logging.stream = GetBool(logging_json, "stream", out.logging.stream);
    out.logging.path = GetString(logging_json, "path", out.logging.path);
    out.logging.console_summary =
        GetBool(logging_json, "console_summary", out.logging.console_summary);

    // ── work_dir / state_dir / SessionLayout + 路径兜底(同 kernel path 尾段)──
    out.work_dir      = GetString(root, "work_dir", std::string{});
    out.state_dir     = GetString(root, "state_dir", std::string{});
    out.retention     = GetBool(root, "retention", false);
    out.retention_max = GetU32(root, "retention_max", 3U);
    if (out.state_dir.empty()) {
        const std::string base = out.work_dir.empty() ? std::string("/tmp") : out.work_dir;
        out.state_dir = base + "/state";
    }
    try {
        SessionLayoutOptions lopt;
        lopt.work_dir      = out.work_dir;
        lopt.retention     = out.retention;
        lopt.retention_max = out.retention_max;
        out.layout         = MakeSessionLayout(lopt);
    } catch (const std::exception& e) {
        refuzz::logging::HostLineBuilder("Config", "session_layout_failed")
            << "xiuos: failed to create session layout: " << e.what() << "\n";
        return false;
    }
    if (out.logging.path.empty()) {
        out.logging.path = out.layout.logs_dir + "/host_events.txt";
    }
    if (out.coverage_output_dir.empty()) {
        out.coverage_output_dir = out.state_dir + "/coverage";
    }
    if (out.corpus_persist_dir.empty()) {
        out.corpus_persist_dir = out.state_dir + "/corpus";
    }
    if (out.coverage_persist_path.empty()) {
        out.coverage_persist_path = out.state_dir + "/coverage/coverage.bin";
    }
    if (out.repros_persist_dir.empty()) {
        out.repros_persist_dir = out.state_dir + "/repros";
    }
    return true;
}

// [Phase Q2] 物理 CH32V208RBT6 板 backend 专属配置解析。
//
// 与 ParseXiuosConfigFromJson **同构**(都是 XiUOS guest;本文件刻意按 backend family
// 走独立隔离解析路径——见 ParseXiuosConfigFromJson 头注的理由)。差别只在:① channel
// 子块名 channel.ch32(vs channel.xiuos);② backend profile 字段(真串口 serial_device
// + wlink flash/reset,而非 qemu_bin + TCP serial_host/port)。其余 target/executor/
// fuzzer/coverage/persistence/run-limit/logging/work-dir 完全一致。
//
// 由 ParseConfigFromJson 在 channel.backend_id == "ch32_uart_xiuos" 时分派进来。
//
// schema(channel.ch32 块):
//   "channel": {
//     "backend_id": "ch32_uart_xiuos",
//     "n_workers": 1, "wait_ready_timeout_ms": 60000, "loop_interval_ms": 50,
//     "ch32": {
//       "serial_device": "/dev/ttyACM0",        // 必填非空
//       "baud": 115200,                          // 可选
//       "image_path": "/abs/XiZi-ch32.bin",      // 可选(flash 用)
//       "flash_command": "wlink flash {image}",  // 可选({image} 占位 → image_path)
//       "reset_command": "wlink reset",          // 可选(RebootVM 用)
//       "command_timeout_ms": 60000,             // 可选
//       "connect_timeout_ms": 10000,             // 可选
//       "frame_timeout_ms": 10000,               // 可选
//       "heartbeat_timeout_ms": 500,             // 可选
//       "poll_slice_ms": 10,                     // 可选
//       "program_timeout_ms": 15000,             // 可选: Poll 中的 wedge 预算
//       "shutdown_grace_ms": 2000                // 可选
//     }
//   }
static bool ParseCh32ConfigFromJson(const nlohmann::json& root, OrchestratorConfig& out)
{
    nlohmann::json channel_json;
    nlohmann::json ch32_json;
    nlohmann::json executor_json;
    nlohmann::json timeouts_json;
    nlohmann::json fuzzer_json;
    nlohmann::json corpus_json;
    nlohmann::json coverage_json;
    nlohmann::json coverage_kcov_json;
    nlohmann::json target_json;
    nlohmann::json persistence_json;
    nlohmann::json corpus_persist_json;
    nlohmann::json coverage_persist_json;
    nlohmann::json logging_json;

    if (!GetObject(root, "channel", "root.channel", &channel_json) ||
        !GetObject(channel_json, "ch32", "root.channel.ch32", &ch32_json) ||
        !GetObject(root, "executor", "root.executor", &executor_json) ||
        !GetObject(executor_json, "timeouts_ms", "root.executor.timeouts_ms", &timeouts_json) ||
        !GetObject(root, "fuzzer", "root.fuzzer", &fuzzer_json) ||
        !GetObject(fuzzer_json, "corpus", "root.fuzzer.corpus", &corpus_json) ||
        !GetObject(root, "coverage", "root.coverage", &coverage_json) ||
        !GetObject(coverage_json, "kcov", "root.coverage.kcov", &coverage_kcov_json) ||
        !GetObject(root, "target", "root.target", &target_json) ||
        !GetObject(root, "persistence", "root.persistence", &persistence_json) ||
        !GetObject(persistence_json, "corpus", "root.persistence.corpus", &corpus_persist_json) ||
        !GetObject(persistence_json, "coverage", "root.persistence.coverage", &coverage_persist_json) ||
        !GetObject(root, "logging", "root.logging", &logging_json)) {
        return false;
    }

    out.profile = GetString(root, "profile", "xiuos");

    // ── target 模式 ──
    const auto execution_mode =
        ParseExecutionMode(GetString(target_json, "execution_mode", "kernel_syscall"));
    const auto coverage_mode =
        ParseCoverageMode(GetString(target_json, "coverage_mode", "kcov"));
    const auto sanitizer_mode =
        ParseSanitizerMode(GetString(target_json, "sanitizer_mode", "none"));
    const auto sandbox_mode =
        ParseSandboxMode(GetString(target_json, "sandbox_mode", "none"));
    if (!execution_mode || !coverage_mode || !sanitizer_mode || !sandbox_mode) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "ch32: invalid target mode field\n";
        return false;
    }
    out.target.execution_mode = *execution_mode;
    out.target.coverage_mode  = *coverage_mode;
    out.target.sanitizer_mode = *sanitizer_mode;
    out.target.sandbox_mode   = *sandbox_mode;

    // ── executor ──
    if (!ParseExecutorConfig(executor_json, &out.executor)) {
        return false;
    }
    out.pop_timeout  = std::chrono::milliseconds{timeouts_json.value("pop", 5U)};
    out.poll_timeout = std::chrono::microseconds{
        static_cast<uint64_t>(timeouts_json.value("poll", 1U)) * 1000ULL};

    // ── 中性 ChannelConfig ──
    out.channel_common.channel_id = 0;  // orchestrator 构造 main channel 时补 1
    uint32_t n_workers = GetU32(channel_json, "n_workers", 1U);
    if (n_workers == 0 || n_workers > 1) {
        n_workers = 1;  // XiUOS 单 worker
    }
    out.channel_common.n_workers = n_workers;
    out.channel_common.wait_ready_timeout = std::chrono::milliseconds{
        GetU64(channel_json, "wait_ready_timeout_ms",
               static_cast<uint64_t>(out.channel_common.wait_ready_timeout.count()))};
    out.channel_common.loop_interval = std::chrono::milliseconds{
        GetU64(channel_json, "loop_interval_ms",
               static_cast<uint64_t>(out.channel_common.loop_interval.count()))};

    // ── CH32 backend profile ──
    auto profile = std::make_unique<refuzz::channel::factory::Ch32UartProfile>();
    profile->serial_device = GetString(ch32_json, "serial_device", std::string{});
    if (profile->serial_device.empty()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "ch32: channel.ch32.serial_device is required and must be non-empty\n";
        return false;
    }
    profile->baud          = GetU32(ch32_json, "baud", profile->baud);
    profile->image_path    = GetString(ch32_json, "image_path", std::string{});
    profile->flash_command = GetString(ch32_json, "flash_command", std::string{});
    profile->reset_command = GetString(ch32_json, "reset_command", std::string{});
    profile->command_timeout = std::chrono::milliseconds{
        GetU64(ch32_json, "command_timeout_ms",
               static_cast<uint64_t>(profile->command_timeout.count()))};
    profile->connect_timeout = std::chrono::milliseconds{
        GetU64(ch32_json, "connect_timeout_ms",
               static_cast<uint64_t>(profile->connect_timeout.count()))};
    profile->frame_timeout = std::chrono::milliseconds{
        GetU64(ch32_json, "frame_timeout_ms",
               static_cast<uint64_t>(profile->frame_timeout.count()))};
    profile->max_queued_frames = static_cast<std::size_t>(
        GetU64(ch32_json, "max_queued_frames",
               static_cast<uint64_t>(profile->max_queued_frames)));
    profile->heartbeat_timeout = std::chrono::milliseconds{
        GetU64(ch32_json, "heartbeat_timeout_ms",
               static_cast<uint64_t>(profile->heartbeat_timeout.count()))};
    profile->poll_slice = std::chrono::milliseconds{
        GetU64(ch32_json, "poll_slice_ms",
               static_cast<uint64_t>(profile->poll_slice.count()))};
    profile->program_timeout = std::chrono::milliseconds{
        GetU64(ch32_json, "program_timeout_ms",
               fuzzer_json.contains("exec_timeout_ms")
                   ? static_cast<uint64_t>(fuzzer_json.value("exec_timeout_ms", 15000U))
                   : static_cast<uint64_t>(profile->program_timeout.count()))};
    profile->shutdown_grace = std::chrono::milliseconds{
        GetU64(ch32_json, "shutdown_grace_ms",
               static_cast<uint64_t>(profile->shutdown_grace.count()))};

    out.channel_common.backend_id =
        std::string(refuzz::channel::channel_backend_id::kCh32UartXiuos);
    out.channel_backend_id =
        std::string(refuzz::channel::channel_backend_id::kCh32UartXiuos);
    // worker 二进制存在性 check:XiUOS worker 编进 flash 镜像,无独立二进制 →
    // 回退指向 image_path(orchestrator.cpp 仅做 filesystem::exists())。
    out.worker_bin_host_path =
        root.value("worker_bin_host_path",
                   root.value("phase0_worker_bin", profile->image_path));
    out.vm_id = root.value("phase0_vm_id", 0U);
    out.snapshot_fuzzing = false;  // XiUOS 不支持 snapshot
    out.channel_backend = std::move(profile);

    // ── fuzzer ──
    // [request-window] 窗口 = 2 × n_workers（= syz `2·procs`）；high_watermark 配置键已废弃
    //   （仍被 strict-key 校验接受但不再读取）。xiuos 单 worker → 窗口 = 2。
    out.fuzzer.request_window_limit =
        2 * static_cast<std::size_t>(std::max<uint32_t>(1, out.channel_common.n_workers));
    out.fuzzer.corpus_max_drain = corpus_json.value("max_drain", out.fuzzer.corpus_max_drain);
    // [coverage-ownership bound] fuzzer.corpus.{capacity,minimize.*} 配置键已废弃但仍被
    // strict-key 校验接受(不破已有 config);语料边界由覆盖所有权不变量维护,不再读取。
    out.fuzzer.exec_timeout_ms = fuzzer_json.value("exec_timeout_ms", 5000U);
    out.shutdown_grace_ms = fuzzer_json.value("shutdown_grace_ms", 60000U);
    out.mutator_policy = GetString(fuzzer_json, "mutator_policy", "");
    out.fuzzer.scheduling_policy = GetString(fuzzer_json, "scheduling_policy", "");
    // [seed-value signals shadow] opt-in per-mutation JSONL (default off).
    out.fuzzer.seed_value_shadow_enabled =
        GetBool(fuzzer_json, "seed_value_shadow_enabled", false);
    out.fuzzer.seed_horizon_enabled =
        GetBool(fuzzer_json, "seed_horizon_enabled", false);
    out.fuzzer.seed_band2_map_path =
        fuzzer_json.value("seed_band2_map_path", std::string{});
    out.fuzzer.variant_handler_map_path =
        fuzzer_json.value("variant_handler_map_path", std::string{});
    out.fuzzer.belief_graph_path =
        fuzzer_json.value("belief_graph_path", std::string{});
    // [request-stream capture] Mirror of syz-manager's -request-stream: records every
    // dispatched request as JSONL so reFuzz's own workload can be converted
    // (tools/syz-stream-from-jsonl) and replayed by BOTH systems. Empty = off.
    // Ignored under run_mode=replay -- see orchestrator.cpp.
    out.fuzzer.request_stream_capture_path =
        fuzzer_json.value("request_stream_capture_path", std::string{});

    // ── coverage ──
    out.coverage_raw_pc = coverage_kcov_json.value("raw_pc", true);
    out.coverage_cover_edges = coverage_kcov_json.value("cover_edges", false);
    out.coverage_max_pcs_per_exec = coverage_kcov_json.value("max_pcs_per_exec", 0U);
    // [syz-parity convertCallInfo] kernel-address sanity filter (default off; range = syz amd64).
    out.coverage_filter_signal = coverage_kcov_json.value("filter_signal", false);
    out.coverage_kernel_text_start =
        coverage_kcov_json.value("kernel_text_start", 0xffffffff80000000ULL);
    out.coverage_kernel_text_end =
        coverage_kcov_json.value("kernel_text_end", 0xffffffffff000000ULL);
    out.coverage_sample_rate = coverage_kcov_json.value("sample_rate", 1.0);
    out.coverage_kcov_entries = kDefaultKcovEntries;
    out.coverage_output_dir = coverage_kcov_json.value("output_dir", std::string{});

    // ── persistence ──
    out.corpus_persist_enable = corpus_persist_json.value("enable", true);
    out.corpus_persist_dir = corpus_persist_json.value("dir", std::string{});
    out.corpus_load_on_start = corpus_persist_json.value("load_on_start", true);
    out.coverage_persist_enable = coverage_persist_json.value("enable", true);
    out.coverage_persist_path = coverage_persist_json.value("path", std::string{});
    out.coverage_load_on_start = coverage_persist_json.value("load_on_start", true);
    out.crash_repros_as_seeds = persistence_json.value("crash_repros_as_seeds", true);

    // ── repro 子系统(可选)──
    // 开启后 reFuzz 自带的 repro/minimizer 把 crash(worker_dead / exec_timeout /…)
    // 复现并最小化,产物落 repros_persist_dir。QEMU backend 的 dedicated repro VM 由
    // MakeXiuosProfile().derive_repro_channel_cfg 派生(2nd QEMU,serial_port+offset);
    // 物理板(ch32)derive 返回 null → 不派生 repro VM。默认 enable=false(行为同此前)。
    // ParseXiuos/ParseCh32 与 kernel path 隔离解析,需在此显式读 repro 块。
    {
        const nlohmann::json repro_json =
            (root.contains("repro") && root["repro"].is_object())
                ? root["repro"] : nlohmann::json::object();
        out.repro.enable = GetBool(repro_json, "enable", false);
        out.repro.dedicated_vm_count = GetU32(repro_json, "dedicated_vm_count", 1);
        out.repro.repro_queue_capacity =
            repro_json.value("queue_capacity", static_cast<std::size_t>(64));
        out.repro.execute_timeout = std::chrono::milliseconds{
            GetU32(repro_json, "execute_timeout_ms", 30000U)};
        out.repro.addr2line_binary = GetString(repro_json, "addr2line_binary", "addr2line");
        // Reliability policy: XiUOS findings (timeout-0 wedges, worker-deaths)
        // reproduce deterministically (reliability ~1.0), so default "full" — it
        // runs the minimize stage AND filters flaky one-offs via the 0.15 gate.
        out.repro.policy = GetString(repro_json, "policy", std::string{"full"});
        // Triage policy: XiUOS findings are mostly wedges/worker-deaths, not
        // kKernelCrash, so default "actionable" to enqueue those for repro.
        out.repro.triage_policy =
            GetString(repro_json, "triage_policy", std::string{"actionable"});
    }

    // ── run limit ──
    const auto run_limit_mode =
        ParseRunLimitMode(root.value("phase1_run_limit_mode", std::string{"both"}));
    if (!run_limit_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "ch32: invalid phase1_run_limit_mode\n";
        return false;
    }
    out.run_limit_mode = *run_limit_mode;
    out.runtime = std::chrono::seconds{root.value("phase1_runtime_seconds", 20ULL)};
    out.total_tasks = root.value("phase1_total_tasks", 5000ULL);

    // ── logging ──
    out.logging.enable = GetBool(logging_json, "enable", out.logging.enable);
    out.logging.stream = GetBool(logging_json, "stream", out.logging.stream);
    out.logging.path = GetString(logging_json, "path", out.logging.path);
    out.logging.console_summary =
        GetBool(logging_json, "console_summary", out.logging.console_summary);

    // ── work_dir / state_dir / SessionLayout + 路径兜底 ──
    out.work_dir      = GetString(root, "work_dir", std::string{});
    out.state_dir     = GetString(root, "state_dir", std::string{});
    out.retention     = GetBool(root, "retention", false);
    out.retention_max = GetU32(root, "retention_max", 3U);
    if (out.state_dir.empty()) {
        const std::string base = out.work_dir.empty() ? std::string("/tmp") : out.work_dir;
        out.state_dir = base + "/state";
    }
    try {
        SessionLayoutOptions lopt;
        lopt.work_dir      = out.work_dir;
        lopt.retention     = out.retention;
        lopt.retention_max = out.retention_max;
        out.layout         = MakeSessionLayout(lopt);
    } catch (const std::exception& e) {
        refuzz::logging::HostLineBuilder("Config", "session_layout_failed")
            << "ch32: failed to create session layout: " << e.what() << "\n";
        return false;
    }
    if (out.logging.path.empty()) {
        out.logging.path = out.layout.logs_dir + "/host_events.txt";
    }
    if (out.coverage_output_dir.empty()) {
        out.coverage_output_dir = out.state_dir + "/coverage";
    }
    if (out.corpus_persist_dir.empty()) {
        out.corpus_persist_dir = out.state_dir + "/corpus";
    }
    if (out.coverage_persist_path.empty()) {
        out.coverage_persist_path = out.state_dir + "/coverage/coverage.bin";
    }
    if (out.repros_persist_dir.empty()) {
        out.repros_persist_dir = out.state_dir + "/repros";
    }
    return true;
}

bool ParseConfig(const std::string& path, OrchestratorConfig& out)
{
    std::ifstream in(path);
    if (!in) {
        refuzz::logging::HostLineBuilder("Config", "open_failed") << "failed to open config: " << path << "\n";
        return false;
    }

    nlohmann::json root;
    try {
        in >> root;
    } catch (const std::exception& e) {
        refuzz::logging::HostLineBuilder("Config", "parse_failed") << "failed to parse config: " << e.what() << "\n";
        return false;
    }

    return ParseConfigFromJson(root, out);
}

bool ParseConfigFromJson(const nlohmann::json& root, OrchestratorConfig& out)
{
    if (!root.is_object()) {
        refuzz::logging::HostLineBuilder("Config", "invalid") << "root must be a JSON object\n";
        return false;
    }
    // [Stage 3 去山头] backend 分派:channel.backend_id == "qemu_uart_xiuos" 时走
    // XiUOS 独立解析路径(不同 target schema,跳过 kernel strict-key check +
    // qemu/ivshmem/worker_start_cmd 组装)。其余沿用下方 kernel(qemu_ivshmem_linux)
    // 单体路径。
    if (root.contains("channel") && root["channel"].is_object() &&
        (root["channel"].value("backend_id", std::string{}) ==
             std::string(refuzz::channel::channel_backend_id::kQemuUartXiuos) ||
         root["channel"].value("backend_id", std::string{}) ==
             std::string(refuzz::channel::channel_backend_id::kQemuUartSifiveU))) {
        // 同 XiUOS QEMU 家族:flat virt-rv32 与 app-surface sifive_u 共用解析路径
        // (ParseXiuosConfigFromJson 内按 backend_id 选 profile 类型 + extras)。
        return ParseXiuosConfigFromJson(root, out);
    }
    // [Phase Q2] 物理 CH32 板:同 XiUOS family,独立隔离解析(channel.ch32 块)。
    if (root.contains("channel") && root["channel"].is_object() &&
        root["channel"].value("backend_id", std::string{}) ==
            std::string(refuzz::channel::channel_backend_id::kCh32UartXiuos)) {
        return ParseCh32ConfigFromJson(root, out);
    }
    if (!CheckKnownConfigKeys(root)) {
        return false;
    }

    // 解析各 JSON 子节点
    // [v2 new-approach — 当前版本]
    // 按代码组件层次重新布局：channel（vm/transport/health）/ executor / fuzzer / telemetry
    nlohmann::json channel_json;
    nlohmann::json vm_json;
    nlohmann::json transport_json;
    nlohmann::json health_json;
    nlohmann::json qemu_json;
    nlohmann::json executor_json;
    nlohmann::json timeouts_json;
    nlohmann::json fuzzer_json;
    nlohmann::json corpus_json;
    nlohmann::json worker_log_json;
    nlohmann::json worker_perf_json;
    nlohmann::json telemetry_json;
    nlohmann::json monitor_json;
    nlohmann::json observability_json;
    nlohmann::json dashboard_json;
    nlohmann::json logging_json;
    nlohmann::json coverage_json;
    nlohmann::json coverage_kcov_json;
    // [v2 PR-K-E1] coverage.export.enabled — disk export opt-in;
    // optional sub-object, absence implies enabled=false.
    nlohmann::json coverage_export_json;
    nlohmann::json target_json;
    nlohmann::json persistence_json;
    nlohmann::json corpus_persist_json;
    nlohmann::json coverage_persist_json;
    nlohmann::json repro_json;
    // [fixed request stream] see RunMode/ReplayConfig.
    nlohmann::json replay_json;

    if (!GetObject(root, "channel", "root.channel", &channel_json) ||
        !GetObject(channel_json, "vm", "root.channel.vm", &vm_json) ||
        !GetObject(channel_json, "transport", "root.channel.transport", &transport_json) ||
        !GetObject(channel_json, "health", "root.channel.health", &health_json) ||
        !GetObject(vm_json, "qemu", "root.channel.vm.qemu", &qemu_json) ||
        !GetObject(root, "executor", "root.executor", &executor_json) ||
        !GetObject(executor_json, "timeouts_ms", "root.executor.timeouts_ms", &timeouts_json) ||
        !GetObject(root, "fuzzer", "root.fuzzer", &fuzzer_json) ||
        !GetObject(fuzzer_json, "corpus", "root.fuzzer.corpus", &corpus_json) ||
        !GetObject(fuzzer_json, "worker_log", "root.fuzzer.worker_log", &worker_log_json) ||
        !GetObject(fuzzer_json, "worker_perf", "root.fuzzer.worker_perf", &worker_perf_json) ||
        !GetObject(root, "telemetry", "root.telemetry", &telemetry_json) ||
        !GetObject(telemetry_json, "policy_monitor", "root.telemetry.policy_monitor", &monitor_json) ||
        !GetObject(telemetry_json, "observability", "root.telemetry.observability", &observability_json) ||
        !GetObject(telemetry_json, "dashboard", "root.telemetry.dashboard", &dashboard_json) ||
        !GetObject(telemetry_json, "logging", "root.telemetry.logging", &logging_json) ||
        !GetObject(root, "coverage", "root.coverage", &coverage_json) ||
        !GetObject(coverage_json, "kcov", "root.coverage.kcov", &coverage_kcov_json) ||
        !GetObject(root, "target", "root.target", &target_json) ||
        !GetObject(root, "persistence", "root.persistence", &persistence_json) ||
        !GetObject(persistence_json, "corpus", "root.persistence.corpus", &corpus_persist_json) ||
        !GetObject(persistence_json, "coverage", "root.persistence.coverage", &coverage_persist_json) ||
        !GetObject(root, "repro", "root.repro", &repro_json) ||
        !GetObject(root, "replay", "root.replay", &replay_json)) {
        return false;
    }

    // [fixed request stream] "fuzzing" (default) leaves every existing config's
    // behavior unchanged -- no stream validation, normal ExploreJob supply.
    const std::string run_mode_value = GetString(root, "run_mode", "fuzzing");
    const auto run_mode = ParseRunMode(run_mode_value);
    if (!run_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "invalid run_mode (supported: fuzzing, replay): " << run_mode_value << "\n";
        return false;
    }
    out.run_mode = *run_mode;
    out.replay.stream_path = GetString(replay_json, "stream_path", "");
    // [fixed request stream] hold-before-teardown; empty marker path = disabled.
    out.replay.drained_marker_path = GetString(replay_json, "drained_marker_path", "");
    out.replay.release_path        = GetString(replay_json, "release_path", "");
    out.replay.hold_timeout_s      = GetU32(replay_json, "hold_timeout_s", 900);

    if (!ParseExecutorConfig(executor_json, &out.executor)) {
        return false;
    }

    // profile 选择（默认 "kernel"）
    out.profile = GetString(root, "profile", "kernel");
    const std::string execution_mode_value = GetString(target_json, "execution_mode", "kernel_syscall");
    const std::string coverage_mode_value = GetString(target_json, "coverage_mode", "kcov");
    const std::string sanitizer_mode_value = GetString(target_json, "sanitizer_mode", "none");
    const std::string sandbox_mode_value = GetString(target_json, "sandbox_mode", "none");
    const auto execution_mode = ParseExecutionMode(execution_mode_value);
    const auto coverage_mode = ParseCoverageMode(coverage_mode_value);
    const auto sanitizer_mode = ParseSanitizerMode(sanitizer_mode_value);
    const auto sandbox_mode = ParseSandboxMode(sandbox_mode_value);
    if (!execution_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid") << "invalid target.execution_mode: " << execution_mode_value << "\n";
        return false;
    }
    if (!coverage_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid") << "invalid target.coverage_mode (supported: none, kcov): " << coverage_mode_value << "\n";
        return false;
    }
    if (!sanitizer_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid") << "invalid target.sanitizer_mode: " << sanitizer_mode_value << "\n";
        return false;
    }
    if (!sandbox_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "invalid target.sandbox_mode (supported: none, setuid, namespace): "
            << sandbox_mode_value << "\n";
        return false;
    }
    out.target.execution_mode = *execution_mode;
    out.target.coverage_mode = *coverage_mode;
    out.target.sanitizer_mode = *sanitizer_mode;
    out.target.sandbox_mode = *sandbox_mode;
    // [syscall-enable-whitelist] syzkaller-style syscall selection globs.
    // Validation (unknown glob / empty result) happens against the target
    // at mutator engine build time (program::syz::compute_enabled_calls),
    // where the syscall table is available.
    out.target.enable_syscalls  = GetStringArray(target_json, "enable_syscalls");
    out.target.disable_syscalls = GetStringArray(target_json, "disable_syscalls");

    // [debug instrumentation] off by default;真要诊断 perf 时手动开。
    out.target.debug_smaps = GetBool(target_json, "debug_smaps", false);
    out.target.debug_empty_fork = GetBool(target_json, "debug_empty_fork", false);
    out.target.debug_mount_timing =
        GetBool(target_json, "debug_mount_timing", false);
    out.target.debug_topology_probe =
        GetBool(target_json, "debug_topology_probe", false);
    out.target.warmup_devices =
        GetBool(target_json, "warmup_devices", false);

    // [FUP-METRIC-VM 2026-05-10] target.metric_dump_path string, default empty。
    // 非空时 worker_start_cmd 追加 --metric-dump-path <path>;worker 在
    // engine.Run 退出后据此 dump pseudo dispatch metric JSON。Path 支持
    // {worker_id} 占位符;不带占位符时多 worker 会互相覆盖(单 worker 调试
    // 场景可接受)。空字符串 = 禁用 dump。
    out.target.metric_dump_path = GetString(target_json, "metric_dump_path", std::string{});

    // [v2 Epic 7 PR-4.5] target.thread_count uint, default 1, range [1, 32]。
    //   == 1 → worker_start_cmd 不追加 --thread-count (向后兼容,行为等价
    //          Epic 7 PR-1~PR-3);
    //   >  1 → worker_start_cmd 追加 --thread-count N,worker 端 driver
    //          lazy 构造 KernelThreadPool 接收 threaded task;
    //   > 32 → fail-closed (worker profile 内部 clamp,但 host 端拒收避免
    //          运维误认为 "我配了 64 实际跑 32")。
    out.target.thread_count = 1;
    if (target_json.contains("thread_count")) {
        const auto& thread_count_json = target_json["thread_count"];
        if (thread_count_json.is_number_unsigned()) {
            const auto value = thread_count_json.get<uint64_t>();
            if (value > std::numeric_limits<uint32_t>::max()) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "target.thread_count must fit in uint32, got "
                    << value << "\n";
                return false;
            }
            out.target.thread_count = static_cast<uint32_t>(value);
        } else if (thread_count_json.is_number_integer()) {
            const auto value = thread_count_json.get<int64_t>();
            if (value < 0) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "target.thread_count must be non-negative, got "
                    << value << "\n";
                return false;
            }
            out.target.thread_count = static_cast<uint32_t>(value);
        } else {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.thread_count must be an integer\n";
            return false;
        }
    }
    if (out.target.thread_count < 1 || out.target.thread_count > 32) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "target.thread_count must be in [1, 32], got "
            << out.target.thread_count << "\n";
        return false;
    }

    // [当前版本 kcov-pool-config] target.kcov_collector_count /
    // target.kcov_premap_count 可选,默认 8 / 3 对齐 syzkaller upstream 的
    // delayed-KCOV mmap 参数。thread_count 是 logical worker 上限;KCOV
    // collector_count 是已打开 coverage fd 上限,允许小于 thread_count。
    // worker 调度层会避免把 coverage-required call 静默跑到无 KCOV fd 的
    // thread 上,而不是在 config parse 阶段强制二者相等。
    // 0 视作未设(保持默认)。
    out.target.kcov_collector_count = 8;
    out.target.kcov_premap_count    = 3;
    if (target_json.contains("kcov_collector_count")) {
        const auto& v = target_json["kcov_collector_count"];
        if (!v.is_number_unsigned() && !v.is_number_integer()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.kcov_collector_count must be a non-negative integer\n";
            return false;
        }
        const int64_t value = v.is_number_unsigned()
            ? static_cast<int64_t>(v.get<uint64_t>())
            : v.get<int64_t>();
        if (value < 0 || value > 64) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.kcov_collector_count must be in [0, 64], got "
                << value << "\n";
            return false;
        }
        if (value != 0) {
            out.target.kcov_collector_count = static_cast<uint32_t>(value);
        }
    }
    if (target_json.contains("kcov_premap_count")) {
        const auto& v = target_json["kcov_premap_count"];
        if (!v.is_number_unsigned() && !v.is_number_integer()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.kcov_premap_count must be a non-negative integer\n";
            return false;
        }
        const int64_t value = v.is_number_unsigned()
            ? static_cast<int64_t>(v.get<uint64_t>())
            : v.get<int64_t>();
        if (value < 0 || value > 64) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.kcov_premap_count must be in [0, 64], got "
                << value << "\n";
            return false;
        }
        out.target.kcov_premap_count = static_cast<uint32_t>(value);
    }
    if (out.target.kcov_premap_count > out.target.kcov_collector_count) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "target.kcov_premap_count (" << out.target.kcov_premap_count
            << ") must be <= target.kcov_collector_count ("
            << out.target.kcov_collector_count << ")\n";
        return false;
    }

    // [当前版本 per-call-timeout-config] target.per_call_timeout_ms 可选。
    // 默认 500ms 对齐 syzkaller upstream QEMU fuzz 路径 (targets.go Syscall=50ms
    // × slowdown=10);0 视作未设。范围 [10, 60000]。
    // 注意:5000ms 是 stdio fallback (executor.cc:1647),不是实际 fuzz 路径的值,
    // 之前的 hardcode 5000ms 拖 tail latency 10×。
    out.target.per_call_timeout_ms = 500;
    if (target_json.contains("per_call_timeout_ms")) {
        const auto& v = target_json["per_call_timeout_ms"];
        if (!v.is_number_unsigned() && !v.is_number_integer()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.per_call_timeout_ms must be a non-negative integer\n";
            return false;
        }
        const int64_t value = v.is_number_unsigned()
            ? static_cast<int64_t>(v.get<uint64_t>())
            : v.get<int64_t>();
        if (value < 0 || value > 60000) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.per_call_timeout_ms must be in [0, 60000], got "
                << value << "\n";
            return false;
        }
        if (value != 0) {
            if (value < 10) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "target.per_call_timeout_ms must be 0 (default) or >= 10, got "
                    << value << "\n";
                return false;
            }
            out.target.per_call_timeout_ms = static_cast<uint32_t>(value);
        }
    }

    // [v2 Epic 7 PR-4.6] target.intra_task_mode = "serial" (default) | "threaded"。
    //   serial   : 历史行为,所有 task 走 worker driver serial fast path。
    //   threaded : channeldispatcher 在 BuildRequest 给每个 task 的 wire
    //              flag OR 上 TASK_FLAG_INTRA_THREADED,worker 走
    //              KernelThreadPool 调度。要求 target.thread_count > 1,否
    //              则 fail-closed (单 collector + threaded 路径 worker 永远
    //              拒收返 exec_error,等价配错)。
    {
        if (target_json.contains("intra_task_mode") &&
            !target_json["intra_task_mode"].is_string()) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.intra_task_mode must be a string\n";
            return false;
        }
        const std::string mode_value =
            GetString(target_json, "intra_task_mode", std::string{"serial"});
        if (mode_value == "serial") {
            out.target.intra_task_mode = TargetRuntimeConfig::IntraTaskMode::kSerial;
        } else if (mode_value == "threaded") {
            out.target.intra_task_mode = TargetRuntimeConfig::IntraTaskMode::kThreaded;
        } else {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.intra_task_mode must be \"serial\" or \"threaded\", got \""
                << mode_value << "\"\n";
            return false;
        }
        if (out.target.intra_task_mode == TargetRuntimeConfig::IntraTaskMode::kThreaded &&
            out.target.thread_count == 1) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.intra_task_mode=threaded requires target.thread_count > 1; "
                << "got thread_count=1 (worker driver would reject every threaded "
                << "task as exec_error since KernelThreadPool is not constructed)\n";
            return false;
        }
        // [coverage-off arm] threaded + coverage_mode=none 现已支持:profile 在
        // coverage off 时装配 NullKcovProvider/NullKcovDrainSink(worker/coverage/
        // null_kcov.hpp),threaded 执行算法本身不依赖 KCOV(per-call lifecycle
        // 全部 null-guarded)。原 "threaded ⇒ kcov" ban 已移除;driver 仍 fail-
        // closed 要求 provider/drain 非空,由 Null Object 满足。
        // syzkaller delayed-KCOV keeps 32 logical executor threads but opens
        // only kCoverOptimizedCount(8) KCOV fds. A coverage-required call that
        // would need an unopened coverage slot fails in the executor. reFuzz
        // mirrors that split now: parse accepts collector_count < thread_count,
        // and the worker scheduler enforces the no-uncovered-execution rule.
        // [v2 Epic 7 PR-4.6] plumb target.intra_task_mode → ExecutorConfig。
        // ParseExecutorConfig 在 target 解析之前调用 (line 659),只读 executor.*
        // 节;intra_task_mode 是 target.* 节字段,所以这里 post-process 覆写。
        out.executor.default_intra_threaded =
            (out.target.intra_task_mode == TargetRuntimeConfig::IntraTaskMode::kThreaded);
    }


    const auto worker_coverage_mode =
        out.target.coverage_mode == CoverageMode::kKcov
            ? refuzz::channel::worker::WorkerCoverageMode::kKcov
            : refuzz::channel::worker::WorkerCoverageMode::kNone;
    refuzz::channel::worker::WorkerSanitizerMode worker_sanitizer_mode =
        refuzz::channel::worker::WorkerSanitizerMode::kNone;
    switch (out.target.sanitizer_mode) {
    case SanitizerMode::kKasan:
        worker_sanitizer_mode = refuzz::channel::worker::WorkerSanitizerMode::kKasan;
        break;
    case SanitizerMode::kKcsan:
        worker_sanitizer_mode = refuzz::channel::worker::WorkerSanitizerMode::kKcsan;
        break;
    case SanitizerMode::kUbsan:
        worker_sanitizer_mode = refuzz::channel::worker::WorkerSanitizerMode::kUbsan;
        break;
    case SanitizerMode::kNone:
    default:
        worker_sanitizer_mode = refuzz::channel::worker::WorkerSanitizerMode::kNone;
        break;
    }

    refuzz::channel::worker::WorkerSandboxMode worker_sandbox_mode =
        refuzz::channel::worker::WorkerSandboxMode::kNone;
    switch (out.target.sandbox_mode) {
    case SandboxMode::kSetuid:
        worker_sandbox_mode = refuzz::channel::worker::WorkerSandboxMode::kSetuid;
        break;
    case SandboxMode::kNamespace:
        worker_sandbox_mode = refuzz::channel::worker::WorkerSandboxMode::kNamespace;
        break;
    case SandboxMode::kNone:
    default:
        worker_sandbox_mode = refuzz::channel::worker::WorkerSandboxMode::kNone;
        break;
    }

    const std::string vm_arch = GetString(vm_json, "arch", "amd64");
    const std::string vm_image = GetString(vm_json, "image");
    const std::string vm_kernel = GetString(vm_json, "kernel");
    const std::string vm_ssh_key = GetString(vm_json, "ssh_key");
    const std::string vm_ssh_user = GetString(vm_json, "ssh_user", "root");

    //workdir 由顶层 work_dir +SessionLayout 派生，Assembler 在装配期填 runtime.instance.workdir。
    if (vm_json.contains("workdir")) {
        refuzz::logging::HostLineBuilder("Config", "deprecated")
            << "channel.vm.workdir has been removed in Phase F.9; "
               "use top-level \"work_dir\" (optional; defaults to /tmp) instead.\n";
        return false;
    }

    if (vm_image.empty() || vm_ssh_key.empty()) {
        refuzz::logging::HostLineBuilder("Config", "invalid") << "missing required vm.image or vm.ssh_key in config\n";
        return false;
    }

    // ivshmem_mode / doorbell 字段来自 channel.transport（transport 层决策）
    const uint32_t n_workers = GetU32(transport_json, "n_workers", 1);
    out.fuzz_channel_count = 1;
    if (channel_json.contains("fuzz_channel_count")) {
        const auto& count_node = channel_json["fuzz_channel_count"];
        uint64_t count_raw = 0;
        if (count_node.is_number_unsigned()) {
            count_raw = count_node.get<uint64_t>();
        } else if (count_node.is_number_integer()) {
            const auto signed_value = count_node.get<int64_t>();
            if (signed_value < 0) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "channel.fuzz_channel_count must be a positive integer\n";
                return false;
            }
            count_raw = static_cast<uint64_t>(signed_value);
        } else {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "channel.fuzz_channel_count must be a positive integer\n";
            return false;
        }
        constexpr uint64_t kMaxFuzzChannelCount = 256;
        if (count_raw < 1 || count_raw > kMaxFuzzChannelCount) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "channel.fuzz_channel_count=" << count_raw
                << " out of range [1, " << kMaxFuzzChannelCount << "]\n";
            return false;
        }
        out.fuzz_channel_count = static_cast<uint32_t>(count_raw);
    }
    const std::string ivshmem_mode_str = GetString(transport_json, "ivshmem_mode", "plain");
    const bool use_doorbell = (ivshmem_mode_str != "plain");
    const std::string doorbell_socket_path =
        GetString(transport_json, "doorbell_socket_path", "/tmp/refuzz_ivshmem_phase1.sock");

    // QEMU 配置：注入来自其他节的参数（qemu 节只含 QEMU 进程参数）
    auto qemu_cfg = qemu_json;
    qemu_cfg["kernel"] = vm_kernel;
    qemu_cfg["ivshmem_path"] = GetString(transport_json, "ivshmem_path", "/tmp/refuzz_ivshmem_phase1");
    qemu_cfg["ivshmem_mode"] = ivshmem_mode_str;
    if (use_doorbell) {
        qemu_cfg["ivshmem_socket"] = doorbell_socket_path;
        qemu_cfg["ivshmem_vectors"] = GetU32(transport_json, "ivshmem_vectors", n_workers);
    }

    //两段式 channel 配置：
    //   - out.channel_common  : 中性 ChannelConfig
    //   - backend_profile     : QemuIvshmemLinuxProfile (kernel 主路径硬编码)
    //   - out.channel_backend_id / channel_backend 最后 move 进去
    // 未来如果支持 backend dispatch，这里从 channel.backend_id 分派创建不同 Profile。
    auto backend_profile = std::make_unique<refuzz::channel::factory::QemuIvshmemLinuxProfile>();

    //中性 ChannelConfig 字段（channel_common）：
    //   - channel_id: 默认 0（orchestrator 构造 main channel 时自动补 1）
    //   - n_workers : 必须从 yaml 同步进来；Assembler 里 channel_cfg.n_workers 与
    //                 backend_profile.infra.n_workers 一致性校验依赖此字段
    //   - *_ms 字段统一使用毫秒单位，对应 ChannelConfig 的 milliseconds 类型。
    //     旧 channel.transport.wait_ready_timeout_us 仍兼容读取，但新字段优先。
    out.channel_common.channel_id = 0;
    out.channel_common.n_workers  = n_workers;
    if (transport_json.contains("wait_ready_timeout_us")) {
        out.channel_common.wait_ready_timeout =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::microseconds{
                    GetU64(transport_json, "wait_ready_timeout_us",
                           static_cast<uint64_t>(
                               std::chrono::duration_cast<std::chrono::microseconds>(
                                   out.channel_common.wait_ready_timeout).count()))});
    }
    out.channel_common.wait_ready_timeout = std::chrono::milliseconds{
        GetU64(channel_json, "wait_ready_timeout_ms",
               static_cast<uint64_t>(out.channel_common.wait_ready_timeout.count()))};
    out.channel_common.loop_interval = std::chrono::milliseconds{
        GetU64(channel_json, "loop_interval_ms",
               static_cast<uint64_t>(out.channel_common.loop_interval.count()))};
    out.channel_common.health_check_interval = std::chrono::milliseconds{
        GetU64(channel_json, "health_check_interval_ms",
               static_cast<uint64_t>(out.channel_common.health_check_interval.count()))};
    out.channel_common.pre_reboot_drain = std::chrono::milliseconds{
        GetU64(channel_json, "pre_reboot_drain_ms",
               static_cast<uint64_t>(out.channel_common.pre_reboot_drain.count()))};

    // [v2 PR-E abnormal_console_snapshot_lines — 当前版本]
    // abnormal 路径(worker 上报 abnormal / channel recovery 触发)从共享
    // ConsoleRingBuffer 取的最近行数,落到 AbnormalCompletion.console_snapshot,
    // 下游 BuildContextOp 据此填 ctx.console_log,落盘 report0/[console] block +
    // serial_log_tail.txt。默认 80 与 HeartbeatSensor.console_snapshot_lines 对齐。
    // 0 = 不抓(退化到旧行为,落盘无 console 上下文)。
    out.channel_common.abnormal_console_snapshot_lines = static_cast<uint32_t>(
        GetU64(channel_json, "abnormal_console_snapshot_lines",
               static_cast<uint64_t>(out.channel_common.abnormal_console_snapshot_lines)));

    // [crash-execution-history-ring] Layer-2 crash history depth (per-worker ring
    // of recently completed programs; harvested on a confirmed kernel crash to
    // capture async/deferred triggers). Default 16; 0 disables (Layer-1 only).
    out.channel_common.crash_history_depth = static_cast<std::size_t>(
        GetU64(channel_json, "crash_history_depth",
               static_cast<uint64_t>(out.channel_common.crash_history_depth)));

    //input_queue_capacity 分层决策(放在 channel_common 起作用,
    //           repro 派生时会继承这份值,一次改动覆盖 main+repro):
    //     显式 JSON  "channel.input_queue_capacity": N  →  直接用 N
    //     未显式    → n_workers × kInputQueuePerWorker (3x, 经验值)
    //     n_workers=0 的保底 → ChannelConfig::input_queue_capacity 默认 64
    //   为什么 3x:>= 2x 能让 SubmitLoop 在 worker 全忙时仍有缓冲不空转,
    //   >= 4x 只是堆内存并让 channel 侧常驻饱和、制造 busy 噪音。
    constexpr std::size_t kInputQueuePerWorker = 3;
    constexpr std::size_t kInputQueueCapMax =
        static_cast<std::size_t>(std::numeric_limits<uint32_t>::max());
    if (channel_json.contains("input_queue_capacity")) {
        const auto& cap_node = channel_json["input_queue_capacity"];
        // [v2 accept-signed-nonneg — 当前版本]
        // 与 GetU64 的兼容策略对齐:接受 number_integer 且 >= 0 的 signed
        // 字面量,避免 in-memory JSON 构造时 int 字面量被误拒。
        std::size_t cap_raw = 0;
        if (cap_node.is_number_unsigned()) {
            cap_raw = cap_node.get<std::size_t>();
        } else if (cap_node.is_number_integer()) {
            const auto signed_value = cap_node.get<int64_t>();
            if (signed_value < 0) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "channel.input_queue_capacity must be a non-negative integer\n";
                return false;
            }
            cap_raw = static_cast<std::size_t>(signed_value);
        } else {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "channel.input_queue_capacity must be a non-negative integer\n";
            return false;
        }
        if (cap_raw < 1 || cap_raw > kInputQueueCapMax) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "channel.input_queue_capacity=" << cap_raw
                << " out of range [1, " << kInputQueueCapMax << "]\n";
            return false;
        }
        out.channel_common.input_queue_capacity = cap_raw;
    } else if (n_workers > 0) {
        const auto derived = static_cast<std::size_t>(n_workers) * kInputQueuePerWorker;
        // 派生路径同样过边界 check (n_workers × 3 极少越界,但 fail-closed)
        if (derived < 1 || derived > kInputQueueCapMax) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "derived input_queue_capacity=" << derived
                << " (n_workers=" << n_workers << ") out of range [1, "
                << kInputQueueCapMax << "]\n";
            return false;
        }
        out.channel_common.input_queue_capacity = derived;
    }

    // 后端字段：infra
    backend_profile->infra.shm_path  = qemu_cfg["ivshmem_path"].get<std::string>();
    backend_profile->infra.n_workers = n_workers;

    // 后端字段：runtime
    backend_profile->runtime.instance.arch           = vm_arch;
    backend_profile->runtime.instance.kernel         = vm_kernel;
    backend_profile->runtime.instance.disk_image     = vm_image;
    backend_profile->runtime.instance.ssh_key        = vm_ssh_key;
    backend_profile->runtime.instance.ssh_user       = vm_ssh_user;
    //runtime.instance.workdir 由 Assembler 从ChannelBuildContext::vm_workdir 填入；yaml 解析期保持空串。
    backend_profile->runtime.instance.workdir        = "";
    backend_profile->runtime.instance.index          = 0;
    backend_profile->runtime.instance.ivshmem_path   = backend_profile->infra.shm_path;
    backend_profile->runtime.instance.ivshmem_mode   = ivshmem_mode_str;
    backend_profile->runtime.instance.ivshmem_socket = use_doorbell ? doorbell_socket_path : "";
    backend_profile->runtime.instance.ivshmem_vectors = static_cast<int>(
        std::max<uint32_t>(1, qemu_cfg.value("ivshmem_vectors", n_workers)));
    if (qemu_cfg.contains("qemu") && qemu_cfg["qemu"].is_string()) {
        backend_profile->runtime.instance.qemu_bin = qemu_cfg["qemu"].get<std::string>();
    }
    if (qemu_cfg.contains("cpu") && qemu_cfg["cpu"].is_number_integer()) {
        backend_profile->runtime.instance.cpu = qemu_cfg["cpu"].get<int>();
    }
    if (qemu_cfg.contains("mem") && qemu_cfg["mem"].is_number_integer()) {
        backend_profile->runtime.instance.mem_mb = qemu_cfg["mem"].get<int>();
    }
    if (qemu_cfg.contains("cmdline") && qemu_cfg["cmdline"].is_string()) {
        backend_profile->runtime.instance.kernel_cmdline = qemu_cfg["cmdline"].get<std::string>();
    }
    if (qemu_cfg.contains("snapshot") && qemu_cfg["snapshot"].is_boolean()) {
        backend_profile->runtime.instance.snapshot = qemu_cfg["snapshot"].get<bool>();
    }
    // snapshot_fuzzing=true：syzkaller-style 每 testcase savevm/loadvm 还原模式。
    // 需要可写 qcow2 disk + 去掉 `-snapshot`（见 qemu_args.cpp）。与上面 `snapshot`
    // （磁盘 CoW overlay）是不同语义，二者不应同时为 true。
    if (qemu_cfg.contains("snapshot_fuzzing") && qemu_cfg["snapshot_fuzzing"].is_boolean()) {
        backend_profile->runtime.instance.snapshot_fuzzing =
            qemu_cfg["snapshot_fuzzing"].get<bool>();
    }
    if (qemu_cfg.contains("serial_log_path") && qemu_cfg["serial_log_path"].is_string()) {
        backend_profile->runtime.instance.serial_log_path = qemu_cfg["serial_log_path"].get<std::string>();
    }

    // 后端字段：transport
    backend_profile->transport.n_workers = n_workers;
    backend_profile->transport.use_doorbell = use_doorbell;
    backend_profile->transport.doorbell_socket_path = doorbell_socket_path;
    backend_profile->transport.wait_ready_poll_us = std::chrono::microseconds{
        static_cast<uint64_t>(GetU32(transport_json, "wait_ready_poll_us", 1000U))};
    backend_profile->transport.poll_sleep_us = std::chrono::microseconds{
        static_cast<uint64_t>(GetU32(transport_json, "poll_sleep_us", 100U))};

    // 后端字段：worker
    backend_profile->worker.n_workers = n_workers;

    // 后端字段：health_monitor（来自 channel.health）
    // [v2 new-approach — 当前版本]
    // 替换旧分散 checker 字段为组件级聚合配置（health_monitor / recovery_config）
    const bool enable_health_monitor = GetBool(health_json, "enable", true);
    // [调优 Stage 1] sample_interval_ms 默认 500 → 250:heartbeat 采样本身很轻量(读
    //   ctrl region 的 uint64_t counter),每 250ms 全扫一遍压力可忽略;
    //   配合 workers_per_round=0 (all),单 worker dead 检测延迟从 ≤3s 降到 ~750ms,
    //   显著缩短 recovery 触发链路 → executor backoff 窗口缩短 → exec_s 上升。
    backend_profile->health_monitor.heartbeat.poll_interval = std::chrono::milliseconds{
        GetU32(health_json, "sample_interval_ms", 250U)};
    // [心跳重定义 → 阈值必须跟着重算] counter 已从"RT 线程自增"换成"执行状态机进度令牌"
    //   (见 control_plane.hpp WorkerHeartbeatSample)。两者的**静止特性完全相反**:
    //     旧心跳:独立 RT 线程每 1s 自增,**程序执行期间照样 tick** → "4s 不动 = 真死"成立,
    //             地板取 exec_timeout + 2×poll 就够。
    //     新令牌:由执行路径顺手写,**程序执行期间纹丝不动**(start_ts_us 写完就静止到
    //             completion)→ "4s 不动"是完全正常的:一个程序本来就要跑 5s。
    //   所以旧的 4000 / 旧地板在新语义下会把每个正常执行的 worker 判死,必须同批改。
    //
    //   新的合法静止期上界(全部由 host 侧配置决定,**不依赖 guest 的死活** —— 这正是本
    //   判据能成立的根据):
    //     kExecuting ≤ daemon_watchdog_ms = 3×exec_timeout             = 15s
    //     kStopping  ≤ stop grace+kill+runner+reap = 0+2000+1000+2000  =  5s
    //     kStarting  ≤ domain_startup_timeout_ms                       = 60s  ← 最大
    //   即一次完整的 daemon 自救最长 15+5+60 = 80s 内可以没有任何令牌变化。
    //
    //   默认 300s 的两条依据:
    //     (1) 对 80s 那个最坏合法静止期留 ~4× 余量;
    //     (2) 对齐内核自报窗口 —— hung task 要 140-280s 才打印(syzkaller
    //         targets.go:863-871 正是由此反推出 NoOutput=300s)。判死早于它 = 我们抢在
    //         内核开口前动手,拿不到带栈的报告。让 ConsoleSensor 先说话。
    //   与 Detector A 的 vm_dead_timeout(300s)同值:同一个判据,per-worker 与聚合两种读法。
    std::chrono::milliseconds heartbeat_timeout = std::chrono::milliseconds{
        GetU32(health_json, "heartbeat_timeout_ms", 300'000U)};
    backend_profile->health_monitor.heartbeat.miss_threshold = 1;
    // workers_per_round:0 = 每轮扫全部(默认);>0 = round-robin 分批(大集群降压用)。
    // 历史默认 1(round-robin)放大了 fuzz 场景下的检测延迟:n_workers=3 时要 3 轮才
    // 能采样到同一个 worker 的第 2 个样本,miss_threshold=11 时最坏 3×11×poll ≈ 33×poll。
    // 改 all 后:一轮采到所有 worker,最坏延迟 = miss_threshold × poll_interval。
    backend_profile->health_monitor.heartbeat.workers_per_round =
        GetU32(health_json, "workers_per_round", 0U);
    backend_profile->health_monitor.heartbeat.capture_step_events = enable_health_monitor;
    backend_profile->health_monitor.serial_watcher.capture_step_events = enable_health_monitor;

    // 队列超时
    out.pop_timeout = std::chrono::milliseconds{timeouts_json.value("pop", 5U)};
    out.poll_timeout = std::chrono::microseconds{static_cast<uint64_t>(timeouts_json.value("poll", 1U)) * 1000ULL};

    // fuzzer 配置
    // [request-window] 解析时把 2 × transport.n_workers（= syz `2·procs`，pkg/rpcserver/runner.go:178
    //   `len(requests) − len(executing) < 2*procs`）**一次性赋值**给 request_window_limit 常量
    //   ——替换,非运行时推导。high_watermark 配置键已废弃（仍被 strict-key 校验接受但不再读取）。
    out.fuzzer.request_window_limit =
        2 * static_cast<std::size_t>(std::max<uint32_t>(1, out.channel_common.n_workers));
    out.fuzzer.corpus_max_drain = corpus_json.value("max_drain", 32);
    // [coverage-ownership bound] capacity/minimize 配置键已废弃但仍被 strict-key 校验
    // 接受;语料边界由覆盖所有权不变量维护,不再读取。
    // [program-timeout parity] exec_timeout_ms 默认 5000(回退自短暂的 2000)。
    //   exec_timeout_ms 是整体 program timeout(= syz Timeouts.Program base,
    //   targets.go:860 = 5s),它必须 ≥ 最大单 call 的 per-call timeout,否则
    //   attr 重的 call 会被 host 背板(request.timeout_ms)提前截断:mount 的
    //   per-call wait = per_call_timeout_ms(500) + kLinuxAmd64CallTimeoutMs
    //   attr(4000) = 4500ms,2000 的整体超时会在 mount 跑完前砍掉 child。
    //   per-call timeout 不能替代 program timeout(正交两层),所以这里取 5000
    //   覆盖最大 per-call attr,对齐 syz program_timeout base。
    out.fuzzer.exec_timeout_ms = fuzzer_json.value("exec_timeout_ms", 5000U);
    // [心跳重定义 → 地板重算] 旧地板 = exec_timeout + 2×poll,前提是"心跳在执行期间照样
    //   tick,所以只要熬过一个程序即可"。新令牌在执行期间不动,地板必须覆盖 daemon **一次
    //   完整自救**期间的静止期,否则会把正在正确履职的 daemon 判死:
    //     3×exec_timeout  daemon watchdog 判超时          (domain_supervisor.cpp:266-267)
    //     + stop 预算     StopDomain 的 grace+kill+runner+reap
    //                     (watchdog 路径 graceful=false → 0+2000+1000+2000,
    //                      domain_supervisor.hpp:41-44)
    //     + startup 预算  那一次有界 replacement boot
    //                     (topology::kDefaultDomainStartupTimeoutMs)
    //   这两个常量属 worker 侧 profile,不跨层 include(host config parser 不该依赖 guest
    //   worker 头);worker 侧调整了它们必须同步这里。随 exec_timeout 缩放,写死会在
    //   slowdown 环境下失效。
    constexpr uint64_t kDomainStopBudgetMs    =  5'000;  // 0 + 2000 + 1000 + 2000
    constexpr uint64_t kDomainStartupBudgetMs = 60'000;  // kDefaultDomainStartupTimeoutMs
    const auto min_heartbeat_timeout = std::chrono::milliseconds{
        static_cast<uint64_t>(out.fuzzer.exec_timeout_ms) * 3ULL
        + kDomainStopBudgetMs + kDomainStartupBudgetMs};
    if (heartbeat_timeout < min_heartbeat_timeout) {
        // 不静默抬:旧语义下写的 1500/4000 在新语义下会被抬 20-50 倍,配置文件上却看不出
        // 来。抬了就说一声,否则调参的人会拿着"配置写的 1500"去解释一个 80s 的现象。
        refuzz::logging::HostLineBuilder("Config", "heartbeat_timeout_clamped")
            << "channel.health.heartbeat_timeout_ms=" << heartbeat_timeout.count()
            << " is below the floor " << min_heartbeat_timeout.count()
            << "ms (3*exec_timeout + domain stop + domain startup budget); using the floor."
            << " The heartbeat counter is an execution-state progress token, not a liveness"
            << " tick — it legitimately stands still for a full daemon self-recovery.\n";
        heartbeat_timeout = min_heartbeat_timeout;
    }
    const uint64_t sample_ms = std::max<uint64_t>(
        1, static_cast<uint64_t>(backend_profile->health_monitor.heartbeat.poll_interval.count()));
    const uint64_t timeout_ms = std::max<uint64_t>(
        sample_ms, static_cast<uint64_t>(heartbeat_timeout.count()));
    // 向上取整,否则 sample_ms 较大时整数截断会把上面那条地板悄悄截漏:
    //   sample=60000 / timeout=80000 → 截断得 1 → 实际只有 60s < 地板 80s → 误判正在
    //   自救的 daemon。ceil 后得 2 → 120s ≥ 地板,方向永远偏保守(宁可晚判,不可早判)。
    const uint32_t base_miss_threshold = static_cast<uint32_t>(
        std::max<uint64_t>(1, (timeout_ms + sample_ms - 1) / sample_ms));
    // heartbeat_timeout_ms 硬性映射：miss_threshold = heartbeat_timeout_ms / poll_interval
    //   取消 pressure_factor 动态放大:n_workers=10 / vCPU=2 时 factor=3 会把
    //   配置里的 heartbeat_timeout_ms=4000 静默变成 12s 检测延迟,实测 phase5
    //   smoke 会出现一次 ~12.46s 的单点 stall(9/10 worker 同时失联但 fault 要
    //   等 miss_threshold×poll_interval 才上报),占总耗时 ~70%。
    //   改为:miss_threshold = heartbeat_timeout_ms / poll_interval,严格等于
    //   用户配置意图。仍保留 heartbeat_miss_threshold 显式覆盖路径(优先级最高)。
    const uint32_t explicit_miss_threshold =
        GetU32(health_json, "heartbeat_miss_threshold", 0U);
    backend_profile->health_monitor.heartbeat.miss_threshold =
        explicit_miss_threshold > 0U ? explicit_miss_threshold
                                      : base_miss_threshold;

    // [检测器 A / 级联断路] 阈值全部从 channel.health 读，留默认 = 当前设计起步值，
    //   测试期按 characterization run 实测调（vm_dead_timeout 是最关键、最该实测的一个）。
    backend_profile->health_monitor.vm_liveness.vm_dead_timeout = std::chrono::milliseconds{
        GetU32(health_json, "vm_dead_timeout_ms", 30000U)};
    backend_profile->recovery_config.mechanism.recovery_window_base_ms =
        GetU32(health_json, "recovery_window_base_ms", 90000U);
    backend_profile->recovery_config.mechanism.recovery_window_cap_ms =
        GetU32(health_json, "recovery_window_cap_ms", 600000U);
    backend_profile->recovery_config.mechanism.cascade_window_ms =
        GetU32(health_json, "cascade_window_ms", 120000U);
    backend_profile->recovery_config.policy.escalation.cascade_reboot_budget =
        GetU32(health_json, "cascade_reboot_budget", 2U);

    out.shutdown_grace_ms = fuzzer_json.value("shutdown_grace_ms", 60000U);

    // policy engine 配置
    out.policy_engine.min_dwell = std::chrono::seconds{monitor_json.value("min_dwell_seconds", 300)};
    out.policy_engine.window_size = monitor_json.value("window_size", 10);
    out.policy_engine.stall_threshold = monitor_json.value("stall_threshold", 0.01);
    out.policy_engine.required_stall_windows = monitor_json.value("required_windows", 3);
    out.policy_engine.degraded_channel_ratio = monitor_json.value("degraded_channel_ratio", 0.5);

    // observability 配置
    out.observability.pull_interval = std::chrono::milliseconds{
        observability_json.value("pull_interval_ms", 1000U)};

    // dashboard 配置
    out.dashboard.enable = dashboard_json.value("enable", true);
    out.dashboard.refresh_interval = std::chrono::milliseconds{
        dashboard_json.value("refresh_interval_ms", 500U)};
    out.dashboard.max_events = dashboard_json.value("max_events", static_cast<size_t>(6));
    out.dashboard.use_alternate_screen = dashboard_json.value("use_alternate_screen", true);

    // [Phase F.9] logging.path 默认值改为 <session_root>/logs/host_events.txt，
    //             在 session layout 落盘后（本函数末尾）才能算出；这里先留 "" 标记，
    //             由 layout 填充。用户若显式指定 yaml logging.path，则沿用。
    out.logging.enable = GetBool(logging_json, "enable", true);
    out.logging.stream = GetBool(logging_json, "stream", false);
    out.logging.path = GetString(logging_json, "path", std::string{});
    out.logging.flush_interval = std::chrono::milliseconds{
        GetU32(logging_json, "flush_interval_ms", 250U)};
    out.logging.console_summary = GetBool(logging_json, "console_summary", true);
    out.logging.hot_path_sample_rate = GetU32(logging_json, "hot_path_sample_rate", 0U);
    out.logging.task_trace_sample_rate = GetU32(logging_json, "task_trace_sample_rate", 0U);

    // coverage 配置
    out.coverage_raw_pc = coverage_kcov_json.value("raw_pc", true);
    out.coverage_cover_edges = coverage_kcov_json.value("cover_edges", false);
    out.coverage_max_pcs_per_exec = coverage_kcov_json.value("max_pcs_per_exec", 0U);
    // [syz-parity convertCallInfo] kernel-address sanity filter (default off; range = syz amd64).
    out.coverage_filter_signal = coverage_kcov_json.value("filter_signal", false);
    out.coverage_kernel_text_start =
        coverage_kcov_json.value("kernel_text_start", 0xffffffff80000000ULL);
    out.coverage_kernel_text_end =
        coverage_kcov_json.value("kernel_text_end", 0xffffffffff000000ULL);
    out.coverage_sample_rate = coverage_kcov_json.value("sample_rate", 1.0);
    out.coverage_kcov_entries = kDefaultKcovEntries;
    if (coverage_kcov_json.contains("entries")) {
        const auto& entries_json = coverage_kcov_json["entries"];
        uint64_t entries = 0;
        if (entries_json.is_number_unsigned()) {
            entries = entries_json.get<uint64_t>();
        } else if (entries_json.is_number_integer()) {
            const auto signed_entries = entries_json.get<int64_t>();
            if (signed_entries < 0) {
                refuzz::logging::HostLineBuilder("Config", "invalid")
                    << "coverage.kcov.entries must be non-negative, got "
                    << signed_entries << "\n";
                return false;
            }
            entries = static_cast<uint64_t>(signed_entries);
        } else {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "coverage.kcov.entries must be an integer\n";
            return false;
        }
        if (entries < kMinKcovEntries || entries > kMaxKcovEntries) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "coverage.kcov.entries must be in ["
                << kMinKcovEntries << ", " << kMaxKcovEntries
                << "], got " << entries << "\n";
            return false;
        }
        out.coverage_kcov_entries = static_cast<uint32_t>(entries);
    }
    // [Phase G] 默认留空 → ParseConfig 末尾用 state_dir + "/coverage" 填充。
    //           用户若显式 yaml coverage.kcov.output_dir 则沿用。
    out.coverage_output_dir = coverage_kcov_json.value("output_dir", std::string{});

    // [v2 PR-K-E1] coverage.export.enabled (optional, default false).
    // Sub-object is optional — absence keeps disk export off.
    if (coverage_json.contains("export") && coverage_json["export"].is_object()) {
        coverage_export_json = coverage_json["export"];
        out.coverage_export_enabled = coverage_export_json.value("enabled", false);
        out.coverage_export_corpus_pc_path =
            coverage_export_json.value("corpus_pc_path", std::string{});
        out.coverage_export_corpus_signal_path =
            coverage_export_json.value("corpus_signal_path", std::string{});
        out.coverage_export_all_signal_path =
            coverage_export_json.value("all_signal_path", std::string{});
        // [edge-over-time] coverage.export.edge_series_enabled (optional,
        // default true — 默认开启 edge dump). Independent gate: on → corpus_edge
        // time-series is recorded into coverage_edge_series.log; set false to
        // opt out (not recorded, file not created).
        out.coverage_export_edge_series_enabled =
            coverage_export_json.value("edge_series_enabled", true);
    }

    // persistence 配置
    out.corpus_persist_enable = corpus_persist_json.value("enable", true);
    out.corpus_persist_dir = corpus_persist_json.value("dir", std::string{});
    out.corpus_load_on_start = corpus_persist_json.value("load_on_start", true);
    out.coverage_persist_enable = coverage_persist_json.value("enable", true);
    out.coverage_persist_path = coverage_persist_json.value("path", std::string{});
    out.coverage_load_on_start = coverage_persist_json.value("load_on_start", out.coverage_load_on_start);
    out.crash_repros_as_seeds = persistence_json.value("crash_repros_as_seeds", true);

    // repro 子系统配置
    // [v4 Policy 化 — 当前版本]
    // runner.* 字段已迁移到 IReproPolicy（FullReproPolicy / FastTriageReproPolicy 等）
    // 此处只保留基础设施配置
    out.repro.enable = GetBool(repro_json, "enable", false);
    out.repro.dedicated_vm_count = GetU32(repro_json, "dedicated_vm_count", 1);
    out.repro.vmlinux_path = GetString(repro_json, "vmlinux_path");
    out.repro.addr2line_binary = GetString(repro_json, "addr2line_binary", "addr2line");
    out.repro.repro_queue_capacity = repro_json.value("queue_capacity", static_cast<size_t>(64));
    out.repro.execute_timeout = std::chrono::milliseconds{
        GetU32(repro_json, "execute_timeout_ms", 30000U)};

    // 运行参数
    out.worker_bin_host_path = root.value("phase0_worker_bin", out.worker_bin_host_path);
    backend_profile->worker.worker_binary_host_path = out.worker_bin_host_path;
    out.vm_id = root.value("phase0_vm_id", 0U);
    // worker 诊断日志开关:从 fuzzer.worker_log.enable 读取。开启后 VM 内 worker
    // 把 [Worker] child[...]: exec ... 行写到 /dev/ttyS0,qemu serial.log 直接可见,
    // 用于性能调优/真实 per-task elapsed 分析。默认 false,生产别开(serial 带宽)。
    out.worker_log_enabled = GetBool(worker_log_json, "enable", false);
    out.worker_perf_enabled = GetBool(worker_perf_json, "enable", false);
    out.worker_perf_sample_rate =
        GetU32(worker_perf_json, "sample_rate", out.worker_perf_sample_rate);
    if (out.worker_perf_sample_rate == 0) {
        out.worker_perf_sample_rate = 1;
    }
    out.worker_perf_report_every =
        GetU32(worker_perf_json, "report_every", out.worker_perf_report_every);
    if (out.worker_perf_report_every == 0) {
        out.worker_perf_report_every = 256;
    }
    std::string worker_cmd = backend_profile->worker.worker_remote_path;
    worker_cmd += " --vm-id " + std::to_string(out.vm_id);
    worker_cmd += " --peer-id 1";
    worker_cmd += " --poll-ms 1";
    worker_cmd += " --exec-timeout-ms " + std::to_string(out.fuzzer.exec_timeout_ms);
    worker_cmd += " --coverage-mode " + std::string(CoverageModeToArg(worker_coverage_mode));
    worker_cmd += " --sanitizer-mode " + std::string(SanitizerModeToArg(worker_sanitizer_mode));
    worker_cmd += " --sandbox " + std::string(SandboxModeToArg(worker_sandbox_mode));
    if (out.worker_log_enabled) {
        worker_cmd += " --enable-worker-log";
    }
    if (out.worker_perf_enabled) {
        worker_cmd += " --worker-perf";
        worker_cmd += " --worker-perf-sample " +
                      std::to_string(out.worker_perf_sample_rate);
        worker_cmd += " --worker-perf-report-every " +
                      std::to_string(out.worker_perf_report_every);
    }
    // [Brick 4a] snapshot worker mode: when the backend is snapshot-fuzzing
    // (qemu_ivshmem_snapshot_linux), launch the worker with --snapshot so it runs
    // the single-process in-place spin-wait loop (RunSnapshotEngine) instead of
    // the continuous daemon+loop_child+fork topology. Host drives per-program
    // loadvm. See docs/plans/snapshot-brick4a-worker.md.
    if (backend_profile->runtime.instance.snapshot_fuzzing) {
        worker_cmd += " --snapshot";
    }
    if (out.target.debug_smaps) {
        worker_cmd += " --debug-smaps";
    }
    if (out.target.debug_empty_fork) {
        worker_cmd += " --debug-empty-fork";
    }
    if (out.target.debug_mount_timing) {
        worker_cmd += " --debug-mount-timing";
    }
    if (out.target.debug_topology_probe) {
        worker_cmd += " --debug-topology-probe";
    }
    if (out.target.warmup_devices) {
        worker_cmd += " --warmup-devices";
    }
    // [v2 Epic 7 PR-4.5] target.thread_count > 1 时把 --thread-count N 注入
    // worker_start_cmd。== 1 不追加,既有 sample config 不需要改。
    if (out.target.thread_count > 1) {
        worker_cmd += " --thread-count " + std::to_string(out.target.thread_count);
    }
    if (out.coverage_kcov_entries != kDefaultKcovEntries) {
        worker_cmd += " --kcov-entries " +
                      std::to_string(out.coverage_kcov_entries);
    }
    // [当前版本 kcov-pool-config] 仅 threaded mode 且非默认时注入。默认值
    // (8/3) 在 worker 端 KernelSyzArgs / KcovSink 同源,不注入也是同样行为。
    if (out.target.thread_count > 1) {
        if (out.target.kcov_collector_count != 8) {
            worker_cmd += " --kcov-collector-count " +
                          std::to_string(out.target.kcov_collector_count);
        }
        if (out.target.kcov_premap_count != 3) {
            worker_cmd += " --kcov-premap-count " +
                          std::to_string(out.target.kcov_premap_count);
        }
    }
    // [当前版本 per-call-timeout-config] threaded mode 非默认时注入;serial
    // path 不读 per_call_timeout_ms,所以也只在 thread_count>1 时注入。
    // 默认 500 = QEMU fuzz 路径基准 (targets.go 50ms × slowdown 10)。
    if (out.target.thread_count > 1 && out.target.per_call_timeout_ms != 500) {
        worker_cmd += " --per-call-timeout-ms " +
                      std::to_string(out.target.per_call_timeout_ms);
    }
    // [FUP-METRIC-VM 2026-05-10] target.metric_dump_path 非空时把
    // --metric-dump-path <path> 注入 worker_start_cmd。Path 内的 {worker_id}
    // 占位符由 worker 端 ResolveMetricDumpPath 替换,保证多 worker 不 race。
    // 路径里若含空格会破坏 cmd 解析,这里做 fail-closed 检查(操作员不该用
    // 含空格路径;若需要,日后扩 shell-quote 逻辑)。
    if (!out.target.metric_dump_path.empty()) {
        if (out.target.metric_dump_path.find(' ') != std::string::npos) {
            refuzz::logging::HostLineBuilder("Config", "invalid")
                << "target.metric_dump_path contains whitespace which would "
                << "break worker_start_cmd shell parsing: '"
                << out.target.metric_dump_path << "'\n";
            return false;
        }
        worker_cmd += " --metric-dump-path " + out.target.metric_dump_path;
    }
    backend_profile->worker.worker_start_cmd = std::move(worker_cmd);

    const std::string run_limit_mode_value =
        root.value("phase1_run_limit_mode", std::string{"both"});
    const auto run_limit_mode = ParseRunLimitMode(run_limit_mode_value);
    if (!run_limit_mode.has_value()) {
        refuzz::logging::HostLineBuilder("Config", "invalid")
            << "invalid phase1_run_limit_mode (supported: both, task_count, runtime): "
            << run_limit_mode_value << "\n";
        return false;
    }
    out.run_limit_mode = *run_limit_mode;
    out.runtime = std::chrono::seconds{root.value("phase1_runtime_seconds", 20ULL)};
    out.total_tasks = root.value("phase1_total_tasks", 5000ULL);
    out.mutator_policy = GetString(fuzzer_json, "mutator_policy", "");
    out.fuzzer.scheduling_policy = GetString(fuzzer_json, "scheduling_policy", "");
    // [seed-value signals shadow] opt-in per-mutation JSONL (default off).
    out.fuzzer.seed_value_shadow_enabled =
        GetBool(fuzzer_json, "seed_value_shadow_enabled", false);
    out.fuzzer.seed_horizon_enabled =
        GetBool(fuzzer_json, "seed_horizon_enabled", false);
    out.fuzzer.seed_band2_map_path =
        fuzzer_json.value("seed_band2_map_path", std::string{});
    out.fuzzer.variant_handler_map_path =
        fuzzer_json.value("variant_handler_map_path", std::string{});
    out.fuzzer.belief_graph_path =
        fuzzer_json.value("belief_graph_path", std::string{});
    // [request-stream capture] Mirror of syz-manager's -request-stream: records every
    // dispatched request as JSONL so reFuzz's own workload can be converted
    // (tools/syz-stream-from-jsonl) and replayed by BOTH systems. Empty = off.
    // Ignored under run_mode=replay -- see orchestrator.cpp.
    out.fuzzer.request_stream_capture_path =
        fuzzer_json.value("request_stream_capture_path", std::string{});
    // [reFuzz reward] reward 任务时间成本 t(秒,= guest exec 窗,triage-immune)的 outlier 截顶。
    // task-MAB 无 on/off config —— 默认模式,chain 有 gen+mut 即生效(FuzzerLoop::mab_active_)。
    out.fuzzer.mab_time_cap_s = fuzzer_json.value("mab_time_cap_s", 2.0);

    //backend profile 填充完毕：move 到 out.channel_backend，设定 channel_backend_id。
    //  这里只标识"用了哪个后端 Profile 类型"(qemu_ivshmem_linux),NOT 把 snapshot
    //  写死成某个 backend id —— snapshot 是执行模式诉求,具体后端由 Resolver 按
    //  "模式 → profile per-mode 默认 + backend 能力" 转译(见 resolver.cpp)。
    //  qemu.snapshot_fuzzing 标进后端无关的 out.snapshot_fuzzing 供 Resolver 选择;
    //  同时 backend_profile->runtime.instance.snapshot_fuzzing 已置(供 qemu_args)。
    out.snapshot_fuzzing = backend_profile->runtime.instance.snapshot_fuzzing;
    out.channel_common.backend_id  = std::string(refuzz::channel::channel_backend_id::kQemuIvshmemLinux);
    out.channel_backend_id         = std::string(refuzz::channel::channel_backend_id::kQemuIvshmemLinux);
    out.channel_backend            = std::move(backend_profile);

    //顶层 work_dir / state_dir / retention / retention_max + 构造 SessionLayout。
    //   - work_dir  空 → SessionLayout 内部回退到 "/tmp"
    //   - state_dir 空 → <work_dir>/state （或 "/tmp/state" 当 work_dir 也空）
    //   - retention 默认 false（启动期自动清理 base 下旧 run-*，永不碰 state/）
    //   - retention_max 默认 3
    out.work_dir      = GetString(root, "work_dir", std::string{});
    out.state_dir     = GetString(root, "state_dir", std::string{});
    out.retention     = GetBool(root, "retention", false);
    out.retention_max = GetU32(root, "retention_max", 3U);

    if (out.state_dir.empty()) {
        const std::string base = out.work_dir.empty() ? std::string("/tmp") : out.work_dir;
        out.state_dir = base + "/state";
    }

    try {
        SessionLayoutOptions lopt;
        lopt.work_dir      = out.work_dir;
        lopt.retention     = out.retention;
        lopt.retention_max = out.retention_max;
        out.layout         = MakeSessionLayout(lopt);
    } catch (const std::exception& e) {
        refuzz::logging::HostLineBuilder("Config", "session_layout_failed")
            << "failed to create session layout: " << e.what() << "\n";
        return false;
    }

    //路径兜底：
    //   - 瞬态: logging.path → session_layout.logs_dir
    //   - 持久: coverage / corpus / repros → state_dir
    //   用户在 yaml/json 里显式给了绝对路径就沿用（优先级更高）。
    if (out.logging.path.empty()) {
        out.logging.path = out.layout.logs_dir + "/host_events.txt";
    }
    if (out.coverage_output_dir.empty()) {
        out.coverage_output_dir = out.state_dir + "/coverage";
    }
    if (out.corpus_persist_dir.empty()) {
        out.corpus_persist_dir = out.state_dir + "/corpus";
    }
    if (out.coverage_persist_path.empty()) {
        out.coverage_persist_path = out.state_dir + "/coverage/coverage.bin";
    }
    if (out.repros_persist_dir.empty()) {
        out.repros_persist_dir = out.state_dir + "/repros";
    }

    return true;
}

std::string DumpConfigSummary(const OrchestratorConfig& config)
{
    nlohmann::json summary;
    summary["profile"] = config.profile;
    summary["work_dir"] = config.work_dir;
    summary["state_dir"] = config.state_dir;
    summary["session_root"] = config.layout.root;

    summary["channel"] = {
        {"backend_id", config.channel_backend_id},
        {"fuzz_channel_count", config.fuzz_channel_count},
        {"channel_id", config.channel_common.channel_id},
        {"n_workers", config.channel_common.n_workers},
        {"use", config.channel_common.use == channel::ChannelUse::kRepro
                    ? "repro"
                    : "fuzz"},
        {"wait_ready_timeout_ms",
         config.channel_common.wait_ready_timeout.count()},
        {"loop_interval_ms", config.channel_common.loop_interval.count()},
        {"health_check_interval_ms",
         config.channel_common.health_check_interval.count()},
        {"pre_reboot_drain_ms",
         config.channel_common.pre_reboot_drain.count()},
        {"input_queue_capacity",
         config.channel_common.input_queue_capacity},
    };

    summary["executor"] = {
        {"idle_sleep_us", config.executor.idle_sleep_us},
        {"submit_strategy", {{"name", config.executor.submit_strategy}}},
        {"event_forward_strategy",
         {{"blocking_timeout_us", config.executor.event_blocking_timeout_us},
          {"blocking_timeout_ms",
           static_cast<double>(config.executor.event_blocking_timeout_us) /
               1000.0}}},
        {"submit_wait_for_slot_ms", config.executor.submit_wait_for_slot_ms},
        {"timeouts",
         {{"pop_timeout_ms", config.pop_timeout.count()},
          {"poll_timeout_us", config.poll_timeout.count()}}},
    };

    summary["fuzzer"] = {
        // [request-window] 窗口 = 2 × n_workers,解析时赋给 request_window_limit 常量(非 config
        //   旋钮),故不在 config summary 回显。
        {"exec_timeout_ms", config.fuzzer.exec_timeout_ms},
        {"shutdown_grace_ms", config.shutdown_grace_ms},
        {"corpus_max_drain", config.fuzzer.corpus_max_drain},
        {"worker_log", {{"enable", config.worker_log_enabled}}},
        {"worker_perf",
         {{"enable", config.worker_perf_enabled},
          {"sample_rate", config.worker_perf_sample_rate},
          {"report_every", config.worker_perf_report_every}}},
        {"mutator_policy", config.mutator_policy},
    };

    summary["logging"] = {
        {"enable", config.logging.enable},
        {"stream", config.logging.stream},
        {"path", config.logging.path},
        {"console_summary", config.logging.console_summary},
        {"hot_path_sample_rate", config.logging.hot_path_sample_rate},
        {"task_trace_sample_rate", config.logging.task_trace_sample_rate},
    };

    if (const auto* qemu =
            dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
                config.channel_backend.get())) {
        summary["channel"]["qemu_ivshmem_linux"] = {
            {"transport",
             {{"ivshmem_mode", qemu->transport.use_doorbell ? "doorbell" : "plain"},
              {"doorbell_socket_path", qemu->transport.doorbell_socket_path},
              {"wait_ready_poll_us",
               qemu->transport.wait_ready_poll_us.count()},
              {"poll_sleep_us", qemu->transport.poll_sleep_us.count()}}},
            {"health_monitor",
             {{"sample_interval_ms",
               qemu->health_monitor.heartbeat.poll_interval.count()},
              {"miss_threshold",
               qemu->health_monitor.heartbeat.miss_threshold},
              {"workers_per_round",
               qemu->health_monitor.heartbeat.workers_per_round}}},
            {"runtime",
             {{"arch", qemu->runtime.instance.arch},
              {"kernel", qemu->runtime.instance.kernel},
              {"disk_image", qemu->runtime.instance.disk_image},
              {"ssh_user", qemu->runtime.instance.ssh_user},
              {"cpu", qemu->runtime.instance.cpu},
              {"mem_mb", qemu->runtime.instance.mem_mb},
              {"snapshot", qemu->runtime.instance.snapshot}}},
        };
    }

    return summary.dump(2);
}

} // namespace refuzz::orchestrator
