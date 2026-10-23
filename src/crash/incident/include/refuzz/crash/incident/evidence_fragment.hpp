// §3.11-D — CrashEvidenceFragment：跨 target 中性的"一条故障证据"。
//
// 设计目标：把 syzkaller-flavored CrashFragment（kernel-syz 专用，
// 强 console 偏好）抽成 target-neutral 的"evidence shape"，覆盖未来 7 个
// target 家族（kernel-syz / AFL CLI / middleware / protocol / DB / compiler
// / browser / DL）。每个 sensor / observation path 产生一个 fragment；多个
// fragment 关联到一个 Incident（incident.hpp）。
//
// 设计原则：
//   1) **target-format aware**：每个 fragment 携带 `program_format`，下游
//      analyzer 按 format 分派（不让通用层猜测）。
//   2) **payload 是 variant，不是 string**：信号 / 退出码 / console / 数值差分
//      / 大 blob 全部各自有结构化类型，不用单一 string 装下。
//   3) **confidence 分级**：heartbeat=Low（弱信号）vs console panic=High
//      （强信号）。aggregator 做合并 / classifier 做判定时按 confidence
//      取最高优。
//   4) **timestamp + sequence**：确保 incident aggregator 可以按时间窗 +
//      顺序关联多个 fragment。
//   5) **不绑死 transport**：fragment 不知道自己来自 ivshmem 还是 TCP；
//      只知道 source 类型（kHeartbeat / kSignal / ...）。
//
// 现状（D 阶段）：本文件只提供数据类型；HealthMonitor / Channel /
// CrashPipeline 还在用旧 health::CrashFragment + cc::Fault 路径。E 阶段
// 引入 IIncidentAnalyzer registry 时，会同步把 health 侧 emit 改写成
// EvidenceFragment，pipeline 入口也换成 Incident。

#pragma once

#include "refuzz/program/artifact.hpp"               // ProgramArtifact for origin_artifact link
#include "refuzz/program/prog_format.hpp"    // refuzz::fuzzer::ProgFormat

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace refuzz::crash::incident {

// ----------------------------------------------------------------
// Source — 触发本 fragment 的"观察路径"
// ----------------------------------------------------------------
//
// 同一份 evidence 可能由多种路径产出（console panic 同时被 console
// pattern + heartbeat 看到；compiler ICE 同时由 stderr + exit_code 命中）。
// Source 帮助 analyzer 区分"哪条链路来的"，影响 confidence + 是否升级
// classification（参见 §3.11-A coercion gate 的同款思路）。

enum class Source : std::uint8_t {
    // health-side detection sources
    kHeartbeat            = 0,   // worker heartbeat 卡住（low confidence）
    kKernelConsole        = 1,   // kernel /dev/console printk 模式命中（high）
    kSerialEof            = 2,   // serial channel EOF（worker died mid-output）
    kVmAlive              = 3,   // VM IsAlive() 返回 false
    kHealthInternal       = 4,   // sensor 自身错误（escalation）

    // OS / process signals (AFL / DB / browser / DL all need these)
    kSignal               = 10,  // SIGSEGV/SIGABRT/SIGILL/...
    kExitCode             = 11,  // 进程退出码（AFL fork-server / compiler）
    kCoreDump             = 12,  // post-mortem core file
    kStderrPattern        = 13,  // userspace stderr (ASAN / ICE / Python tb)
    kServerLog            = 14,  // daemon log file（Nginx / Postgres / Redis）
    kPythonTraceback      = 15,  // Python 异常栈

    // structured-data sources（per-target 特定）
    kCudaError            = 20,  // CUDA driver error code（PyTorch / TF）
    kSandboxViolation     = 21,  // browser 沙箱违规
    kIpcError             = 22,  // browser 多进程 IPC 失败
    kStepEvent            = 23,  // worker behavior trace（已有的 step ring）

    // differential / observation sources
    kDifferentialMismatch = 30,  // wrong-code / response diff / 数值差分
    kAssertionFailure     = 31,  // database / server assertion
    kHungCheck            = 32,  // host-side timeout / no-response
    kTimeout              = 33,

    kInternal             = 99,
};

// ----------------------------------------------------------------
// Confidence — 这条 evidence 对 incident 分类的影响力
// ----------------------------------------------------------------
//
// aggregator 收到多个 fragment 时，最终 classified incident 的 kind
// 取 confidence 最高的 fragment 主导。例如：
//   - heartbeat (Low) + console panic (High) → 合并 incident，分类
//     按 console panic 走（kernel crash）。
//   - heartbeat (Low) only → 保持 worker_dead，confidence Low。
enum class Confidence : std::uint8_t {
    kLow     = 0,
    kMedium  = 1,
    kHigh    = 2,
};

// ----------------------------------------------------------------
// Payload variants — 每种 source 对应的结构化 evidence
// ----------------------------------------------------------------

struct ConsoleLines {
    std::vector<std::string> lines;        // 行序列；空 = 无 console
    bool                     truncated = false;
};

struct SignalInfo {
    int          signum     = 0;           // POSIX signal number (SIGSEGV=11)
    std::uint64_t fault_addr = 0;          // siginfo_t::si_addr
    std::string  signal_name;              // "SIGSEGV" / "SIGABRT" / ...
    // Optional symbolized stack at signal site（addr2line / sanitizer 提供）
    std::vector<std::string> stack_top;
};

struct ExitCodeInfo {
    int           exit_code      = 0;      // process exit status
    bool          was_oom_killed = false;  // dmesg 检测 / cgroup signal
    bool          had_core_dump  = false;
};

struct StepEventSnapshot {
    // 与现有 channel/evidence/StepEventRing 对齐的快照；持有 record blob
    // 以便 fragment 跨 sensor 转发不依赖 step source 生命周期。
    std::vector<std::uint8_t> raw_records;  // serialized step events
};

struct StderrInfo {
    std::string  text;                     // captured stderr
    std::string  pattern_id;                // "asan_oob" / "asan_uaf" / "ice" / ...
    bool         truncated = false;
};

struct TimeoutInfo {
    std::uint64_t deadline_us = 0;
    std::uint64_t actual_us   = 0;
    std::string   stage;                   // "submit" / "execution" / "drain"
};

struct HeartbeatGap {
    std::uint64_t last_seen_us = 0;
    std::uint64_t gap_us       = 0;
    std::uint32_t miss_count   = 0;
};

// 差分 bug（compiler wrong-code / protocol diff / DL numerical diff）
struct DifferentialMismatchInfo {
    std::string left_fingerprint;          // e.g. opt level / impl name
    std::string right_fingerprint;
    std::string mismatch_type;              // "exit_code" / "stdout" / "tensor"
    std::vector<std::uint8_t> left_output_summary;
    std::vector<std::uint8_t> right_output_summary;
    double      tolerance = 0.0;            // numerical only
};

struct IceMessage {
    std::string compiler;                   // "clang" / "rustc" / "gcc"
    std::string ice_signature;              // distilled ICE banner
    std::string source_excerpt;
};

struct CudaErrorInfo {
    int          error_code = 0;
    std::string  error_string;              // cudaGetErrorString
    std::string  kernel_name;
    std::string  device_name;
};

struct RendererCrashInfo {
    std::string  process_role;              // "renderer" / "gpu" / "main"
    std::int32_t process_id = 0;
    std::string  v8_stack;
    std::string  crash_dump_summary;
};

struct ProtocolDiffInfo {
    std::string  protocol;                  // "http2" / "tls" / "dns" / "quic"
    std::vector<std::uint8_t> our_response;
    std::vector<std::uint8_t> ref_response;
};

// LargeBlobInfo —— blob 体积大（minidump、server log、tensor）时不 inline，
// 引用 IEvidenceBlobStore 的 blob_id；step F 引入 blob store 后启用。
struct LargeBlobInfo {
    std::string  blob_id;                   // sha256 of blob contents
    std::uint64_t size_bytes = 0;
    std::string  mime_type;                 // "application/x-minidump" / ...
    std::string  human_summary;             // for at-a-glance dedup
};

// 兜底 —— 暂未结构化的 sensor 输出 / 调试用。
struct OpaqueText {
    std::string text;
    std::string label;                      // free-form
};

using FragmentPayload = std::variant<
    ConsoleLines,
    SignalInfo,
    ExitCodeInfo,
    StepEventSnapshot,
    StderrInfo,
    TimeoutInfo,
    HeartbeatGap,
    DifferentialMismatchInfo,
    IceMessage,
    CudaErrorInfo,
    RendererCrashInfo,
    ProtocolDiffInfo,
    LargeBlobInfo,
    OpaqueText
>;

// ----------------------------------------------------------------
// CrashEvidenceFragment
// ----------------------------------------------------------------

struct CrashEvidenceFragment {
    Source                          source         = Source::kInternal;
    refuzz::fuzzer::ProgFormat      program_format = refuzz::fuzzer::ProgFormat::kSyzProg;
    std::uint64_t                   worker_id      = 0;
    std::uint64_t                   captured_ts_us = 0;
    std::uint64_t                   sequence       = 0;       // monotonic per process
    Confidence                      confidence     = Confidence::kLow;
    FragmentPayload                 payload;
    std::string                     checker_name;             // e.g. "heartbeat" / "console"
};

} // namespace refuzz::crash::incident
