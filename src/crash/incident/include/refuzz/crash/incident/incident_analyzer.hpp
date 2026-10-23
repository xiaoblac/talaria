// §3.11-E — IIncidentAnalyzer + IncidentAnalyzerRegistry (per-target adapter ABI).
//
// 仿 ArtifactMaterializerRegistry（§3.10 follow-up）的 registry pattern：
// 每个 (program_format, IncidentKind) 注册一个 analyzer adapter；上层
// `CrashPipelineManager`（或测试）按 (format, kind) 查表派发，不写硬分支。
//
// 7 家族落地路径：
//   - kernel-syz crash    → KernelSyzCrashAnalyzer    (kSyzProg, kCrash)
//   - AFL CLI crash       → AflRawCrashAnalyzer       (kAflRaw, kCrash)
//   - compiler ICE        → CompilerIceCrashAnalyzer  (kSrcFile, kCrash)
//   - compiler wrong-code → CompilerDiffAnalyzer      (kSrcFile, kDifferential)
//   - DB result diff      → DbResultDiffAnalyzer      (kSqlProgram, kDifferential)
//   - browser renderer    → RendererCrashAnalyzer     (kHtmlJs, kCrash)
//   - DL numerical diff   → DlNumericalDiffAnalyzer   (kTensorOpGraph, kDifferential)
//
// E 阶段交付：interface + registry + KernelSyzCrashAnalyzer 一份；
// CrashPipelineManager 还在用旧 ops 链（行为不变），新接入点供后续家族
// 加 adapter 时使用。

#pragma once

#include "refuzz/crash/incident/incident.hpp"
#include "refuzz/program/prog_format.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::crash::incident {

// ----------------------------------------------------------------
// ClassifiedIncident — analyzer 分析后的 incident 摘要
// ----------------------------------------------------------------

struct ClassifiedIncident {
    IncidentKind             kind        = IncidentKind::kUnknown;
    std::string              title;       // primary one-line identifier
    std::string              signature;   // canonical semantic key
    std::vector<std::string> stack_top;   // top-N frames (≥0 entries)
    Confidence               confidence  = Confidence::kLow;
};

// ----------------------------------------------------------------
// IIncidentAnalyzer — per-target 分析器
// ----------------------------------------------------------------

class IIncidentAnalyzer {
public:
    virtual ~IIncidentAnalyzer() = default;

    // 注册 key
    virtual refuzz::fuzzer::ProgFormat program_format() const = 0;
    virtual IncidentKind               incident_kind()  const = 0;

    // 把 incident 综合成 ClassifiedIncident。实现按 fragments[i].source /
    // payload / confidence 各取所需；最高 confidence fragment 通常主导
    // kind / title。
    virtual ClassifiedIncident
    Classify(const CrashIncident& incident) = 0;

    // dedup bucket hash —— 默认实现是 ClassifiedIncident 字段的哈希；
    // adapter 可以加 target-specific 维度（如编译器加 opt-set / DL 加
    // tolerance）。
    virtual std::uint64_t
    BucketHash(const ClassifiedIncident& classified) = 0;

    // 语义级合并判定（hash 相同未必合并；hash 不同也可能合并）。
    // 默认 = (BucketHash(a) == BucketHash(b))，实现自由覆盖。
    virtual bool
    ShouldMerge(const ClassifiedIncident& a,
                const ClassifiedIncident& b) = 0;
};

// ----------------------------------------------------------------
// IIncidentCorrelator — fragment → incident 关联策略
// ----------------------------------------------------------------
//
// 关联策略 per profile，处理多 fragment / 多 worker / 多进程的情形：
//   - SingleWorkerTimeWindowCorrelator：单 worker_id + 时间窗（默认）
//   - MultiProcessGroupCorrelator：browser pid 树关联
//   - DifferentialPairCorrelator：source-input + opt-set 配对

class IIncidentCorrelator {
public:
    virtual ~IIncidentCorrelator() = default;

    // 找到 fragment 应该 attach 到的 open incident；返回 nullopt 表示
    // 应当新开一个 incident（caller 负责分配 incident_id）。
    virtual std::optional<std::uint64_t>
    FindOrAttach(const CrashEvidenceFragment& frag,
                 const std::vector<CrashIncident>& open_incidents) = 0;

    // 给定时刻 now_us，incident 是否可以关闭并送给下游 analyzer。
    virtual bool
    ShouldClose(const CrashIncident& incident, std::uint64_t now_us) = 0;
};

// ----------------------------------------------------------------
// IncidentAnalyzerRegistry — 进程单例
// ----------------------------------------------------------------

class IncidentAnalyzerRegistry {
public:
    static IncidentAnalyzerRegistry& Instance();

    void Register(std::unique_ptr<IIncidentAnalyzer>);

    // 查表。未注册返回 nullptr。
    IIncidentAnalyzer* Find(refuzz::fuzzer::ProgFormat format,
                             IncidentKind kind) const;

    void ResetForTest();

private:
    IncidentAnalyzerRegistry() = default;

    struct Key {
        int format_int;
        int kind_int;
        bool operator==(const Key& o) const noexcept {
            return format_int == o.format_int && kind_int == o.kind_int;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<long long>{}(
                (static_cast<long long>(k.format_int) << 32) ^
                static_cast<long long>(k.kind_int));
        }
    };

    std::unordered_map<Key, std::unique_ptr<IIncidentAnalyzer>, KeyHash> by_key_;
};

// 进程级一次性注册所有 builtin analyzer。idempotent（重复调用安全）。
void RegisterBuiltinIncidentAnalyzers();

// ----------------------------------------------------------------
// SingleWorkerTimeWindowCorrelator — 默认 correlator
// ----------------------------------------------------------------

class SingleWorkerTimeWindowCorrelator : public IIncidentCorrelator {
public:
    explicit SingleWorkerTimeWindowCorrelator(std::uint64_t window_us = 5'000'000)
        : window_us_(window_us) {}

    std::optional<std::uint64_t>
    FindOrAttach(const CrashEvidenceFragment& frag,
                 const std::vector<CrashIncident>& open_incidents) override;

    bool ShouldClose(const CrashIncident& incident,
                     std::uint64_t now_us) override;

private:
    std::uint64_t window_us_;
};

} // namespace refuzz::crash::incident
