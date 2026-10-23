// §3.11-D — Incident：把同一次故障的多个 EvidenceFragment 关联起来。
//
// 背景：现状 reFuzz 把每个 CrashEvent 当独立事件流过 pipeline。但真实场景
// 一次故障常由多源信号组成：
//   t=0 worker heartbeat 慢
//   t=2s console 出 "softlockup detected"
//   t=5s heartbeat 完全停
//   t=8s VM ssh 不上
// 旧路径：4 条独立 CrashEvent → 4 条 dedup 写盘记录 → 同一 bug 看上去
// 报了 4 次。
//
// Incident 是 aggregator（IIncidentCorrelator）按一定策略把多 fragment
// 关联起来，下游 analyzer 看到的是"一个 incident 里有 N 条 evidence"。
//
// 关联策略（IIncidentCorrelator）按 profile 注入：
//   - SingleWorkerTimeWindowCorrelator：单 worker_id + 时间窗（kernel-syz）
//   - MultiProcessGroupCorrelator：browser 主/渲染/GPU 多 pid → 一 incident
//   - DifferentialPairCorrelator：编译器多 opt-level 对比，按 source-input
//     hash + opt-set 关联
//
// 现状（D 阶段）：本文件只提供数据类型；E 阶段引入 IIncidentAnalyzer 后
// CrashPipelineManager 改用 Incident 作为入口。

#pragma once

#include "refuzz/crash/incident/evidence_fragment.hpp"
#include "refuzz/program/artifact.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::crash::incident {

// 一次故障的 incident 类型 —— 跨 target 通用。
enum class IncidentKind : std::uint8_t {
    kCrash         = 0,   // 进程 / VM / 内核崩溃
    kHang          = 1,   // 卡住但没死（hung_task / heartbeat lost）
    kDifferential  = 2,   // 差分 bug（wrong-code / response diff / numerical）
    kSanitizer     = 3,   // ASAN / UBSAN / KASAN 报告（无进程 crash 也算）
    kInfraFault    = 4,   // 基础设施故障（VM 启不来、ssh 断、submit 失败）
    kUnknown       = 99,
};

inline const char* IncidentKindName(IncidentKind k) {
    switch (k) {
    case IncidentKind::kCrash:        return "crash";
    case IncidentKind::kHang:         return "hang";
    case IncidentKind::kDifferential: return "differential";
    case IncidentKind::kSanitizer:    return "sanitizer";
    case IncidentKind::kInfraFault:   return "infra_fault";
    case IncidentKind::kUnknown:      return "unknown";
    }
    return "unknown";
}

struct CrashIncident {
    std::uint64_t                 incident_id           = 0;
    refuzz::fuzzer::ProgFormat    program_format        =
        refuzz::fuzzer::ProgFormat::kSyzProg;
    std::uint64_t                 first_fragment_ts_us  = 0;
    std::uint64_t                 last_fragment_ts_us   = 0;

    // Correlation key：按 profile 策略不同，semantics 不同。
    //   single-worker: 单值 worker_id
    //   multi-process: 一组 pid（root + children）
    //   differential:  source-input hash + opt-set 序列化
    // 这里用 vector<uint64_t> 容纳所有形态；correlator 自己解读。
    std::vector<std::uint64_t>    correlation_keys;

    std::vector<CrashEvidenceFragment> fragments;

    // 触发本 incident 的程序 artifact（program/ 跨 target 中性边界）。
    // 一个 incident 通常对应一个被测程序；多 input 差分情况由
    // DifferentialMismatchInfo 内部携带 left/right summary。
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> origin_artifact;
};

// 简便 helper：取 fragments 中 confidence 最高的（用于 analyzer 选定
// 主分类信号）。
inline const CrashEvidenceFragment*
HighestConfidenceFragment(const CrashIncident& incident) {
    const CrashEvidenceFragment* best = nullptr;
    for (const auto& f : incident.fragments) {
        if (best == nullptr || f.confidence > best->confidence) best = &f;
    }
    return best;
}

} // namespace refuzz::crash::incident
