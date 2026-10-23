// §3.11-E — IncidentAnalyzerRegistry + builtin analyzer registration +
// SingleWorkerTimeWindowCorrelator 实现。

#include "refuzz/crash/incident/incident_analyzer.hpp"

#include <algorithm>
#include <mutex>

namespace refuzz::crash::incident {

// ----- IncidentAnalyzerRegistry -----

IncidentAnalyzerRegistry& IncidentAnalyzerRegistry::Instance() {
    static IncidentAnalyzerRegistry inst;
    return inst;
}

void IncidentAnalyzerRegistry::Register(std::unique_ptr<IIncidentAnalyzer> a) {
    if (a == nullptr) return;
    Key key{
        static_cast<int>(a->program_format()),
        static_cast<int>(a->incident_kind())
    };
    by_key_[key] = std::move(a);
}

IIncidentAnalyzer* IncidentAnalyzerRegistry::Find(
    refuzz::fuzzer::ProgFormat format,
    IncidentKind kind) const
{
    Key key{static_cast<int>(format), static_cast<int>(kind)};
    auto it = by_key_.find(key);
    return it == by_key_.end() ? nullptr : it->second.get();
}

void IncidentAnalyzerRegistry::ResetForTest() {
    by_key_.clear();
}

// ----- Builtin registration -----

// Forward decl for KernelSyzCrashAnalyzer factory defined in
// kernel_syz_crash_analyzer.cpp（namespace-level so the linker can
// resolve across TUs）。
std::unique_ptr<IIncidentAnalyzer> CreateKernelSyzCrashAnalyzer();

void RegisterBuiltinIncidentAnalyzers() {
    // 幂等：Register 按 (format, kind) key 覆盖；多次调用安全，且兼容
    // tests 的 ResetForTest → Register 模式（call_once 在那种模式下会
    // 跳过，导致 reset 后再调 Register 不生效）。
    auto& reg = IncidentAnalyzerRegistry::Instance();
    reg.Register(CreateKernelSyzCrashAnalyzer());
    // Future: Afl/Compiler/Db/Browser/Dl analyzers register here.
}

// ----- SingleWorkerTimeWindowCorrelator -----

std::optional<std::uint64_t>
SingleWorkerTimeWindowCorrelator::FindOrAttach(
    const CrashEvidenceFragment& frag,
    const std::vector<CrashIncident>& open_incidents)
{
    // 用 fragment.worker_id 跟 incident.correlation_keys[0] 对比；
    // 同 worker_id 且 frag.captured_ts_us 落在 incident 时间窗内 → 复用。
    for (const auto& inc : open_incidents) {
        if (inc.correlation_keys.empty()) continue;
        if (inc.correlation_keys[0] != frag.worker_id) continue;

        // 时间窗：fragment 时间不能早于 incident 起始 - window，
        // 也不能晚于 incident 当前末尾 + window。
        const std::uint64_t lo = inc.first_fragment_ts_us > window_us_
            ? (inc.first_fragment_ts_us - window_us_) : 0;
        const std::uint64_t hi = inc.last_fragment_ts_us + window_us_;
        if (frag.captured_ts_us >= lo && frag.captured_ts_us <= hi) {
            return inc.incident_id;
        }
    }
    return std::nullopt;
}

bool SingleWorkerTimeWindowCorrelator::ShouldClose(
    const CrashIncident& incident, std::uint64_t now_us)
{
    if (incident.last_fragment_ts_us == 0) return false;
    return now_us > incident.last_fragment_ts_us + window_us_;
}

} // namespace refuzz::crash::incident
