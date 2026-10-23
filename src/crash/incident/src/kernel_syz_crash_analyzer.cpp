// §3.11-E — KernelSyzCrashAnalyzer：把现有 KernelReportParser /
// ParseAndClassifyOp / DedupOp 的 kernel-syz crash 分析逻辑包成一个
// `IIncidentAnalyzer` adapter（kSyzProg, kCrash）。
//
// 行为预期：跟现有 syz_pipeline_ops.cpp 的输出**等价** —— title /
// stack / kind / dedup hash 同源同算法，只是入口从"按 op 顺序跑"换成
// "按 incident 综合分析"。
//
// 现状：CrashPipelineManager 仍走 old ops；本 adapter 通过 registry 暴露
// 给后续家族扩展使用。完整 pipeline 改派发是 §3.11 后续工作。

#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/crash/incident/incident_analyzer.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

namespace refuzz::crash::incident {

namespace {

// ----- FNV-1a 64-bit (跟 diagnostic_store.cpp 同算法) -----

constexpr std::uint64_t kFnvOffset = 0xcbf29ce484222325ULL;
constexpr std::uint64_t kFnvPrime  = 0x100000001b3ULL;

std::uint64_t Fnv1a64(const std::string& s) {
    std::uint64_t h = kFnvOffset;
    for (unsigned char c : s) {
        h ^= c;
        h *= kFnvPrime;
    }
    return h;
}

std::uint64_t Fnv1a64Fold(std::uint64_t seed, const std::string& s) {
    for (unsigned char c : s) {
        seed ^= c;
        seed *= kFnvPrime;
    }
    return seed;
}

// ----- KernelSyzCrashAnalyzer -----

class KernelSyzCrashAnalyzer final : public IIncidentAnalyzer {
public:
    refuzz::fuzzer::ProgFormat program_format() const override {
        return refuzz::fuzzer::ProgFormat::kSyzProg;
    }
    IncidentKind incident_kind() const override {
        return IncidentKind::kCrash;
    }

    ClassifiedIncident Classify(const CrashIncident& incident) override {
        ClassifiedIncident out;
        out.kind       = IncidentKind::kCrash;
        out.confidence = Confidence::kLow;

        // 第一遍：取最高 confidence fragment 主导分类。
        const CrashEvidenceFragment* primary = HighestConfidenceFragment(incident);
        if (primary != nullptr) {
            out.confidence = primary->confidence;
        }

        // 第二遍：扫所有 console-类型 fragment，凑 console_text 给
        // KernelReportParser；若任意 fragment 是 kKernelConsole 且有
        // ConsoleLines，则把它的 lines 串起来送给 parser。这与现有
        // BuildContextOp + ParseAndClassifyOp 行为一致：parser 读
        // ctx.console_log（多源拼接）。
        std::string console_text;
        for (const auto& f : incident.fragments) {
            if (f.source != Source::kKernelConsole && f.source != Source::kSerialEof) {
                continue;
            }
            if (const auto* cl = std::get_if<ConsoleLines>(&f.payload)) {
                for (const auto& line : cl->lines) {
                    console_text.append(line);
                    console_text.push_back('\n');
                }
            }
        }

        bool has_parsed_kernel_title = false;
        if (!console_text.empty()) {
            refuzz::crash::KernelReportParser parser;
            auto parsed = parser.Parse(console_text);
            if (parsed.has_value() && !parsed->title.empty()) {
                has_parsed_kernel_title = true;
                out.title = parsed->title;
                out.stack_top.reserve(std::min<std::size_t>(3, parsed->frames.size()));
                for (std::size_t i = 0; i < std::min<std::size_t>(3, parsed->frames.size()); ++i) {
                    out.stack_top.push_back(parsed->frames[i].function);
                }
            }
        }

        // 兜底标题：从 highest-confidence fragment 的 SignalInfo /
        // OpaqueText / HeartbeatGap 里凑一个。
        if (out.title.empty() && primary != nullptr) {
            if (const auto* s = std::get_if<SignalInfo>(&primary->payload)) {
                out.title = "signal-" + std::to_string(s->signum);
                out.stack_top = s->stack_top;
            } else if (const auto* h = std::get_if<HeartbeatGap>(&primary->payload)) {
                out.title = "worker heartbeat stalled";
                (void)h;
            } else if (const auto* t = std::get_if<OpaqueText>(&primary->payload)) {
                out.title = t->label.empty() ? std::string("unknown crash") : t->label;
            } else {
                out.title = "unknown crash";
            }
        }

        // A parsed Linux report is identified by the same canonical title used
        // by the main crash pipeline. Keep stack_top as diagnostic data, but do
        // not turn raw frames into a second, incompatible identity scheme.
        std::string sig;
        sig.reserve(96);
        sig.append(out.title);
        if (!has_parsed_kernel_title) {
            sig.append("|fmt=");
            sig.append(std::to_string(static_cast<int>(incident.program_format)));
            if (!out.stack_top.empty()) {
                sig.append("|stack=");
                for (std::size_t i = 0; i < out.stack_top.size(); ++i) {
                    if (i > 0) sig.push_back(',');
                    sig.append(out.stack_top[i]);
                }
            }
        }
        out.signature = std::move(sig);

        return out;
    }

    std::uint64_t BucketHash(const ClassifiedIncident& classified) override {
        std::uint64_t h = Fnv1a64(IncidentKindName(classified.kind));
        h = Fnv1a64Fold(h, classified.signature);
        return h;
    }

    bool ShouldMerge(const ClassifiedIncident& a,
                      const ClassifiedIncident& b) override {
        // 默认实现：bucket hash 相同 → 合并。target-specific 优化（如
        // 容忍 KASAN 报告里 frame 偏移差异）将来用 std::hash distance 做。
        return BucketHash(a) == BucketHash(b);
    }
};

} // namespace

std::unique_ptr<IIncidentAnalyzer> CreateKernelSyzCrashAnalyzer() {
    return std::make_unique<KernelSyzCrashAnalyzer>();
}

} // namespace refuzz::crash::incident
