#pragma once

// XiuosReproEngine — XiUOS RTOS 的 repro 能力引擎(exec-wire program)。
//
// 与 KernelReproEngine 对等:都是 IReproEngine 的实现。ReproManager 经接口调用,
// 不知道具体 target。XiUOS 的三处差异:
//   - MatchVerdict : 重放后 worker 死(run.crashed = xiuos worker_dead /
//                    kernel_crash)即重现;wedge 是 run.timed_out,不算。
//   - Minimize     : 直接对 exec-wire payload 做 **call-level delta-debug**
//                    (XiUOS 是 bytes-only,无 typed ProgramArtifact),逐个删 call、
//                    仍崩则提交,直到不能再删。RequiresTypedArtifactForMinimize=false。
//   - ParseAndSymbolize : 无(XiUOS 无 Linux dmesg)→ 用 IReproEngine 默认 no-op。

#include "refuzz/crash/repro/core/repro_engine.hpp"

namespace refuzz::crash {

class XiuosReproEngine final : public IReproEngine {
public:
    // XiUOS crash on replay = worker stops returning RESULT: either a hard
    // worker_dead/kernel_crash (run.crashed) or a wedge (run.timed_out). Both are
    // the same observable the channel-health path classified as the crash.
    bool CountsAsRepro(const RunResult& run) const override {
        return run.crashed || run.timed_out;
    }

    // A wedge leaves the worker blocked forever in an ecall (the VM stays
    // "running", so the channel never auto-recovers); a worker death likewise
    // leaves it unusable. Each repro candidate must therefore run on a freshly
    // rebooted worker, else minimize over-collapses (every later candidate also
    // times out against the stuck worker and looks like it "reproduces").
    bool RequiresHardRebootBetweenRuns() const override { return true; }

    bool MatchVerdict(
        const RunResult& run,
        const VerdictParams& params,
        bool strict,
        const std::string& target_title,
        const std::unordered_set<std::string>& observed_titles,
        const std::vector<std::string>& alt_titles,
        CrashKind crash_kind) const override;

    // XiUOS 程序是 exec-wire bytes,无 typed authority → 直接 minimize payload。
    bool RequiresTypedArtifactForMinimize() const override { return false; }

    MinimizeResult Minimize(
        const std::vector<uint8_t>& payload,
        const ::refuzz::program::ProgramArtifact* artifact,
        TestFunc test_fn,
        StopFunc stop_fn,
        const MinimizeParams& params) override;
};

} // namespace refuzz::crash
