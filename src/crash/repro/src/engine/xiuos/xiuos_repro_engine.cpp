#include "refuzz/crash/repro/engine/xiuos/xiuos_repro_engine.hpp"

#include <utility>
#include <vector>

namespace refuzz::crash {

bool XiuosReproEngine::MatchVerdict(
    const RunResult& run,
    const VerdictParams& /*params*/,
    bool /*strict*/,
    const std::string& /*target_title*/,
    const std::unordered_set<std::string>& /*observed_titles*/,
    const std::vector<std::string>& /*alt_titles*/,
    CrashKind /*crash_kind*/) const
{
    // A replayed program reproduces the crash iff the worker stopped returning a
    // RESULT — worker_dead/kernel_crash (run.crashed) OR a wedge (run.timed_out).
    // The channel-health path classified both as the original crash; CountsAsRepro
    // keeps the extract verdict and the minimize test loop in agreement.
    return CountsAsRepro(run);
}

MinimizeResult XiuosReproEngine::Minimize(
    const std::vector<uint8_t>& payload,
    const ::refuzz::program::ProgramArtifact* /*artifact*/,
    TestFunc test_fn,
    StopFunc stop_fn,
    const MinimizeParams& /*params*/)
{
    // XiUOS exec-wire PROGRAM layout: [version, suite, call_count, flags] then
    // call_count × 20-byte call records. Greedy call-level delta-debug: drop each
    // call; if the candidate still crashes (test_fn.first), commit.
    constexpr std::size_t kHdr = 4;
    constexpr std::size_t kRec = 20;

    MinimizeResult r;
    r.artifact = nullptr;  // bytes-only target

    if (payload.size() < kHdr) {
        r.payload = payload;
        r.success = false;
        return r;
    }
    const std::uint8_t version = payload[0];
    const std::uint8_t suite   = payload[1];
    const std::uint8_t count   = payload[2];
    const std::uint8_t flags   = payload[3];
    if (payload.size() != kHdr + static_cast<std::size_t>(count) * kRec) {
        r.payload = payload;  // malformed framing → leave as-is, don't shrink
        r.success = false;
        return r;
    }
    r.original_call_count = count;

    std::vector<std::vector<std::uint8_t>> calls;
    calls.reserve(count);
    for (std::uint8_t i = 0; i < count; ++i) {
        const std::size_t off = kHdr + static_cast<std::size_t>(i) * kRec;
        calls.emplace_back(payload.begin() + static_cast<long>(off),
                           payload.begin() + static_cast<long>(off + kRec));
    }

    auto encode = [&](const std::vector<std::vector<std::uint8_t>>& cs) {
        std::vector<std::uint8_t> p;
        p.reserve(kHdr + cs.size() * kRec);
        p.push_back(version);
        p.push_back(suite);
        p.push_back(static_cast<std::uint8_t>(cs.size()));
        p.push_back(flags);
        for (const auto& c : cs) {
            p.insert(p.end(), c.begin(), c.end());
        }
        return p;
    };

    std::uint32_t attempts = 0;
    std::uint32_t commits  = 0;
    bool changed = true;
    while (changed && calls.size() > 1 && !stop_fn()) {
        changed = false;
        for (std::size_t i = 0; i < calls.size(); ++i) {
            if (stop_fn()) {
                break;
            }
            std::vector<std::vector<std::uint8_t>> cand = calls;
            cand.erase(cand.begin() + static_cast<long>(i));
            ++attempts;
            const auto verdict = test_fn(encode(cand));  // complete verdict
            if (verdict.first) {                          // still crashes without call i
                calls = std::move(cand);
                ++commits;
                changed = true;
                break;
            }
        }
    }

    r.payload              = encode(calls);
    r.minimized_call_count = static_cast<std::uint32_t>(calls.size());
    r.success              = true;  // payload entering Minimize already reproduced
    r.minimize_attempts    = attempts;
    r.minimize_commits     = commits;
    r.minimize_stage       = "xiuos_calls";
    return r;
}

} // namespace refuzz::crash
