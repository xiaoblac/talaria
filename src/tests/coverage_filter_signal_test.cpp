// [syz-parity convertCallInfo] Tests for the kernel-address sanity filter in
// NormalizeCoverageEntries: a coverage slice with ANY PC outside
// [kernel_text_start, kernel_text_end] is dropped WHOLE (mirrors syzkaller
// pkg/rpcserver/runner.go convertCallInfo). The filter runs on raw PCs BEFORE
// hashing, so it works in both raw-PC and hash mode.

#include "refuzz/feedback/coverage_semantics.hpp"
#include "refuzz/feedback/feedback_codec.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

using refuzz::fuzzer::NormalizeCoverageEntries;
using refuzz::fuzzer::CoverageNormalizationConfig;
using refuzz::fuzzer::ComputeEdgeSignal;

namespace {

// A valid kernel-text PC (inside the syz amd64 default window) and two bogus ones.
constexpr std::uint64_t kPcA      = 0xffffffff81000000ULL;
constexpr std::uint64_t kPcB      = 0xffffffff81000123ULL;
constexpr std::uint64_t kBelow    = 0x0000000200000000ULL;  // < text_start
constexpr std::uint64_t kAbove    = 0xffffffffff800000ULL;  // > text_end

CoverageNormalizationConfig RawPcCfg(bool filter)
{
    CoverageNormalizationConfig c;
    c.raw_pc = true;            // keep PCs (no hashing) so we can compare addresses
    c.filter_signal = filter;   // defaults of kernel_text_start/end = syz amd64
    return c;
}

void TestFilterOffPassesThrough()
{
    auto out = NormalizeCoverageEntries({kBelow, kPcA, kAbove}, RawPcCfg(/*filter=*/false));
    // Off => legacy behavior: out-of-range PCs survive (sorted+unique).
    assert(out.size() == 3);
    printf("  [ok] filter off: out-of-range PCs pass through\n");
}

void TestFilterOnAllInRangeKept()
{
    auto out = NormalizeCoverageEntries({kPcB, kPcA, kPcA}, RawPcCfg(/*filter=*/true));
    assert(out.size() == 2);          // dedup of kPcA
    assert(out[0] == kPcA && out[1] == kPcB);
    printf("  [ok] filter on, all in range: kept (sorted+unique)\n");
}

void TestFilterOnBogusBelowDropsWhole()
{
    auto out = NormalizeCoverageEntries({kPcA, kBelow, kPcB}, RawPcCfg(/*filter=*/true));
    assert(out.empty());              // one PC below text_start => whole slice gone
    printf("  [ok] filter on, PC below text_start: whole slice dropped\n");
}

void TestFilterOnBogusAboveDropsWhole()
{
    auto out = NormalizeCoverageEntries({kPcA, kAbove}, RawPcCfg(/*filter=*/true));
    assert(out.empty());              // one PC above text_end => whole slice gone
    printf("  [ok] filter on, PC above text_end: whole slice dropped\n");
}

void TestFilterOnZeroRangeDisabled()
{
    auto c = RawPcCfg(/*filter=*/true);
    c.kernel_text_start = 0;          // start==0 => disabled (matches syz textStart!=0 guard)
    auto out = NormalizeCoverageEntries({kBelow, kPcA}, c);
    assert(out.size() == 2);          // not filtered
    printf("  [ok] filter on but text_start==0: disabled (no filtering)\n");
}

void TestFilterOnEmptyInput()
{
    auto out = NormalizeCoverageEntries({}, RawPcCfg(/*filter=*/true));
    assert(out.empty());
    printf("  [ok] filter on, empty input: empty (no crash)\n");
}

void TestFilterRunsBeforeHashing()
{
    // Hash mode (raw_pc=false): in-range PCs survive (and get hashed -> non-empty);
    // a bogus PC must still drop the whole slice BEFORE hashing turns addrs opaque.
    CoverageNormalizationConfig keep;
    keep.raw_pc = false;
    keep.filter_signal = true;
    auto hashed = NormalizeCoverageEntries({kPcA, kPcB}, keep);
    assert(hashed.size() == 2);       // kept + hashed

    CoverageNormalizationConfig drop = keep;
    auto gone = NormalizeCoverageEntries({kPcA, kAbove}, drop);
    assert(gone.empty());             // dropped pre-hash despite hash mode
    printf("  [ok] filter runs before hashing (works in hash mode)\n");
}

void TestEdgeSignalMatchesSyzkallerHash()
{
    const auto edges = ComputeEdgeSignal({
        0xffffffff81000123ULL,
        0xffffffff81000456ULL,
        0xffffffff81000abcULL,
        0xffffffff81000456ULL,
    });
    const std::vector<std::uint64_t> expected = {
        0xffffffff81000849ULL,
        0xffffffff8100090fULL,
        0xffffffff8100069eULL,
        0xffffffff810001d7ULL,
    };
    assert(edges == expected);
    printf("  [ok] edge signal matches syzkaller executor hash\n");
}

} // namespace

int main()
{
    printf("Running coverage_filter_signal_test...\n");
    TestFilterOffPassesThrough();
    TestFilterOnAllInRangeKept();
    TestFilterOnBogusBelowDropsWhole();
    TestFilterOnBogusAboveDropsWhole();
    TestFilterOnZeroRangeDisabled();
    TestFilterOnEmptyInput();
    TestFilterRunsBeforeHashing();
    TestEdgeSignalMatchesSyzkallerHash();
    printf("coverage_filter_signal_test: ALL PASS\n");
    return 0;
}
