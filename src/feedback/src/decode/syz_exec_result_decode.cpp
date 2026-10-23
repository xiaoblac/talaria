// Copyright 2026 reFuzz project author -------youngkk.
//
// syz_exec_result_decode.cpp — implementation. See header for contract.

#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"

#include <cstring>

namespace refuzz::feedback::decode {

std::vector<refuzz::worker::SyzExecResult>
DecodeSyzExecResults(std::span<const std::uint8_t> output, std::size_t n_calls)
{
    std::vector<refuzz::worker::SyzExecResult> results;
    if (n_calls == 0 || output.empty()) {
        return results;
    }
    const std::size_t need = n_calls * sizeof(refuzz::worker::SyzExecResult);
    if (output.size() < need) {
        return results;
    }
    results.resize(n_calls);
    std::memcpy(results.data(), output.data(), need);
    return results;
}

// [v2 batch 3 PR-X — review revise: Finding 5 fix(2nd-pass:Medium fix)]
// head + tail decode + 可选 strict-mode。详细契约见 header doc。
//
// 2nd-pass review fix:统一 strict mode 验证 — `max_end <= expected` 在 head-only
// 路径(tail_bytes==0)也要检查,否则 expected==0 + 脏数据 cover_count!=0 时
// helper 会返非零 cover_count 但空 coverage_tail,违反 contract。
DecodedExecResultsWithCoverage
DecodeSyzExecResultsWithCoverage(
    std::span<const std::uint8_t> output,
    std::size_t                   n_calls,
    std::optional<std::size_t>    expected_tail_uint64s)
{
    DecodedExecResultsWithCoverage out;
    out.results = DecodeSyzExecResults(output, n_calls);
    if (out.results.empty()) {
        return out;
    }

    const std::size_t head_bytes = n_calls * sizeof(refuzz::worker::SyzExecResult);
    const std::size_t tail_bytes =
        (output.size() > head_bytes) ? (output.size() - head_bytes) : 0;

    // 计算 max_end(用 cover_offset+count)。head-only 时 max_end 仍按 results
    // 算 — 后面统一验证 max_end 与 tail 上限的关系。
    std::size_t max_end = 0;
    for (const auto& r : out.results) {
        const std::size_t end =
            static_cast<std::size_t>(r.cover_offset) +
            static_cast<std::size_t>(r.cover_count);
        if (end > max_end) max_end = end;
    }

    auto clear_all_counts = [&out]() {
        for (auto& r : out.results) {
            r.cover_offset = 0;
            r.cover_count  = 0;
        }
        out.coverage_tail.clear();
    };

    if (expected_tail_uint64s.has_value()) {
        // Strict mode:
        //   (a) tail_bytes 必须严格 == expected*8(caller 已 peel trailing
        //       packets);head-only 路径下 tail_bytes=0,expected==0 才合法。
        //   (b) max_end 必须 <= expected(防 head 内 cover_offset/count 脏数据
        //       即使 tail 长度对了也声称指向 tail 范围外的 cov)。
        const std::size_t expected = *expected_tail_uint64s;
        const std::size_t expected_tail_bytes = expected * sizeof(std::uint64_t);
        if (tail_bytes != expected_tail_bytes || max_end > expected) {
            clear_all_counts();
            return out;
        }
    } else {
        // Lenient mode:max_end <= tail_bytes/8(防 tail 内越界读)。
        const std::size_t cov_uint64s_avail = tail_bytes / sizeof(std::uint64_t);
        if (max_end > cov_uint64s_avail) {
            clear_all_counts();
            return out;
        }
    }

    if (max_end > 0) {
        out.coverage_tail.resize(max_end);
        std::memcpy(out.coverage_tail.data(),
                    output.data() + head_bytes,
                    max_end * sizeof(std::uint64_t));
    }
    return out;
}

}  // namespace refuzz::feedback::decode
