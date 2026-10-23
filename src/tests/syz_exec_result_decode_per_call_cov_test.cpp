// syz_exec_result_decode_per_call_cov_test.cpp
//
// [v2 batch 3 PR-X] DecodeSyzExecResultsWithCoverage 单测:
//   Lenient mode (默认):
//     - Case 1: head + tail decode round-trip
//     - Case 2: legacy output(只有 head 没 tail)— 各 cover_count=0
//     - Case 3: corrupted tail(cover_offset+count 越界)— 清零防御
//     - Case 4: empty output / n_calls == 0
//
//   Strict mode (review revise — Finding 5):
//     - Case 5: tail 严格匹配 expected_tail_uint64s — round-trip
//     - Case 6: tail_bytes < expected_tail_uint64s*8 — corrupted clear
//     - Case 7: tail_bytes > expected_tail_uint64s*8(模拟 caller 没 peel
//               trailing packet 字节)— corrupted clear
//     - Case 8: expected_tail_uint64s == 0 + 有 tail bytes — corrupted clear
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-X step 4。

#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <optional>
#include <vector>

int main()
{
    using refuzz::feedback::decode::DecodeSyzExecResultsWithCoverage;
    using refuzz::worker::kCallFlagExecuted;
    using refuzz::worker::kCallFlagFaultInjected;
    using refuzz::worker::kCallFlagFinished;
    using refuzz::worker::SyzExecResult;

    std::fprintf(stdout, "Running syz_exec_result_decode_per_call_cov_test...\n");

    // ── Case 1: head + tail decode roundtrip ─────────────────────────────
    {
        constexpr std::size_t kN = 3;
        // 准备 results: call 0 → cov[0..2], call 1 → cov[2..5], call 2 → no cov
        SyzExecResult results[kN] = {};
        results[0] = {/*ret=*/100, /*err=*/0,    /*flags=*/0, /*cover_offset=*/0, /*cover_count=*/2};
        results[1] = {/*ret=*/-1,  /*err=*/-13,  /*flags=*/0, /*cover_offset=*/2, /*cover_count=*/3};
        results[2] = {/*ret=*/0,   /*err=*/0,    /*flags=*/0, /*cover_offset=*/0, /*cover_count=*/0};
        const std::uint64_t cov_tail[5] = {0x111, 0x222, 0x333, 0x444, 0x555};

        // pack: head (kN × SyzExecResult) + tail (5 × uint64)
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        const std::size_t tail_bytes = 5 * sizeof(std::uint64_t);
        std::vector<std::uint8_t> output(head_bytes + tail_bytes);
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, cov_tail, tail_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(output, kN);
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_offset == 0);
        assert(decoded.results[0].cover_count == 2);
        assert(decoded.results[1].cover_offset == 2);
        assert(decoded.results[1].cover_count == 3);
        assert(decoded.results[2].cover_count == 0);
        assert(decoded.coverage_tail.size() == 5);
        assert(decoded.coverage_tail[0] == 0x111);
        assert(decoded.coverage_tail[2] == 0x333);
        assert(decoded.coverage_tail[4] == 0x555);

        // slice 验证(consumer 用 cover_offset/count 切)
        auto* cov0 = decoded.coverage_tail.data() + decoded.results[0].cover_offset;
        assert(cov0[0] == 0x111);
        assert(cov0[1] == 0x222);
        auto* cov1 = decoded.coverage_tail.data() + decoded.results[1].cover_offset;
        assert(cov1[0] == 0x333);
        assert(cov1[2] == 0x555);
    }

    // ── Case 2: legacy output(只有 head,没 tail)── 各 cover_count=0 ────
    // 模拟旧 worker(没有 PR-X cover_offset/count 写入)或 KCOV 不可用场景。
    {
        constexpr std::size_t kN = 2;
        SyzExecResult results[kN] = {};
        results[0] = {1, 0, 0, 0, 0};
        results[1] = {2, 0, 0, 0, 0};

        std::vector<std::uint8_t> output(kN * sizeof(SyzExecResult));
        std::memcpy(output.data(), results, output.size());

        auto decoded = DecodeSyzExecResultsWithCoverage(output, kN);
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 0);
        assert(decoded.results[1].cover_count == 0);
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 3: corrupted tail(cover_offset+count 越界)── 防御性清零 ───
    {
        constexpr std::size_t kN = 1;
        SyzExecResult results[kN] = {};
        results[0] = {0, 0, 0, /*cover_offset=*/100, /*cover_count=*/50};  // 越界

        const std::uint64_t cov_tail[2] = {0xAA, 0xBB};
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        const std::size_t tail_bytes = 2 * sizeof(std::uint64_t);
        std::vector<std::uint8_t> output(head_bytes + tail_bytes);
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, cov_tail, tail_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(output, kN);
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 0);  // 越界 → 清零
        assert(decoded.results[0].cover_offset == 0);
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 4: empty output / n_calls == 0 ────────────────────────────
    {
        std::vector<std::uint8_t> empty;
        auto decoded = DecodeSyzExecResultsWithCoverage(empty, 0);
        assert(decoded.results.empty());
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 5: strict mode roundtrip(tail 严格匹配 expected)──────────
    {
        constexpr std::size_t kN = 2;
        SyzExecResult results[kN] = {};
        results[0] = {1, 0, 0, /*offset=*/0, /*count=*/2};
        results[1] = {2, 0, 0, /*offset=*/2, /*count=*/1};
        const std::uint64_t cov_tail[3] = {0xAA, 0xBB, 0xCC};
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        const std::size_t tail_bytes = 3 * sizeof(std::uint64_t);
        std::vector<std::uint8_t> output(head_bytes + tail_bytes);
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, cov_tail, tail_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/3);
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 2);
        assert(decoded.results[1].cover_count == 1);
        assert(decoded.coverage_tail.size() == 3);
        assert(decoded.coverage_tail[0] == 0xAA);
        assert(decoded.coverage_tail[2] == 0xCC);
    }

    // ── Case 6: strict mode tail 太短 — corrupted clear ─────────────────
    {
        constexpr std::size_t kN = 1;
        SyzExecResult results[kN] = {};
        results[0] = {1, 0, 0, /*offset=*/0, /*count=*/2};
        const std::uint64_t cov_tail[1] = {0xAA};  // 实际只 1 个,期望 2 个
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        const std::size_t tail_bytes = 1 * sizeof(std::uint64_t);
        std::vector<std::uint8_t> output(head_bytes + tail_bytes);
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, cov_tail, tail_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/2);
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 0);  // strict mismatch → clear
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 7: strict mode tail 太长(caller 没 peel trailing packet)── corrupted clear
    {
        constexpr std::size_t kN = 1;
        SyzExecResult results[kN] = {};
        results[0] = {1, 0, 0, /*offset=*/0, /*count=*/1};
        const std::uint64_t cov_tail[1] = {0xAA};
        // 模拟 trailing KCOV packet 字节(WorkerFeedbackHeader 16 字节 + payload)
        const std::uint8_t fake_packet[24] = {0};
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        const std::size_t tail_bytes = 1 * sizeof(std::uint64_t);
        std::vector<std::uint8_t> output(head_bytes + tail_bytes + sizeof(fake_packet));
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, cov_tail, tail_bytes);
        std::memcpy(output.data() + head_bytes + tail_bytes, fake_packet, sizeof(fake_packet));

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/1);
        assert(decoded.results.size() == kN);
        // tail_bytes (8 + 24 = 32) != expected*8 (8) — strict reject。
        assert(decoded.results[0].cover_count == 0);
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 8: strict mode expected==0 + 有 tail bytes — corrupted clear ─
    {
        constexpr std::size_t kN = 1;
        SyzExecResult results[kN] = {};
        results[0] = {1, 0, 0, 0, 0};  // 没 cov
        const std::uint64_t stray_tail[1] = {0xAA};
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        std::vector<std::uint8_t> output(head_bytes + sizeof(stray_tail));
        std::memcpy(output.data(), results, head_bytes);
        std::memcpy(output.data() + head_bytes, stray_tail, sizeof(stray_tail));

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/0);
        // tail_bytes (8) != expected*8 (0) — strict reject。
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 0);
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 9(2nd-pass review Medium fix): strict mode expected==0 +
    //   head-only output + cover_count != 0 (脏数据) — corrupted clear ─────
    // 1st-pass 实现 early-return at output.size() <= head_bytes 仅在 expected>0
    // 时 clear,这里脏 cover_count 可绕过 contract。Medium fix 把 max_end<=expected
    // 检查移到统一位置,无论 head-only/normal 路径都跑。
    {
        constexpr std::size_t kN = 1;
        SyzExecResult results[kN] = {};
        // 脏数据:声称 cover_offset=0, cover_count=5,但 output 没 tail bytes。
        results[0] = {1, 0, 0, /*cover_offset=*/0, /*cover_count=*/5};
        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        std::vector<std::uint8_t> output(head_bytes);
        std::memcpy(output.data(), results, head_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/0);
        // expected==0 但 max_end=5 — 必须 corrupted clear。
        assert(decoded.results.size() == kN);
        assert(decoded.results[0].cover_count == 0);
        assert(decoded.results[0].cover_offset == 0);
        assert(decoded.coverage_tail.empty());
    }

    // ── Case 10 [2026-05-13 P1 fix-2]: Executed flag 通过 decode 不丢
    // (driver 写 head 时 set kCallFlagExecuted|Finished,consumer 必须能在
    // round-trip 后看到原 flag,才能区分 empty_call vs real-executed-ret=0)。 ──
    {
        constexpr std::size_t kN = 4;
        SyzExecResult results[kN] = {};
        // mixed pattern 模拟 ForkingProgramExecutor partial fallback 真实输出:
        // slot[0]: 真执行 + 成功(driver dispatch 后 set Executed|Finished)
        // slot[1]: 真执行 + EACCES 失败(error 但跑过了)
        // slot[2]: 真执行 + fault inject(Executed|Finished|FaultInjected)
        // slot[3]: empty_call(driver memset 后 child SIGKILL,从未到 dispatch)
        results[0] = {/*ret=*/0,   /*err=*/0,
                      /*flags=*/kCallFlagExecuted | kCallFlagFinished, 0, 0};
        results[1] = {/*ret=*/-1,  /*err=*/13,
                      /*flags=*/kCallFlagExecuted | kCallFlagFinished, 0, 0};
        results[2] = {/*ret=*/-1,  /*err=*/12,
                      /*flags=*/kCallFlagExecuted | kCallFlagFinished |
                                kCallFlagFaultInjected, 0, 0};
        results[3] = {/*ret=*/0,   /*err=*/0,
                      /*flags=*/0, 0, 0};  // empty_call: 全零

        const std::size_t head_bytes = kN * sizeof(SyzExecResult);
        std::vector<std::uint8_t> output(head_bytes);
        std::memcpy(output.data(), results, head_bytes);

        auto decoded = DecodeSyzExecResultsWithCoverage(
            output, kN, /*expected_tail_uint64s=*/0);
        assert(decoded.results.size() == kN);
        // Executed flag round-trip 不丢
        assert((decoded.results[0].flags & kCallFlagExecuted) != 0);
        assert((decoded.results[1].flags & kCallFlagExecuted) != 0);
        assert((decoded.results[2].flags & kCallFlagExecuted) != 0);
        assert((decoded.results[3].flags & kCallFlagExecuted) == 0);
        // Finished
        assert((decoded.results[0].flags & kCallFlagFinished) != 0);
        assert((decoded.results[3].flags & kCallFlagFinished) == 0);
        // FaultInjected 只在 slot[2]
        assert((decoded.results[0].flags & kCallFlagFaultInjected) == 0);
        assert((decoded.results[2].flags & kCallFlagFaultInjected) != 0);
        // slot[3] 完全空 — 用 consumer 视角验证 "empty_call vs ret=0 success"
        // 分得开:仅看 err==0 时,slot[0] 和 slot[3] 都符合,但 Executed gate 后
        // 只有 slot[0] 真 success。
        assert(decoded.results[0].err == 0);
        assert(decoded.results[3].err == 0);
        // 这一对儿在没 flag gate 时数据上无法区分,gate 后明确分流。
    }

    return 0;
}
