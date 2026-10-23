// Corpus-replay mode for refuzz-exec-replayer (对比 3 / replay scenario).
//
// Unlike the flatrpc-trace replay path (replayer.{hpp,cpp}), corpus replay
// reads a directory of syz-prog text payloads laid out as
// `<corpus-dir>/<hex>/payload.bin` — the same on-disk shape
// `CorpusDiskIO::LoadAll` consumes for fuzz-loop corpus loading — and
// decodes each into a Prog via the v2 TextDecoder + serialize_for_exec
// pipeline before submitting raw wire bytes into the channel.
//
// Goal: measure raw per-program execute throughput with fuzzer logic
// (mutation / generation / coverage feedback shaping) stripped out, so the
// "fork-child execute" cost is isolated from the rest of the fuzz loop.
//
// The output of CorpusReplayStats is what the bench wrapper (replay
// scenario in scripts/bench_single_worker_compare.py) reads to compute
// programs/sec.

#pragma once

#include "refuzz/channel/channel.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::oracle::replayer {

struct CorpusReplayConfig {
    std::filesystem::path corpus_dir;

    // Measurement window. Submission loop stops once steady_clock has
    // advanced this far past Run() entry; a final drain (bounded by
    // final_drain_budget) collects in-flight completions after the window
    // closes. IGNORED when corpus_passes > 0 (pass mode below).
    std::chrono::seconds duration{60};

    // [full-pass口径] When > 0, measure by COMPLETION COUNT instead of a wall
    // window: keep submitting (cycling the fixed corpus) until
    // `corpus_passes × payloads.size()` programs have COMPLETED, then report
    // wall = last_completion − first_completion (the actual steady-state span,
    // boot ramp excluded by anchoring at the first completion). This is the
    // doc's stable口径 (docs/speed_compare_BCD.md #5): syscall/sec = executed
    // calls / 整趟 wall, immune to the double-peak corpus's window-sampling
    // distortion (which order/which sub-window a fixed time slice happens to
    // land on). 0 = legacy duration window.
    uint32_t corpus_passes = 0;

    // ChannelDispatchRequest.timeout_ms — per-program wall budget the
    // worker side enforces. Pick to match the bench's exec_timeout_ms.
    std::chrono::milliseconds per_request_timeout{5000};

    // Wire-side ChannelDispatchRequest.exec_flags. Caller selects the
    // TASK_FLAG_INTRA_* / TASK_FLAG_SHAPE_* / TASK_FLAG_COLLECT_COMPS bits
    // (see proto/wire/include/refuzz/proto_wire/ivshmem_protocol.h).
    // Bench default mirrors fuzz_loop: TASK_FLAG_INTRA_THREADED |
    // TASK_FLAG_SHAPE_SINGLE.
    uint32_t exec_flags = 0;

    // Single Submit() wait when channel is busy; fall through to a drain
    // pump if still kBusy.
    std::chrono::microseconds submit_wait_for_slot{1000};

    // Non-blocking drain poll cadence used between accepted submits.
    std::chrono::microseconds drain_idle_wait{0};

    // After the measurement window closes, how long to wait for inflight
    // completions to drain before declaring the rest lost.
    std::chrono::seconds final_drain_budget{30};

    // [speed-compare 严格 C] host-side coverage 解析模式。决定 drain 完成路径里
    // 是否同步解析 worker output —— 对齐 syzkaller -cover=1 的 convertCallInfo,
    // 它在 request completion 同步路径里跑、计入 executed-programs 节奏。
    //   kNone   : 只数 completion(= C-prelim 现状; worker 仍恒采 cover,但 host
    //             不碰 output → 少算一截 host 解析开销)。
    //   kKcovPc : 同步剥 KCOV packet + DecodeSyzExecResultsWithCoverage(strict)
    //             + 逐 call NormalizeCoverageEntries(= 严格 C; 对齐 execprog
    //             convertCallInfo 的 decode+canonicalize 层,不含 fuzzer 侧
    //             signal-store/priority/saturation —— 那是 D/processResult)。
    enum class CollectCoverMode { kNone, kKcovPc };
    CollectCoverMode collect_cover_mode = CollectCoverMode::kNone;

    // [PC-set 对比] true 时 RunCorpusReplay 把 in-window 完成的 normalized cover PC
    // 并入 CorpusReplayStats::corpus_pc_union(供 -dump-pc-set 落盘)。默认 false →
    // 纯吞吐 kKcovPc run 不付 union 维护成本。需 collect_cover_mode==kKcovPc 才有数据。
    bool collect_pc_set = false;
};

struct CorpusReplayStats {
    // Corpus prep — populated before the measurement window starts.
    uint64_t corpus_files_found    = 0;
    uint64_t corpus_decode_failed  = 0;
    uint64_t corpus_encode_failed  = 0;
    uint64_t corpus_payloads_ready = 0;

    // In-window counts.
    uint64_t submissions_accepted = 0;
    uint64_t submissions_rejected = 0;
    uint64_t completions          = 0;  // TOTAL completions seen (diagnostic)
    uint64_t abnormal             = 0;
    uint64_t faults               = 0;

    // [speed-compare 窗口对齐] The measurement window is anchored at the FIRST
    // completion and runs `duration` seconds (mirrors syz-execprog -run_seconds,
    // whose timer arms on first completion). Only completions that land inside
    // the window feed the throughput numerator; completions collected during the
    // post-window drain are diagnostic and do NOT count. wall_ns is the window
    // length (= duration), excluding both the pre-first-completion submit/boot
    // ramp and the post-window drain — so reFuzz and syz measure the same span.
    uint64_t window_completions = 0;  // completions in [first_completion, +duration] — numerator
    uint64_t drain_completions  = 0;  // completions after the window closed — diagnostic only

    // Post-window drain counts (counted into completions/abnormal/faults
    // above as they arrive; drain_inflight_at_end records how many were
    // still unaccounted for when the drain budget expired).
    uint64_t drain_inflight_at_end = 0;

    // Wallclock from first Submit attempt to drain-budget exhaustion.
    uint64_t wall_ns = 0;

    // [speed-compare problem 2] Per-call executed accounting (always filled,
    // both B and C). The worker ALWAYS returns a fixed head of n_calls
    // SyzExecResult (kernel_wire_driver.cpp:793,1176; output_len >= head_bytes
    // even on early child exit, :1132-1138) — unexecuted calls stay zero-init
    // == upstream empty_call, byte-identical to syzkaller. Each call that ran
    // has kCallFlagExecuted set; `executed` counts those. Crediting a completed
    // program its full NOMINAL call count over-counts when it returns early
    // (hang/timeout/partial), so `executed` is the throughput numerator.
    // `nominal` (Σ n_calls of completed programs) is kept for cross-check + the
    // syzkaller side (which only exposes program counts). Both are reference
    // counts, not a screening gate.
    uint64_t nominal_syz_calls  = 0;
    uint64_t executed_syz_calls = 0;

    // [speed-compare 严格 C] collect_cover_mode==kKcovPc 时填充。证明 reFuzz
    // 实际解析了 worker 产出的 cover(而非丢弃),并让 host 解析成本计入吞吐。
    uint64_t output_bytes        = 0;  // Σ completion.output.size()(含被解析的 cover tail)
    uint64_t total_cover_entries = 0;  // Σ 逐 call NormalizeCoverageEntries 后的 PC 条数
    uint64_t calls_with_cover    = 0;  // cover_count>0 的 call 数
    uint64_t cover_decode_failed = 0;  // codec kMalformed / decode result 数不符 n_calls

    // [PC-set 对比] collect_pc_set 时填充:in-window 完成的 normalized cover PC 并集
    // (raw_pc=true → 原始 KCOV PC)。main.cpp -dump-pc-set 排序后写 0x%x/line。
    std::unordered_set<std::uint64_t> corpus_pc_union;
};

// Runs the corpus replay. Returns false if the corpus dir has no usable
// programs (decode/encode_failed counts populated for diagnosis); returns
// true otherwise — the caller inspects `stats` to decide whether the run
// was healthy.
//
// Caller must Boot() the channel before calling Run() and Close() it after.
bool RunCorpusReplay(refuzz::channel::IChannel& channel,
                     const CorpusReplayConfig& cfg,
                     CorpusReplayStats& stats);

// [speed-compare 解码自检] Standalone decodability test — NO VM, NO channel.
struct CorpusDecodeCheckStats {
    uint64_t found         = 0;
    uint64_t decoded_ok    = 0;  // TextDecoder.decode + serialize_for_exec both OK
    uint64_t decode_failed = 0;  // TextDecoder rejected the program text
    uint64_t encode_failed = 0;  // decoded but serialize_for_exec rejected (eg. kfuzztest)
    std::vector<std::string> decode_failed_paths;  // "<seed-id-dir>: <decode error>"
    std::vector<std::string> encode_failed_paths;  // "<seed-id-dir>"
};

// Decode EVERY <corpus_dir>/*/payload.bin via the SAME path the replayer uses
// (TextDecoder + serialize_for_exec) and report which programs reFuzz cannot
// decode/encode. Returns true iff all programs decoded AND encoded. This is a
// pre-run HEALTH CHECK for reFuzz's decoder — failures mean a reFuzz bug to
// investigate, NOT a reason to filter the corpus before a run.
bool RunCorpusDecodeCheck(const std::filesystem::path& corpus_dir,
                          CorpusDecodeCheckStats& stats);

}  // namespace refuzz::oracle::replayer
