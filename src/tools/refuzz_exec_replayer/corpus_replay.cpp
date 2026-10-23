#include "corpus_replay.hpp"

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/mount_image_segment.hpp"  // SegmentizeMountImages (chunk-based img)

// [speed-compare 严格 C] host-side cover 解析,复用 fuzz-loop 同一条 codec/decode
// 路径(kcov_coverage_signal.cpp:147-205),对齐 syzkaller convertCallInfo 同步成本。
#include "refuzz/feedback/coverage_semantics.hpp"            // NormalizeCoverageEntries
#include "refuzz/feedback/decode/syz_exec_result_decode.hpp" // DecodeSyzExecResultsWithCoverage
#include "refuzz/feedback/feedback_codec.hpp"                // CoverageFeedbackCodec / ParseFeedbackStatus
#include "refuzz/proto_domain/types.hpp"                     // proto::FeedbackDelta
#include "refuzz/proto_wire/feedback_wire.hpp"               // WorkerFeedbackHeader / FeedbackKind (peel loop)
#include "worker/backend/syz_exec_runner.hpp"                // SyzExecResult

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <sstream>
#include <utility>
#include <vector>

namespace refuzz::oracle::replayer {

namespace cc  = refuzz::core::channel_contract;
namespace syz = ::refuzz::program::syz;
namespace fs  = std::filesystem;

namespace {

const char* AbnormalKindName(cc::AbnormalKind k) {
    switch (k) {
        case cc::AbnormalKind::kHang:       return "hang";
        case cc::AbnormalKind::kNoResult:      return "no_result";
        case cc::AbnormalKind::kWorkerCrashed: return "worker_crashed";
        case cc::AbnormalKind::kWorkerSignaled:return "worker_signaled";
        case cc::AbnormalKind::kCancelled:     return "cancelled";
        case cc::AbnormalKind::kChildAborted:  return "child_aborted";
        case cc::AbnormalKind::kHarnessFatal:  return "harness_fatal";
        case cc::AbnormalKind::kHarnessRecovered: return "harness_recovered";
        case cc::AbnormalKind::kInfraFault:    return "infra_fault";
        case cc::AbnormalKind::kUnknown:       return "unknown";
    }
    return "unknown";
}

uint64_t NowMonoNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string ReadFile(const fs::path& p) {
    std::ifstream f(p);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Load every <corpus_dir>/<*>/payload.bin, decode via TextDecoder, re-encode
// via serialize_for_exec, return the resulting wire-byte payloads.
// kfuzztest-bearing programs surface as encode failures (serialize_for_exec
// rejects them per exec_wire.cpp:453) and are skipped — matches what the
// fuzz-loop materializer drops under StrictTyped.
//
// [speed-compare 严格 C] `n_calls` 与 `out` 并行填充:n_calls[i] = 该 payload
// 解码出的 prog 的 call 数。严格 C 的 cover 解析按 ctx.seed_id 映射回 payload
// index 取 n_calls(DecodeSyzExecResultsWithCoverage 需要),不依赖 ctx.artifact
// 是否经 channeldispatcher 回填。

std::vector<std::vector<uint8_t>> LoadCorpusPayloads(const fs::path& corpus_dir,
                                                    std::vector<uint32_t>& n_calls,
                                                    CorpusReplayStats& stats) {
    std::vector<std::vector<uint8_t>> out;
    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    // [speed-compare problem 1] Collect every payload.bin first, THEN sort by
    // the parent dir name before decoding. The on-disk layout is
    // <corpus_dir>/<hex16(seed_id)>/payload.bin (prepare_seed_master packs
    // f"{idx:016x}" over sorted(raw), seed_id 1..N) — fixed-width zero-padded
    // hex, so lexical order == numeric seed_id order. recursive_directory_iterator
    // yields entries in an unspecified (inode/hash) order, so without this sort
    // the replay sequence is filesystem-arbitrary and cannot match syz-execprog,
    // which runs strictly pos%N (execprog.go:379) over loadPrograms() = sorted
    // argv-glob order. After sorting, payloads[i] == seed_id i+1 and the submit
    // cursor loops the identical sequence as execprog.
    std::vector<fs::path> payload_paths;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(corpus_dir, ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        if (it->path().filename() != "payload.bin") continue;
        payload_paths.push_back(it->path());
    }
    std::sort(payload_paths.begin(), payload_paths.end(),
              [](const fs::path& a, const fs::path& b) {
                  // One payload.bin per <hex16> dir → parent filename is a
                  // total order; no tiebreak needed.
                  return a.parent_path().filename().string() <
                         b.parent_path().filename().string();
              });

    // [chunk-based mount image] shared SegmentizeMountImages (program/syz) runs
    // once per program here, host-side (no KASAN); same transform the fuzz-loop
    // artifact materializer uses, so replay and production share one code path.
    uint64_t seg_converted = 0;
    for (const auto& p : payload_paths) {
        stats.corpus_files_found++;

        const std::string text = ReadFile(p);
        auto decoded = dec.decode(text);
        if (!decoded) {
            stats.corpus_decode_failed++;
            continue;
        }
        seg_converted += static_cast<uint64_t>(
            syz::SegmentizeMountImages(**decoded, target));
        auto bytes = syz::serialize_for_exec(**decoded);
        if (!bytes) {
            stats.corpus_encode_failed++;
            continue;
        }
        out.push_back(std::move(*bytes));
        n_calls.push_back(static_cast<uint32_t>((**decoded).calls().size()));
    }
    stats.corpus_payloads_ready = out.size();
    std::fprintf(stderr,
        "corpus-replay: chunk-based mount images: %llu syz_mount_image/"
        "read_part_table args converted to SEGS (zlib decompress moved off the "
        "guest exec path)\n",
        (unsigned long long)seg_converted);
    return out;
}

}  // namespace

bool RunCorpusReplay(refuzz::channel::IChannel& channel,
                     const CorpusReplayConfig& cfg,
                     CorpusReplayStats& stats) {
    std::vector<uint32_t> n_calls;
    auto payloads = LoadCorpusPayloads(cfg.corpus_dir, n_calls, stats);
    std::fprintf(stderr,
        "corpus-replay: prepped payloads from %s — found=%llu decode_failed=%llu "
        "encode_failed=%llu ready=%llu\n",
        cfg.corpus_dir.c_str(),
        (unsigned long long)stats.corpus_files_found,
        (unsigned long long)stats.corpus_decode_failed,
        (unsigned long long)stats.corpus_encode_failed,
        (unsigned long long)stats.corpus_payloads_ready);
    if (payloads.empty()) {
        std::fprintf(stderr,
            "corpus-replay: no usable programs after decode+encode; aborting.\n");
        return false;
    }

    uint64_t inflight = 0;

    // [speed-compare 严格 C] cover 解析所需:codec(剥 KCOV packet)+ normalization
    // config 与 fuzz-loop 一致(raw_pc 默认 true)。kNone 模式下不构造/不调用。
    const bool parse_cover =
        cfg.collect_cover_mode == CorpusReplayConfig::CollectCoverMode::kKcovPc;
    refuzz::fuzzer::CoverageFeedbackCodec cover_codec{};

    // 解析单个 completion 的 worker output —— 复刻 kcov_coverage_signal.cpp:147-205
    // 的同步前半段(codec.Extract → strict DecodeSyzExecResultsWithCoverage →
    // 逐 call NormalizeCoverageEntries),对齐 syzkaller convertCallInfo。
    // 失败(malformed / 结果数不符)只计 cover_decode_failed,不影响 completion 计数。
    auto parse_completion_cover = [&](const cc::Completion& comp) {
        stats.output_bytes += comp.output.size();
        const uint64_t idx = comp.ctx.seed_id - 1;  // submit 时 seed_id = cursor+1
        if (comp.ctx.seed_id == 0 || idx >= n_calls.size()) {
            ++stats.cover_decode_failed;
            return;
        }
        const std::size_t nc = n_calls[idx];
        if (nc == 0 || comp.output.empty()) return;

        std::vector<uint8_t> payload = comp.output;  // peel mutates → copy

        // [remote-kcov S3] Peel ALL trailing WorkerFeedbackHeader packets from
        // the tail before decoding the per-call cover. PC-mode layout:
        //   [SyzExecResult × nc][uint64 per-call cover tail]
        //      [kCoverageKcov extra remote cover]?   (KcovSink S2, program-level)
        // The extra-remote-cover packet (Gap-1 net/softirq/kthread cover, now
        // captured via KCOV_REMOTE_ENABLE) sits at the tail. Walk from the
        // tail handling each kind, stopping when no valid header remains (=
        // reached the raw per-call cover tail). The real fuzz loop does the
        // equivalent (codec.Extract); doing it here
        // hands the per-call decoder a clean [heads][per-call tail] residual AND
        // merges the program-level remote cover into the PC union.
        for (;;) {
            if (payload.size() < sizeof(refuzz::proto::WorkerFeedbackHeader)) break;
            refuzz::proto::WorkerFeedbackHeader hdr{};
            std::memcpy(&hdr,
                        payload.data() + payload.size() - sizeof(hdr),
                        sizeof(hdr));
            if (hdr.magic != refuzz::proto::kWorkerFeedbackMagic ||
                hdr.version != refuzz::proto::kWorkerFeedbackVersion) {
                break;  // raw per-call tail (no header) — done peeling
            }
            const auto kind = static_cast<refuzz::proto::FeedbackKind>(hdr.kind);
            if (kind == refuzz::proto::FeedbackKind::kCoverageKcov) {
                // Program-level extra remote cover. Extract normalizes (same
                // codec config as per-call) + resizes the packet off.
                refuzz::proto::FeedbackDelta delta;
                const auto st = cover_codec.Extract(&payload, &delta);
                if (st != refuzz::fuzzer::ParseFeedbackStatus::kOk) {
                    if (st == refuzz::fuzzer::ParseFeedbackStatus::kMalformed) {
                        ++stats.cover_decode_failed;
                    }
                    break;
                }
                if (!delta.cov_hashes.empty()) {
                    stats.total_cover_entries += delta.cov_hashes.size();
                    if (cfg.collect_pc_set) {
                        for (std::uint64_t pc : delta.cov_hashes)
                            stats.corpus_pc_union.insert(pc);
                    }
                }
            } else if (kind == refuzz::proto::FeedbackKind::kCoverageKcovCmp) {
                const std::size_t cmp_bytes =
                    static_cast<std::size_t>(hdr.entry_count) * 4u * sizeof(std::uint64_t);
                if (payload.size() < sizeof(hdr) + cmp_bytes) break;
                payload.resize(payload.size() - sizeof(hdr) - cmp_bytes);
            } else {
                break;  // unknown kind — leave it, lenient decode ignores tail
            }
        }

        // LENIENT decode of the residual per-call [heads][per-call tail]. The
        // worker's per-call cover_offset/cover_count are authoritative; lenient
        // mode trusts them and still guards OOB (max_end <= tail_uint64s). After
        // the peel loop the residual is normally exactly [heads][per-call tail],
        // but lenient stays robust if any unhandled trailing packet remains.
        auto dec = refuzz::feedback::decode::DecodeSyzExecResultsWithCoverage(
            std::span<const std::uint8_t>(payload.data(), payload.size()),
            nc, std::nullopt);
        if (dec.results.size() != nc) {
            ++stats.cover_decode_failed;
            return;
        }
        for (std::size_t i = 0; i < nc; ++i) {
            const auto& r = dec.results[i];
            const std::size_t end = static_cast<std::size_t>(r.cover_offset) +
                                    static_cast<std::size_t>(r.cover_count);
            std::vector<std::uint64_t> raw_slice;
            if (r.cover_count > 0 && end <= dec.coverage_tail.size()) {
                raw_slice.assign(dec.coverage_tail.begin() + r.cover_offset,
                                 dec.coverage_tail.begin() + end);
            }
            // 与 fuzz-loop 同 normalization → 同步成本对齐(canonicalize/dedup)。
            auto norm = refuzz::fuzzer::NormalizeCoverageEntries(std::move(raw_slice),
                                                                 cover_codec.config());
            if (!norm.empty()) {
                stats.total_cover_entries += norm.size();
                ++stats.calls_with_cover;
                // [PC-set 对比] 并入 corpus PC union(原始 KCOV PC;下游按 instr_len
                // 平移对齐 syz PreviousInstructionPC 空间)。仅 -dump-pc-set 时维护。
                if (cfg.collect_pc_set) {
                    for (std::uint64_t pc : norm) stats.corpus_pc_union.insert(pc);
                }
            }
        }
    };

    // [speed-compare problem 2] Count ACTUALLY-executed calls (not nominal).
    // The worker ALWAYS returns a fixed head of n_calls SyzExecResult at output
    // front (kernel_wire_driver.cpp:793,1176; output_len >= head_bytes even on
    // early child exit, :1132-1138) — unexecuted calls stay zero-init ==
    // upstream empty_call, byte-identical to syzkaller. A call that ran has
    // kCallFlagExecuted set (driver:1038); flags==0 never executed (early return
    // / hang / partial, program_runtime.cpp:1083). Crediting a completed program
    // its full nominal call count over-counts when it returns early — worst
    // during a hang, where wall time is burned but few calls ran. Same bit as
    // syzkaller's CallFlagExecuted gate (execprog.go:302). Always-on for B and C;
    // syzkaller decodes per-call flags in both arms too, so this is parity-faithful.
    auto tally_executed_calls = [&](const cc::Completion& comp) {
        const uint64_t idx = comp.ctx.seed_id - 1;  // submit set seed_id = cursor+1
        if (comp.ctx.seed_id == 0 || idx >= n_calls.size()) return;
        const std::size_t nc = n_calls[idx];
        if (nc == 0) return;
        const std::size_t head_bytes = nc * sizeof(refuzz::worker::SyzExecResult);
        // Fixed-head invariant guarantees output >= head_bytes; pure OOB safety,
        // not expected to fire.
        if (comp.output.size() < head_bytes) return;
        stats.nominal_syz_calls += nc;
        for (std::size_t i = 0; i < nc; ++i) {
            refuzz::worker::SyzExecResult r{};
            std::memcpy(&r, comp.output.data() + i * sizeof(r), sizeof(r));
            if (r.flags & refuzz::worker::kCallFlagExecuted) ++stats.executed_syz_calls;
        }
    };

    // [speed-compare 窗口对齐] Measurement window anchored at the FIRST
    // completion, length = cfg.duration (mirrors syz-execprog -run_seconds).
    // window_*_ns are set inside drain() on the first completion and read by the
    // submit loop to decide when to stop. Completions are counted toward the
    // numerator only while now <= window_end_ns; later (drain) completions are
    // diagnostic. This makes reFuzz's wall == syz's wall (both = duration,
    // ramp/drain excluded).
    const uint64_t window_ns = (uint64_t)cfg.duration.count() * 1'000'000'000ULL;
    uint64_t window_start_ns = 0;
    uint64_t window_end_ns   = 0;

    // [full-pass口径] When corpus_passes>0 the numerator is anchored on
    // COMPLETION COUNT, not a wall window: count exactly `target_completions`
    // completions (= passes × corpus size) and report wall = last_completion −
    // first_completion. last_completion_ns is updated on every counted
    // completion; window_start_ns still marks the first completion (boot ramp
    // excluded). See CorpusReplayConfig::corpus_passes.
    const bool     pass_mode          = cfg.corpus_passes > 0;
    const uint64_t target_completions =
        pass_mode ? (uint64_t)cfg.corpus_passes * payloads.size() : 0;
    uint64_t last_completion_ns = 0;

    // [heap churn 减少 2026-05-22] EventList 提到 drain 外层复用 — 之前
    // 每次 drain() lambda 调用都 heap alloc 64-entry vector. Submit loop
    // 每 program 至少 drain 一次, 这是 host-side hot path heap churn 大头.
    // events.clear() 保留 capacity, 后续 DrainEvents resize 不重新 alloc.
    refuzz::channel::EventList events;
    events.reserve(64);

    auto drain = [&](std::chrono::microseconds wait) {
        events.clear();
        if (!channel.DrainEvents(events, wait)) return;
        for (const auto& e : events) {
            switch (e.kind) {
                case cc::ChannelEvent::Kind::kCompletion:
                    if (const auto* comp = e.AsCompletion()) {
                        const uint64_t now = NowMonoNs();
                        // Anchor the window at the first completion (= worker
                        // warmed up; excludes the boot/sandbox/device_init ramp).
                        if (window_start_ns == 0) {
                            window_start_ns = now;
                            window_end_ns   = now + window_ns;
                        }
                        // pass mode: count until target_completions reached;
                        // window mode: count while inside the wall window.
                        const bool counts = pass_mode
                            ? (stats.window_completions < target_completions)
                            : (now <= window_end_ns);
                        if (counts) {
                            // Counts toward throughput. Parse cover + tally
                            // executed here so their host cost lands inside the
                            // measured span (aligns with execprog convertCallInfo).
                            ++stats.window_completions;
                            last_completion_ns = now;  // pass-mode wall endpoint
                            tally_executed_calls(*comp);
                            if (parse_cover) parse_completion_cover(*comp);
                        } else {
                            // Past the window / target → diagnostic only.
                            ++stats.drain_completions;
                        }
                    }
                    stats.completions++;  // total (diagnostic)
                    if (inflight > 0) --inflight;
                    break;
                case cc::ChannelEvent::Kind::kAbnormal:
                    stats.abnormal++;
                    // Identify WHICH program went abnormal and WHY. kind tells
                    // tool-bug (worker_crashed/signaled) apart from slow-program
                    // (timeout) vs protocol (child_aborted/exec_error). seed_id
                    // maps back to the sorted corpus (corpus/refuzz/<hex16>).
                    if (const auto* ab = e.AsAbnormal()) {
                        std::fprintf(stderr,
                            "corpus-replay: ABNORMAL seed_id=%llu kind=%s\n",
                            (unsigned long long)ab->ctx.seed_id,
                            AbnormalKindName(ab->kind));
                    }
                    if (inflight > 0) --inflight;
                    break;
                case cc::ChannelEvent::Kind::kFault:
                    stats.faults++;
                    // Fault is per-incident, not per-inflight — do not
                    // decrement inflight or completions will overcount.
                    break;
            }
        }
    };

    std::atomic<uint64_t> next_executor_id{1};
    const uint64_t submit_start_ns = NowMonoNs();
    // Safety cap on the pre-window ramp: the window opens on the first
    // completion, but if none ever arrives (dead worker) we must not submit
    // forever. NOTE (2026-05-28): Boot() returns once the channel transport is
    // up, but the worker still finishes sandbox/device_init before it can
    // execute — on a heavy KASAN guest that occasionally takes ~70s (vs ~25s
    // typical, host-contention dependent). A 60s cap lost that race and reported
    // 0 completions / "worker_crashed" on a perfectly HEALTHY worker. Raised to
    // 300s (the harness start_timeout is far larger still).
    const uint64_t ramp_cap_ns = submit_start_ns + 300ULL * 1'000'000'000ULL;
    size_t cursor = 0;

    // [heap churn 减少 2026-05-22] ChannelDispatchRequest 提到 loop 外复用 —
    // vector::operator= 会 reuse 上次的 capacity (no realloc if 上次 cap ≥
    // 新 size), 减 per-iter alloc/dealloc round trip. trace/scalar fields
    // 每 iter 重赋值无问题。注意:channel.Submit() 内部 deep-copy req 到 slot,
    // caller 的 req 不被 take ownership, 复用 safe.
    cc::ChannelDispatchRequest req{};
    for (;;) {
        // Ramp until the first completion opens the window, then keep submitting
        // (cycling the corpus) until the stop condition. drain() (below + in the
        // kBusy path) sets window_*_ns / window_completions.
        const uint64_t now = NowMonoNs();
        if (pass_mode) {
            // Stop once the target completion count is reached. Safety nets:
            //   - ramp cap guards a worker that never produces a completion;
            //   - window_end_ns (= first_completion + cfg.duration) is a hard
            //     wall cap so a worker that dies MID-pass can't spin forever
            //     (the caller sets duration generously as this backstop; a pass
            //     cut short here lands window_completions < target_completions,
            //     which the wrapper flags as an incomplete pass).
            if (stats.window_completions >= target_completions) break;
            if (window_start_ns == 0 && now >= ramp_cap_ns) break;
            if (window_start_ns != 0 && now >= window_end_ns) break;
        } else if (window_start_ns == 0) {
            if (now >= ramp_cap_ns) break;       // never completed → bail
        } else if (now >= window_end_ns) {
            break;                                // window closed → stop submitting
        }
        req.executor_id      = next_executor_id.fetch_add(1, std::memory_order_relaxed);
        req.seed_id          = cursor + 1;
        req.origin_seed_id   = req.seed_id;
        req.payload          = payloads[cursor];
        req.timeout_ms       = static_cast<uint32_t>(cfg.per_request_timeout.count());
        req.exec_flags       = cfg.exec_flags;
        req.target_worker_id = cc::kAnyWorkerId;
        // cursor advance moved to success path (after Accept) so retry refill
        // 仍读当前 cursor 的 payload.

        for (;;) {
            // [submit path heap churn 减少 2026-05-22] std::move(req) 走
            // Channel::Submit(&&) rvalue overload, 内部直接 std::move 进
            // SubmitSlot, 省一次 deep payload copy. retry 时 req 已 moved-from
            // (payload 空), 需重 fill 然后再 submit.
            auto r = channel.Submit(std::move(req), cfg.submit_wait_for_slot);
            if (r.status == cc::ChannelSubmitStatus::kAccepted) {
                ++stats.submissions_accepted;
                ++inflight;
                cursor = (cursor + 1) % payloads.size();
                break;
            }
            if (r.status == cc::ChannelSubmitStatus::kBusy) {
                // Channel full — drain pump to free a slot, then retry.
                drain(std::chrono::milliseconds(1));
                req.payload = payloads[cursor];
                continue;
            }
            // kUnavailable / kInvalid — drop and move on. With
            // target_worker_id = kAnyWorkerId this should not normally
            // happen, so count it as a hard reject for diagnosis.
            cursor = (cursor + 1) % payloads.size();
            ++stats.submissions_rejected;
            break;
        }
        // Opportunistic non-blocking drain between submits.
        drain(cfg.drain_idle_wait);
    }

    // Final drain — clear in-flight up to the configured budget. These
    // completions land AFTER window_end_ns, so the kCompletion handler counts
    // them as drain_completions (diagnostic), never in the numerator.
    const uint64_t drain_deadline_ns =
        NowMonoNs() + (uint64_t)cfg.final_drain_budget.count() * 1'000'000'000ULL;
    while (inflight > 0 && NowMonoNs() < drain_deadline_ns) {
        drain(std::chrono::milliseconds(50));
    }
    stats.drain_inflight_at_end = inflight;

    // wall:
    //   pass mode  → last_completion − first_completion, the ACTUAL span over
    //                which `target_completions` programs completed (= the doc's
    //                整趟 wall; immune to time-window sampling). 0 if <2
    //                completions arrived.
    //   window mode→ the fixed window length (= duration), anchored at first
    //                completion; excludes submit/boot ramp and post-window drain.
    // Both exclude the boot ramp by anchoring at the first completion. 0 →
    // programs_per_sec 0, run flagged.
    if (pass_mode) {
        stats.wall_ns = (window_start_ns != 0 && last_completion_ns > window_start_ns)
            ? (last_completion_ns - window_start_ns)
            : 0;
    } else {
        stats.wall_ns = (window_start_ns != 0) ? window_ns : 0;
    }

    if (pass_mode) {
        std::fprintf(stderr,
            "corpus-replay: PASS MODE passes=%u corpus=%zu target_completions=%llu "
            "reached=%llu wall_s=%.3f\n",
            cfg.corpus_passes, payloads.size(),
            (unsigned long long)target_completions,
            (unsigned long long)stats.window_completions,
            stats.wall_ns / 1e9);
    }
    std::fprintf(stderr,
        "corpus-replay: window=%llds accepted=%llu rejected=%llu "
        "window_completions=%llu drain_completions=%llu completions_total=%llu "
        "abnormal=%llu faults=%llu inflight_at_end=%llu wall_ns=%llu\n",
        (long long)cfg.duration.count(),
        (unsigned long long)stats.submissions_accepted,
        (unsigned long long)stats.submissions_rejected,
        (unsigned long long)stats.window_completions,
        (unsigned long long)stats.drain_completions,
        (unsigned long long)stats.completions,
        (unsigned long long)stats.abnormal,
        (unsigned long long)stats.faults,
        (unsigned long long)stats.drain_inflight_at_end,
        (unsigned long long)stats.wall_ns);
    std::fprintf(stderr,
        "corpus-replay: syz_calls(in-window) executed=%llu nominal=%llu\n",
        (unsigned long long)stats.executed_syz_calls,
        (unsigned long long)stats.nominal_syz_calls);
    if (parse_cover) {
        std::fprintf(stderr,
            "corpus-replay: cover(strict-C) output_bytes=%llu total_cover_entries=%llu "
            "calls_with_cover=%llu cover_decode_failed=%llu\n",
            (unsigned long long)stats.output_bytes,
            (unsigned long long)stats.total_cover_entries,
            (unsigned long long)stats.calls_with_cover,
            (unsigned long long)stats.cover_decode_failed);
    }
    return true;
}

bool RunCorpusDecodeCheck(const fs::path& corpus_dir, CorpusDecodeCheckStats& stats) {
    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    // Same collect + seed-id sort as LoadCorpusPayloads, so the reported order
    // matches the replay order.
    std::vector<fs::path> payload_paths;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(corpus_dir, ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        if (it->path().filename() != "payload.bin") continue;
        payload_paths.push_back(it->path());
    }
    std::sort(payload_paths.begin(), payload_paths.end(),
              [](const fs::path& a, const fs::path& b) {
                  return a.parent_path().filename().string() <
                         b.parent_path().filename().string();
              });

    for (const auto& p : payload_paths) {
        ++stats.found;
        const std::string text = ReadFile(p);
        auto decoded = dec.decode(text);
        if (!decoded) {
            ++stats.decode_failed;
            stats.decode_failed_paths.push_back(
                p.parent_path().filename().string() + ": " + decoded.error().message);
            continue;
        }
        auto bytes = syz::serialize_for_exec(**decoded);
        if (!bytes) {
            ++stats.encode_failed;
            stats.encode_failed_paths.push_back(p.parent_path().filename().string());
            continue;
        }
        ++stats.decoded_ok;
    }
    return stats.decode_failed == 0 && stats.encode_failed == 0;
}

}  // namespace refuzz::oracle::replayer
