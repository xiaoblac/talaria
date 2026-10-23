// refuzz_exec_replayer — V2 production-exec paired oracle PR3 (replayer).
//
// Reads exec_trace_*.bin files produced by syz_flatrpc_proxy and submits
// each captured ExecRequest into a reFuzz IChannel, recording outcomes to
// ref_result.bin. Backend selection:
//   -backend=echo                in-process echo IChannel (offline smoke;
//                                no QEMU; output==payload)
//   -backend=qemu_ivshmem_linux  real Channel built via ChannelCatalog;
//                                needs -config <phase5-shaped JSON> and a
//                                running-capable kernel/image
//
// See docs/plans/production-exec-paired-oracle.md §6.

#include "corpus_replay.hpp"
#include "echo_channel.hpp"
#include "ref_result_writer.hpp"
#include "replayer.hpp"

#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "refuzz/config_parser/parse_config_from_json.hpp"
#include "refuzz/orchestrator/orchestrator_config.hpp"

#include "util/json.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

void Usage(const char* prog) {
    std::fprintf(stderr,
        "usage:\n"
        "  trace replay (paired oracle):\n"
        "    %s -trace-dir <dir> -output <ref_result.bin>\n"
        "       [-backend echo|qemu_ivshmem_linux] [-config <json>]\n"
        "       [-git-rev <40hex>] [-per-request-timeout-ms N]\n"
        "       [-session-drain-budget-s N] [-pace none|trace] [-no-boot]\n"
        "       [-perf-ready-file <path> -perf-release-file <path>]\n"
        "       [-hold-after-drain-s N] [-hold-release-file <path>]\n"
        "       [-allow-truncated-tail]\n\n"
        "  corpus replay (raw execute throughput / bench replay scenario):\n"
        "    %s -corpus-dir <dir> -duration-s N\n"
        "       -backend qemu_ivshmem_linux -config <json>\n"
        "       [-per-request-timeout-ms N] [-stats-out <path>]\n"
        "       [-collect-cover-mode none|kcov-pc]\n\n"
        "  -backend=echo (default)                no VM; output is the\n"
        "                                          submitted payload echoed back\n"
        "  -backend=qemu_ivshmem_linux            real Channel via\n"
        "                                          ChannelCatalog; requires\n"
        "                                          -config pointing at a\n"
        "                                          phase5-shaped JSON\n"
        "  -corpus-dir <dir>                      a directory of\n"
        "                                          <hex>/payload.bin syz-prog\n"
        "                                          text files (the layout\n"
        "                                          CorpusDiskIO::LoadAll reads).\n"
        "                                          Mutually exclusive with\n"
        "                                          -trace-dir.\n"
        "  -duration-s N                          corpus replay measurement\n"
        "                                          window in seconds (required\n"
        "                                          when -corpus-dir is set).\n"
        "  -stats-out <path>                      corpus replay: write final\n"
        "                                          stats JSON to <path>\n"
        "                                          (consumed by bench script).\n"
        "  -collect-cover-mode none|kcov-pc       corpus replay: kcov-pc 在\n"
        "                                          completion 同步路径解析 worker\n"
        "                                          cover output(对齐 syzkaller\n"
        "                                          -cover=1 convertCallInfo 成本,\n"
        "                                          = 严格 C);none(默认)=C-prelim。\n"
        "  -dump-pc-set <path>                    corpus replay: write in-window\n"
        "                                          cover PC union (raw KCOV PC,\n"
        "                                          0x<hex>/line) to <path>; needs\n"
        "                                          -collect-cover-mode kcov-pc.\n",
        prog, prog);
}

const char* GetArg(int argc, char** argv, const char* flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return nullptr;
}

// Build a real Channel from a phase5-shaped JSON config. Returns nullptr
// on any parse/build failure; details emitted to stderr. Out-param
// out_n_workers receives the channel's worker slot count for diagnostics.
std::unique_ptr<refuzz::channel::IChannel> BuildQemuChannelFromConfig(
    const std::string& config_path,
    std::filesystem::path& out_vm_workdir,
    uint32_t& out_n_workers) {
    std::ifstream f(config_path);
    if (!f) {
        std::fprintf(stderr, "refuzz_exec_replayer: cannot open config %s\n",
                     config_path.c_str());
        return nullptr;
    }
    nlohmann::json root;
    try {
        f >> root;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "refuzz_exec_replayer: bad config JSON: %s\n", e.what());
        return nullptr;
    }

    refuzz::orchestrator::OrchestratorConfig oconfig;
    if (!refuzz::orchestrator::ParseConfigFromJson(root, oconfig)) {
        std::fprintf(stderr,
            "refuzz_exec_replayer: ParseConfigFromJson failed; config must "
            "be phase5-shaped (channel + executor + fuzzer + telemetry + "
            "coverage + target + persistence + repro blocks all present). "
            "See configs/phase5_sample_config.json for the canonical layout.\n");
        return nullptr;
    }
    if (oconfig.channel_backend == nullptr) {
        std::fprintf(stderr, "refuzz_exec_replayer: channel_backend not set\n");
        return nullptr;
    }
    if (oconfig.channel_backend_id != "qemu_ivshmem_linux") {
        std::fprintf(stderr,
            "refuzz_exec_replayer: backend_id mismatch (config=%s, cli=qemu_ivshmem_linux). "
            "Set top-level channel_backend_id=\"qemu_ivshmem_linux\" in your config.\n",
            oconfig.channel_backend_id.c_str());
        return nullptr;
    }

    refuzz::channel::ChannelConfig channel_cfg = oconfig.channel_common;
    if (channel_cfg.channel_id == 0) channel_cfg.channel_id = 1;
    channel_cfg.use = refuzz::channel::ChannelUse::kFuzz;
    out_n_workers = channel_cfg.n_workers;

    // Put the (single) VM's runtime + logs DIRECTLY under config.work_dir — no
    // "vm-N" layer. The benchmark gives each run its own unique directory and
    // there is only ever one VM here, so an extra index layer just scatters
    // logs and lengthens paths. The latter matters: QEMU UNIX socket paths
    // (e.g. <vm_workdir>/serial.sock) must be < 108 bytes, and a deep
    // work_dir/vm-0/ easily overflows that — flat keeps us under the limit.
    std::filesystem::path base = oconfig.work_dir.empty()
        ? std::filesystem::temp_directory_path()
        : std::filesystem::path(oconfig.work_dir);
    out_vm_workdir = base;
    std::error_code ec;
    std::filesystem::create_directories(out_vm_workdir, ec);
    if (ec) {
        std::fprintf(stderr, "refuzz_exec_replayer: mkdir vm_workdir %s: %s\n",
                     out_vm_workdir.string().c_str(), ec.message().c_str());
        return nullptr;
    }

    // ParseConfigFromJson always nests a transient session dir
    // <work_dir>/run-<ts>-<pid>/ (logs/ diagnostics/) via MakeSessionLayout.
    // The replayer never uses that session tree (it drives the channel straight
    // from oconfig.channel_common + ctx.vm_workdir), so the freshly-created dir
    // is pure scatter inside the benchmark's run folder. Drop it and keep
    // everything flat under work_dir.
    if (!oconfig.layout.root.empty()) {
        std::filesystem::path layout_root(oconfig.layout.root);
        if (layout_root != base && layout_root.parent_path() == base &&
            layout_root.filename().string().rfind("run-", 0) == 0) {
            std::error_code rec;
            std::filesystem::remove_all(layout_root, rec);
        }
    }

    refuzz::channel::ChannelBuildContext ctx;
    ctx.channel_cfg     = channel_cfg;
    ctx.backend_profile = oconfig.channel_backend.get();
    ctx.vm_index        = 0;
    ctx.vm_workdir      = out_vm_workdir.string();

    refuzz::channel::ChannelCatalog catalog;
    refuzz::channel::RegisterBuiltinChannels(catalog);
    auto built = catalog.Build(oconfig.channel_backend_id, ctx);
    if (!built) {
        std::fprintf(stderr, "refuzz_exec_replayer: ChannelCatalog.Build failed: %s\n",
                     built.error().message.c_str());
        return nullptr;
    }
    return std::move(*built);
}

} // namespace

int main(int argc, char** argv) {
    const char* trace_dir  = GetArg(argc, argv, "-trace-dir");
    const char* corpus_dir = GetArg(argc, argv, "-corpus-dir");
    const char* duration_s = GetArg(argc, argv, "-duration-s");
    const char* stats_out  = GetArg(argc, argv, "-stats-out");
    const char* output     = GetArg(argc, argv, "-output");
    const char* backend    = GetArg(argc, argv, "-backend");
    const char* config_p   = GetArg(argc, argv, "-config");
    const char* git_rev    = GetArg(argc, argv, "-git-rev");
    const char* per_req    = GetArg(argc, argv, "-per-request-timeout-ms");
    const char* drain_b    = GetArg(argc, argv, "-session-drain-budget-s");
    // [speed-compare 严格 C] none(默认,=C-prelim,host 不解析 output) |
    // kcov-pc(严格 C,同步剥 KCOV packet + decode + normalize,对齐 syzkaller
    // -cover=1 的 convertCallInfo 成本)。仅 corpus 模式有效。
    const char* cover_mode = GetArg(argc, argv, "-collect-cover-mode");
    // [PC-set 对比] -dump-pc-set <path>:corpus 模式 + kcov-pc 下,把 in-window 完成的
    // cover PC 并集(原始 KCOV PC)排序写 <path>(0x<hex>/line)。供 scripts/speed_compare/pc_set_compare.py。
    const char* dump_pc_set = GetArg(argc, argv, "-dump-pc-set");
    // T2 strict-equivalence pacing mode. Default off (production fast path);
    // -pace=trace reproduces syzkaller's per-proc start cadence by stalling
    // each Submit to land at the trace's Executing wall-clock anchor.
    const char* pace       = GetArg(argc, argv, "-pace");
    // [perf-sampling probe] Optional start barrier. Replayer publishes ready
    // only after channel_.Boot() returns, then waits for release before the
    // first RunOneSession/Submit. Both flags absent keeps legacy behavior.
    const char* perf_ready   = GetArg(argc, argv, "-perf-ready-file");
    const char* perf_release = GetArg(argc, argv, "-perf-release-file");
    // [perf-sampling probe] -hold-after-drain-s N: after trace replay drains,
    // keep the channel (and thus the QEMU guest) alive for up to N seconds so
    // an external probe controller can stop in-guest perf and fetch artifacts
    // BEFORE VM teardown. -hold-release-file P ends the hold early once P
    // exists. Trace mode only; 0/absent = exit immediately (legacy behavior).
    const char* hold_s     = GetArg(argc, argv, "-hold-after-drain-s");
    const char* hold_file  = GetArg(argc, argv, "-hold-release-file");
    // [full-pass口径] -corpus-passes N (corpus mode): measure N full passes by
    // completion count, wall = actual span (last−first completion). Immune to
    // the double-peak corpus's time-window sampling distortion. Omit = legacy
    // -duration-s window.
    const char* corpus_passes = GetArg(argc, argv, "-corpus-passes");

    // -no-boot: build the IChannel via ChannelCatalog but never call Boot()
    // or Submit(). Useful as a wiring smoke (config parse + assembler graph)
    // without actually launching QEMU. Echo backend ignores this flag — it
    // boots in-process for free.
    bool no_boot = false;
    bool decode_check = false;
    bool allow_truncated_tail = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-no-boot") == 0) no_boot = true;
        if (std::strcmp(argv[i], "-decode-check") == 0) decode_check = true;
        if (std::strcmp(argv[i], "-allow-truncated-tail") == 0) allow_truncated_tail = true;
    }

    // [speed-compare 解码自检] -decode-check: standalone, NO VM/backend. Decode
    // every <corpus-dir>/*/payload.bin via the real decoder and report which
    // programs reFuzz can't decode/encode. This is a reFuzz health check (run
    // when you want), NOT a corpus filter — execution itself stays direct.
    if (decode_check) {
        if (corpus_dir == nullptr) {
            std::fprintf(stderr,
                "refuzz_exec_replayer: -decode-check requires -corpus-dir\n");
            return 2;
        }
        refuzz::oracle::replayer::CorpusDecodeCheckStats st;
        const bool all_ok =
            refuzz::oracle::replayer::RunCorpusDecodeCheck(corpus_dir, st);
        std::fprintf(stderr,
            "decode-check: found=%llu decoded_ok=%llu decode_failed=%llu encode_failed=%llu\n",
            (unsigned long long)st.found, (unsigned long long)st.decoded_ok,
            (unsigned long long)st.decode_failed, (unsigned long long)st.encode_failed);
        for (const auto& s : st.decode_failed_paths)
            std::fprintf(stderr, "decode-check:   DECODE FAIL %s\n", s.c_str());
        for (const auto& s : st.encode_failed_paths)
            std::fprintf(stderr, "decode-check:   ENCODE FAIL %s (serialize_for_exec rejected)\n",
                         s.c_str());
        if (stats_out != nullptr) {
            nlohmann::json j;
            j["corpus_dir"]    = corpus_dir;
            j["found"]         = st.found;
            j["decoded_ok"]    = st.decoded_ok;
            j["decode_failed"] = st.decode_failed;
            j["encode_failed"] = st.encode_failed;
            j["all_ok"]        = all_ok;
            j["decode_failed_paths"] = st.decode_failed_paths;
            j["encode_failed_paths"] = st.encode_failed_paths;
            std::ofstream out(stats_out);
            out << j.dump(2) << "\n";
            std::fprintf(stderr, "decode-check: stats → %s\n", stats_out);
        }
        std::fprintf(stderr, "decode-check: %s\n",
                     all_ok ? "ALL programs decode+encode OK"
                            : "SOME programs failed — investigate reFuzz decoder (not a filter)");
        return all_ok ? 0 : 7;
    }

    // Corpus replay (bench replay scenario) vs. trace replay (paired oracle):
    // the two modes share the channel build path but use disjoint orchestrators.
    const bool corpus_mode = (corpus_dir != nullptr);
    if (corpus_mode && trace_dir != nullptr) {
        std::fprintf(stderr,
            "refuzz_exec_replayer: -corpus-dir and -trace-dir are mutually exclusive\n");
        Usage(argv[0]);
        return 2;
    }
    if (corpus_mode) {
        if (duration_s == nullptr) {
            std::fprintf(stderr,
                "refuzz_exec_replayer: -corpus-dir requires -duration-s\n");
            Usage(argv[0]);
            return 2;
        }
        // -output is meaningless in corpus mode (no ref_result.bin to write);
        // require it absent so caller scripts don't pass it by reflex.
        if (output != nullptr) {
            std::fprintf(stderr,
                "refuzz_exec_replayer: -output is not used in corpus mode\n");
            return 2;
        }
    } else if (trace_dir == nullptr || output == nullptr) {
        Usage(argv[0]);
        return 2;
    }

    refuzz::oracle::replayer::ReplayerConfig cfg;
    // trace_dir / output are nullptr in corpus mode; std::string assignment
    // from nullptr is UB (segfault). Guard so the unused config is harmless.
    cfg.trace_dir   = trace_dir != nullptr ? trace_dir : "";
    cfg.output_path = output    != nullptr ? output    : "";
    cfg.git_rev     = git_rev   != nullptr ? git_rev   : "";
    cfg.allow_truncated_tail = allow_truncated_tail;
    if ((perf_ready == nullptr) != (perf_release == nullptr)) {
        std::fprintf(stderr,
            "refuzz_exec_replayer: -perf-ready-file and -perf-release-file "
            "must be provided together\n");
        return 2;
    }
    if (per_req != nullptr) {
        int ms = std::atoi(per_req);
        cfg.per_request_timeout = std::chrono::seconds(std::max(1, ms / 1000));
    }
    if (drain_b != nullptr) {
        cfg.session_drain_budget = std::chrono::seconds(std::atoi(drain_b));
    }
    if (pace != nullptr) {
        const std::string mode = pace;
        if (mode == "none") {
            cfg.pacing_mode = refuzz::oracle::replayer::PacingMode::kNone;
        } else if (mode == "trace") {
            cfg.pacing_mode = refuzz::oracle::replayer::PacingMode::kTrace;
        } else {
            std::fprintf(stderr,
                "refuzz_exec_replayer: -pace=%s unknown; expected none|trace\n",
                pace);
            return 2;
        }
    }
    std::string backend_id = backend != nullptr ? backend : "echo";
    std::unique_ptr<refuzz::channel::IChannel> ch;
    std::filesystem::path qemu_vm_workdir;
    uint32_t backend_n_workers = 0;
    if (backend_id == "echo") {
        ch = std::make_unique<refuzz::oracle::replayer::EchoChannel>();
    } else if (backend_id == "qemu_ivshmem_linux") {
        if (config_p == nullptr) {
            std::fprintf(stderr,
                "refuzz_exec_replayer: -backend=qemu_ivshmem_linux requires -config\n");
            return 2;
        }
        ch = BuildQemuChannelFromConfig(config_p, qemu_vm_workdir, backend_n_workers);
        if (ch == nullptr) return 3;
        std::fprintf(stderr,
            "refuzz_exec_replayer: qemu channel built; vm_workdir=%s n_workers=%u\n",
            qemu_vm_workdir.string().c_str(), backend_n_workers);
    } else {
        std::fprintf(stderr, "refuzz_exec_replayer: unknown backend %s\n",
                     backend_id.c_str());
        Usage(argv[0]);
        return 2;
    }

    // ----------------------------------------------------------------
    // Corpus-replay branch (bench replay scenario). Boots the same channel
    // backend as trace mode but skips RefResultWriter (no per-program
    // outcome stream to write — the only output is the summary stats).
    // ----------------------------------------------------------------
    if (corpus_mode) {
        if (backend_id == "echo") {
            std::fprintf(stderr,
                "refuzz_exec_replayer: corpus mode requires a real backend "
                "(echo never executes programs; pick -backend qemu_ivshmem_linux)\n");
            return 2;
        }
        auto boot_ok = ch->Boot();
        if (!boot_ok.ok()) {
            std::fprintf(stderr, "refuzz_exec_replayer: channel Boot() failed: %s\n",
                         boot_ok.error().message.c_str());
            return 5;
        }

        refuzz::oracle::replayer::CorpusReplayConfig ccfg;
        ccfg.corpus_dir          = corpus_dir;
        ccfg.duration            = std::chrono::seconds(std::atoi(duration_s));
        if (per_req != nullptr) {
            ccfg.per_request_timeout = std::chrono::milliseconds(std::atoi(per_req));
        }
        // Mirror fuzz_loop's default exec_flags: INTRA_THREADED + SHAPE_SINGLE
        // (= 1 in the wire encoding). Bench's threaded path sets this; if a
        // future caller needs SERIAL/COMPS toggles add CLI flags then.
        ccfg.exec_flags = TASK_FLAG_INTRA_THREADED;
        if (cover_mode != nullptr) {
            using CCM = refuzz::oracle::replayer::CorpusReplayConfig::CollectCoverMode;
            if (std::strcmp(cover_mode, "kcov-pc") == 0) {
                ccfg.collect_cover_mode = CCM::kKcovPc;
            } else if (std::strcmp(cover_mode, "none") == 0) {
                ccfg.collect_cover_mode = CCM::kNone;
            } else {
                std::fprintf(stderr,
                    "refuzz_exec_replayer: -collect-cover-mode must be none|kcov-pc (got %s)\n",
                    cover_mode);
                return 2;
            }
        }

        ccfg.collect_pc_set = (dump_pc_set != nullptr);
        // [full-pass口径] -corpus-passes N: measure N full corpus passes by
        // completion count (wall = actual span), not a time window. 0/absent =
        // legacy -duration-s window.
        if (corpus_passes != nullptr) {
            ccfg.corpus_passes =
                static_cast<uint32_t>(std::max(0, std::atoi(corpus_passes)));
        }

        refuzz::oracle::replayer::CorpusReplayStats cstats;
        const bool ok = refuzz::oracle::replayer::RunCorpusReplay(*ch, ccfg, cstats);
        ch->Close();

        if (stats_out != nullptr) {
            nlohmann::json j;
            j["corpus_dir"]              = ccfg.corpus_dir.string();
            j["duration_s"]              = (int64_t)ccfg.duration.count();
            // [full-pass口径] measurement_mode tells the wrapper how wall_s was
            // derived: "corpus_pass" = actual span over corpus_passes×size
            // completions; "time_window" = fixed duration window.
            j["corpus_passes"]           = ccfg.corpus_passes;
            j["measurement_mode"]        =
                ccfg.corpus_passes > 0 ? "corpus_pass" : "time_window";
            j["per_request_timeout_ms"]  = (int64_t)ccfg.per_request_timeout.count();
            j["exec_flags"]              = ccfg.exec_flags;
            j["corpus_files_found"]      = cstats.corpus_files_found;
            j["corpus_decode_failed"]    = cstats.corpus_decode_failed;
            j["corpus_encode_failed"]    = cstats.corpus_encode_failed;
            j["corpus_payloads_ready"]   = cstats.corpus_payloads_ready;
            j["submissions_accepted"]    = cstats.submissions_accepted;
            j["submissions_rejected"]    = cstats.submissions_rejected;
            // [speed-compare 窗口对齐] window_completions = numerator (completions
            // in [first_completion, +duration]); completions = TOTAL incl. drain
            // (diagnostic); drain_completions = post-window (diagnostic only).
            j["window_completions"]      = cstats.window_completions;
            j["drain_completions"]       = cstats.drain_completions;
            j["completions"]             = cstats.completions;
            j["abnormal"]                = cstats.abnormal;
            j["faults"]                  = cstats.faults;
            j["drain_inflight_at_end"]   = cstats.drain_inflight_at_end;
            j["wall_ns"]                 = cstats.wall_ns;
            const double wall_s = cstats.wall_ns / 1e9;  // = duration (window only)
            j["wall_s"]                  = wall_s;
            // Throughput numerator = in-window completions only (ramp + drain
            // excluded), matching syz-execprog's first-completion-anchored window.
            j["programs_per_sec"]        = wall_s > 0
                ? (double)cstats.window_completions / wall_s : 0.0;
            // [speed-compare problem 2] syz_calls/sec primary口径 = ACTUAL
            // executed calls (kCallFlagExecuted) of in-window completions; nominal
            // over-counts on early return and is auxiliary. (executed/nominal are
            // tallied only for in-window completions — see corpus_replay.cpp.)
            j["nominal_syz_calls"]         = cstats.nominal_syz_calls;
            j["executed_syz_calls"]        = cstats.executed_syz_calls;
            j["syz_calls_per_sec"]         = wall_s > 0
                ? (double)cstats.executed_syz_calls / wall_s : 0.0;
            j["syz_calls_per_sec_nominal"] = wall_s > 0
                ? (double)cstats.nominal_syz_calls / wall_s : 0.0;
            // [speed-compare 严格 C] cover 解析口径(kcov-pc 模式才非零)。
            const bool cover_on =
                ccfg.collect_cover_mode ==
                refuzz::oracle::replayer::CorpusReplayConfig::CollectCoverMode::kKcovPc;
            j["collect_cover_mode"]      = cover_on ? "kcov-pc" : "none";
            j["output_bytes"]            = cstats.output_bytes;
            j["total_cover_entries"]     = cstats.total_cover_entries;
            j["calls_with_cover"]        = cstats.calls_with_cover;
            j["cover_decode_failed"]     = cstats.cover_decode_failed;
            std::ofstream out(stats_out);
            out << j.dump(2) << "\n";
            std::fprintf(stderr, "corpus-replay: stats → %s\n", stats_out);
        }

        // [PC-set 对比] dump in-window corpus PC union(原始 KCOV PC,sorted,
        // 0x<hex>/line)。下游 scripts/speed_compare/pc_set_compare.py 按 instr_len 平移后与 syz
        // execprog -pcset_out 求 Jaccard/差集。仅 -dump-pc-set + kcov-pc 有数据。
        if (dump_pc_set != nullptr) {
            std::vector<std::uint64_t> pcs(cstats.corpus_pc_union.begin(),
                                           cstats.corpus_pc_union.end());
            std::sort(pcs.begin(), pcs.end());
            std::ofstream pf(dump_pc_set);
            for (std::uint64_t pc : pcs) pf << "0x" << std::hex << pc << "\n";
            std::fprintf(stderr, "corpus-replay: dumped %zu corpus PCs → %s\n",
                         pcs.size(), dump_pc_set);
        }
        return ok ? 0 : 6;
    }

    refuzz::oracle::replayer::RefResultWriter w;
    if (!w.Open(cfg.output_path, cfg.git_rev)) {
        std::fprintf(stderr, "refuzz_exec_replayer: cannot open output %s\n",
                     cfg.output_path.c_str());
        return 4;
    }

    if (no_boot && backend_id == "qemu_ivshmem_linux") {
        std::fprintf(stderr,
            "refuzz_exec_replayer: -no-boot set; channel wired but not booted, "
            "skipping replay\n");
        return w.Close() ? 0 : 4;
    }

    if (perf_ready != nullptr) {
        const std::string ready_file = perf_ready;
        const std::string release_file = perf_release;
        cfg.post_boot_hook = [ready_file, release_file]() {
            {
                std::ofstream ready(ready_file, std::ios::trunc);
                if (!ready) {
                    std::fprintf(stderr,
                        "refuzz_exec_replayer: cannot publish perf ready file %s\n",
                        ready_file.c_str());
                    return false;
                }
            }
            std::fprintf(stderr,
                "refuzz_exec_replayer: PERF ready before first request "
                "(release-file=%s)\n",
                release_file.c_str());
            std::fflush(stderr);
            for (;;) {
                std::error_code ec;
                if (std::filesystem::exists(release_file, ec)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            std::fprintf(stderr,
                "refuzz_exec_replayer: PERF start released\n");
            return true;
        };
    }

    // [perf-sampling probe] Hold the channel (and thus the QEMU guest) alive
    // after the last session drains, so an external probe controller can
    // harvest in-guest artifacts BEFORE teardown. This must run as Run()'s
    // pre_close_hook, not after r.Run() returns: Run() owns the whole
    // Boot()...Close() lifecycle internally and the VM is already gone by
    // the time control returns to main(). The HOLD line below is the
    // controller's trigger -- keep its prefix stable.
    if (hold_s != nullptr) {
        const int hold_total = std::max(0, std::atoi(hold_s));
        if (hold_total > 0) {
            const std::string hold_file_str = hold_file != nullptr ? hold_file : "";
            cfg.pre_close_hook = [hold_total, hold_file_str]() {
                std::fprintf(stderr,
                    "refuzz_exec_replayer: HOLD after drain for up to %ds"
                    " (release-file=%s)\n",
                    hold_total, hold_file_str.empty() ? "<none>" : hold_file_str.c_str());
                std::fflush(stderr);
                for (int waited = 0; waited < hold_total; ++waited) {
                    if (!hold_file_str.empty()) {
                        std::error_code hec;
                        if (std::filesystem::exists(hold_file_str, hec)) break;
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                std::fprintf(stderr, "refuzz_exec_replayer: HOLD released\n");
            };
        }
    }

    refuzz::oracle::replayer::Replayer r(*ch, w, cfg);
    const bool replay_ok = r.Run();
    const bool output_ok = w.Close();
    if (!replay_ok || !output_ok) {
        if (!output_ok) {
            std::fprintf(stderr,
                "refuzz_exec_replayer: ref_result write or flush failed\n");
        }
        std::fprintf(stderr, "refuzz_exec_replayer: replay failed\n");
        return 5;
    }
    const auto& s = r.stats();
    std::fprintf(stderr,
        "refuzz_exec_replayer: done backend=%s sessions=%llu "
        "exec_requests_seen=%llu accepted=%llu rejected=%llu "
        "skipped_unsupported=%llu outcomes_normal=%llu "
        "outcomes_abnormal=%llu outcomes_missing=%llu\n",
        backend_id.c_str(),
        static_cast<unsigned long long>(s.sessions_processed),
        static_cast<unsigned long long>(s.exec_requests_seen),
        static_cast<unsigned long long>(s.submissions_accepted),
        static_cast<unsigned long long>(s.submissions_rejected),
        static_cast<unsigned long long>(s.skips_unsupported),
        static_cast<unsigned long long>(s.outcomes_normal),
        static_cast<unsigned long long>(s.outcomes_abnormal),
        static_cast<unsigned long long>(s.outcomes_missing_at_close));
    return 0;
}
