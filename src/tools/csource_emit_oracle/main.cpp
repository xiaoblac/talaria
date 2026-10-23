// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// csource_emit_oracle — Epic 4 plan §6.3 oracle runner for #c-repro-3
// (csource::Write coverage) and #c-repro-4 (csource::Build success
// rate). Operator-driven: NOT in default ctest. Pure host: no VM,
// no KCOV, no executor — just decodes .syz text fixtures and runs
// the same csource::Write / csource::Build the StageProduceCSource
// uses in production.
//
// Usage:
//   csource_emit_oracle -dir <path-to-.syz-corpus> [-with-build]
//                       [-limit N] [-jobs N] [-verbose]
//
// `-jobs` defaults to `std::thread::hardware_concurrency()`. Each
// worker thread is independent (TextDecoder per-thread; csource module
// singletons are const, the run_process fork is naturally process-
// safe). The cpp / gcc subprocess invocations are the dominant cost,
// so wall time scales linearly with `-jobs` until subprocess fan-out
// or memory bandwidth caps it.
//
// Output (stderr): final histogram as the source of truth for the
// oracle ledger #30 / #31 entries:
//
//   files=N
//   decode  ok=A fail=B
//   write   success=C unsupported_by_epic4=D internal=E
//   build   success=F fail=G [skipped=H]
//
// Plus per-reason breakdowns under `unsupported.<token>=…` (the
// substring match on the kCSourceError message that's most diagnostic
// for prioritization) and `build.<first-line-of-stderr>=…` (build
// failure cluster).
//
// Acceptance per Epic 4 plan §6.3:
//   success + unsupported_by_epic4 == 100% of decoded files
//   internal == 0
//   kCommonHeaderCppFailed == 0
//   build success rate >= 90% (when -with-build)
//
// Exit code: 0 on acceptance pass, 1 on any of the above failing.

#include "refuzz/crash/repro/csource/build.hpp"
#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

namespace cs  = ::refuzz::crash::repro::csource;
namespace syz = ::refuzz::program::syz;

namespace {

cs::Options BaselineOptions() {
    cs::Options opts;
    opts.Sandbox      = "none";
    opts.Threaded     = false;
    opts.Repeat       = false;
    opts.Procs        = 1;
    opts.UseTmpDir    = false;
    opts.HandleSegv   = true;
    opts.CallComments = true;
    return opts;
}

bool host_gcc_available() {
    return ::access("/usr/bin/gcc", X_OK) == 0 ||
           ::access("/usr/local/bin/gcc", X_OK) == 0;
}

std::string slurp(const std::filesystem::path& p) {
    std::ifstream is(p, std::ios::binary);
    if (!is) return {};
    std::ostringstream oss;
    oss << is.rdbuf();
    return oss.str();
}

std::string first_line(const std::string& s) {
    auto eol = s.find('\n');
    return eol == std::string::npos ? s : s.substr(0, eol);
}

const char* error_token(cs::CSourceError code) {
    switch (code) {
    case cs::CSourceError::kNotImplemented:        return "kNotImplemented";
    case cs::CSourceError::kInvalidOptions:        return "kInvalidOptions";
    case cs::CSourceError::kUnsupportedByEpic4:    return "kUnsupportedByEpic4";
    case cs::CSourceError::kSerializeFailed:       return "kSerializeFailed";
    case cs::CSourceError::kDecodeFailed:          return "kDecodeFailed";
    case cs::CSourceError::kCommonHeaderCppFailed: return "kCommonHeaderCppFailed";
    case cs::CSourceError::kInternal:              return "kInternal";
    }
    return "?";
}

// Pull a short prioritization-friendly token out of the
// kUnsupportedByEpic4 message ("FailNth", "Async", "NetInjection",
// "StrDec", etc.). Falls back to "other" when nothing recognizable.
std::string unsupported_class(const std::string& msg) {
    static const std::vector<std::string> kKnown = {
        "FailNth", "Async", "Rerun",
        "NetInjection", "NetDevices", "NetReset",
        "Cgroups", "BinfmtMisc", "Leak",
        "VhciInjection", "Wifi", "IEEE802154",
        "USB", "Sysctl", "Swap",
        "KCSAN", "DevlinkPCI", "NicVF",
        "StrDec", "StrHex", "StrOct",
        "BinaryFormat::Str",  // baseline_gate emits "Str{Dec,Hex,Oct}" template form
        "WireData",
        "Sandbox=", "SandboxArg",
        "Collide", "Fault",
        "FaultInjection",
        "all calls dropped",
    };
    for (const auto& tok : kKnown) {
        if (msg.find(tok) != std::string::npos) return tok;
    }
    return "other";
}

struct Counts {
    std::size_t files          = 0;
    std::size_t decode_ok      = 0;
    std::size_t decode_fail    = 0;
    std::size_t write_success  = 0;
    std::size_t write_unsupp   = 0;
    std::size_t write_internal = 0;
    std::size_t cpp_failed     = 0;
    std::size_t cpp_recovered  = 0;   // promoted to success/unsupp by retry
    std::size_t build_success  = 0;
    std::size_t build_fail     = 0;
    std::size_t build_skipped  = 0;
    std::map<std::string, std::size_t> unsupp_class;
    std::map<std::string, std::size_t> internal_class;
    std::map<std::string, std::size_t> build_first_line;
    // Files that hit cpp_failed in the parallel pass — retried serially
    // to separate contention timeouts from genuine prog issues.
    std::vector<std::filesystem::path> cpp_failed_paths;

    void merge(const Counts& o) {
        files          += o.files;
        decode_ok      += o.decode_ok;
        decode_fail    += o.decode_fail;
        write_success  += o.write_success;
        write_unsupp   += o.write_unsupp;
        write_internal += o.write_internal;
        cpp_failed     += o.cpp_failed;
        cpp_recovered  += o.cpp_recovered;
        build_success  += o.build_success;
        build_fail     += o.build_fail;
        build_skipped  += o.build_skipped;
        for (const auto& [k, v] : o.unsupp_class)     unsupp_class[k]     += v;
        for (const auto& [k, v] : o.internal_class)   internal_class[k]   += v;
        for (const auto& [k, v] : o.build_first_line) build_first_line[k] += v;
        for (const auto& p : o.cpp_failed_paths) cpp_failed_paths.push_back(p);
    }
};

void print_histogram(const Counts& c, bool with_build) {
    std::fprintf(stderr, "\n=== csource_emit_oracle histogram ===\n");
    std::fprintf(stderr,
                 "files=%zu\n"
                 "decode  ok=%zu fail=%zu\n"
                 "write   success=%zu unsupported_by_epic4=%zu internal=%zu (cpp_failed=%zu)\n",
                 c.files, c.decode_ok, c.decode_fail,
                 c.write_success, c.write_unsupp, c.write_internal,
                 c.cpp_failed);
    if (with_build) {
        std::fprintf(stderr, "build   success=%zu fail=%zu skipped=%zu\n",
                     c.build_success, c.build_fail, c.build_skipped);
    }
    if (!c.unsupp_class.empty()) {
        std::fprintf(stderr, "unsupported_by_epic4 reasons:\n");
        for (const auto& [tok, n] : c.unsupp_class) {
            std::fprintf(stderr, "  unsupported.%-20s = %zu\n", tok.c_str(), n);
        }
    }
    if (!c.internal_class.empty()) {
        std::fprintf(stderr, "internal reasons:\n");
        for (const auto& [tok, n] : c.internal_class) {
            std::fprintf(stderr, "  internal.%-25s = %zu\n", tok.c_str(), n);
        }
    }
    if (with_build && !c.build_first_line.empty()) {
        std::fprintf(stderr, "build failure clusters (first stderr line):\n");
        for (const auto& [tok, n] : c.build_first_line) {
            std::fprintf(stderr, "  build.%s = %zu\n", tok.c_str(), n);
        }
    }
}

bool acceptance_pass(const Counts& c, bool with_build) {
    bool ok = true;
    const std::size_t accounted = c.write_success + c.write_unsupp;
    if (accounted != c.decode_ok) {
        std::fprintf(stderr,
                     "FAIL: success+unsupported(%zu) != decode_ok(%zu)\n",
                     accounted, c.decode_ok);
        ok = false;
    }
    if (c.write_internal != 0) {
        std::fprintf(stderr,
                     "FAIL: internal=%zu (must be 0)\n", c.write_internal);
        ok = false;
    }
    if (c.cpp_failed != 0) {
        std::fprintf(stderr,
                     "FAIL: kCommonHeaderCppFailed=%zu (must be 0)\n",
                     c.cpp_failed);
        ok = false;
    }
    if (with_build && (c.build_success + c.build_fail) > 0) {
        const double rate = static_cast<double>(c.build_success) /
            static_cast<double>(c.build_success + c.build_fail);
        std::fprintf(stderr,
                     "build success rate = %.4f (acceptance >= 0.90)\n",
                     rate);
        if (rate < 0.90) ok = false;
    }
    return ok;
}

void process_file(const std::filesystem::path& path,
                  const syz::Target& target,
                  const cs::Options& opts,
                  bool with_build,
                  bool verbose,
                  bool log_all,
                  Counts& c) {
    ++c.files;

    const std::string text = slurp(path);
    if (text.empty()) {
        ++c.decode_fail;
        if (verbose || log_all) {
            std::fprintf(stderr, "PER %s decode=empty\n", path.c_str());
        }
        return;
    }

    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);
    auto prog_or = dec.decode(text);
    if (!prog_or.has_value()) {
        ++c.decode_fail;
        if (verbose || log_all) {
            std::fprintf(stderr,
                         "PER %s decode=fail line=%d col=%d msg=%s\n",
                         path.c_str(),
                         prog_or.error().line, prog_or.error().column,
                         prog_or.error().message.c_str());
        }
        return;
    }
    ++c.decode_ok;

    const auto t_w0 = std::chrono::steady_clock::now();
    auto wr = cs::Write(*prog_or.value(), opts,
                        cs::linux_amd64_annotator(),
                        cs::linux_amd64_target_info());
    const auto write_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_w0).count();

    if (!wr.has_value()) {
        const auto code = wr.error().code;
        if (code == cs::CSourceError::kUnsupportedByEpic4) {
            ++c.write_unsupp;
            const auto klass = unsupported_class(wr.error().message);
            ++c.unsupp_class[klass];
            if (verbose || log_all) {
                std::fprintf(stderr,
                             "PER %s decode=ok write=unsupp class=%s "
                             "wall_ms=%lld msg=%s\n",
                             path.c_str(), klass.c_str(),
                             static_cast<long long>(write_ms),
                             wr.error().message.c_str());
            }
        } else {
            ++c.write_internal;
            if (code == cs::CSourceError::kCommonHeaderCppFailed) {
                ++c.cpp_failed;
                c.cpp_failed_paths.push_back(path);
            }
            ++c.internal_class[error_token(code)];
            if (verbose || log_all) {
                std::fprintf(stderr,
                             "PER %s decode=ok write=internal code=%s "
                             "wall_ms=%lld msg=%s\n",
                             path.c_str(), error_token(code),
                             static_cast<long long>(write_ms),
                             wr.error().message.c_str());
            }
        }
        return;
    }
    ++c.write_success;
    if (log_all) {
        std::fprintf(stderr, "PER %s decode=ok write=success wall_ms=%lld\n",
                     path.c_str(), static_cast<long long>(write_ms));
    }

    if (!with_build) return;

    if (!host_gcc_available()) {
        ++c.build_skipped;
        if (log_all) {
            std::fprintf(stderr, "PER %s build=skipped\n", path.c_str());
        }
        return;
    }
    cs::BuildOptions bopts;
    bopts.timeout_seconds = 60;
    const auto t_b0 = std::chrono::steady_clock::now();
    auto br = cs::Build(*wr, bopts, cs::linux_amd64_target_info());
    const auto build_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_b0).count();

    if (br.has_value()) {
        ++c.build_success;
        // Cleanup the produced binary + temp dir.
        std::error_code ec;
        std::filesystem::remove(br->binary_path, ec);
        std::filesystem::path bin(br->binary_path);
        if (bin.parent_path().filename().string().rfind(
                "refuzz-csource-", 0) == 0) {
            std::filesystem::remove_all(bin.parent_path(), ec);
        }
        if (log_all) {
            std::fprintf(stderr, "PER %s build=success wall_ms=%lld\n",
                         path.c_str(), static_cast<long long>(build_ms));
        }
    } else {
        ++c.build_fail;
        const auto& msg = br.error();
        std::string key = first_line(msg);
        if (key.find("// autogenerated") != std::string::npos ||
            key.find("failed to build program") != std::string::npos) {
            auto p = msg.find("<stdin>:");
            if (p != std::string::npos) {
                auto eol = msg.find('\n', p);
                key = msg.substr(p, eol == std::string::npos ?
                                 std::string::npos : eol - p);
            }
        }
        if (key.size() > 120) key.resize(120);
        ++c.build_first_line[key];
        if (verbose || log_all) {
            std::fprintf(stderr,
                         "PER %s build=fail wall_ms=%lld key=%s\n",
                         path.c_str(),
                         static_cast<long long>(build_ms),
                         key.c_str());
        }
    }
}

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "usage: %s -dir <corpus-dir> [-with-build] [-limit N] "
                 "[-jobs N] [-verbose] [-log-all]\n"
                 "  -log-all: emit one `PER <path> ...` line per file "
                 "(success and failure) so a single run captures the\n"
                 "            whole sample for offline post-mortem.\n",
                 argv0);
}

} // namespace

int main(int argc, char** argv) {
    std::string dir;
    bool with_build = false;
    bool verbose = false;
    bool log_all = false;
    std::size_t limit = 0;
    // Default to nproc/2 — each cs::Write spawns a `cpp` subprocess
    // (and -with-build adds gcc), so over-saturating CPU shoves
    // individual subprocesses past the cs internal wall timeout and
    // surfaces as spurious kCommonHeaderCppFailed timeouts. Operators
    // who want maximum throughput can pass -jobs $(nproc) explicitly.
    unsigned jobs = std::thread::hardware_concurrency() / 2;
    if (jobs == 0) jobs = 1;

    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a == "-dir" && i + 1 < argc) {
            dir = argv[++i];
        } else if (a == "-with-build") {
            with_build = true;
        } else if (a == "-verbose") {
            verbose = true;
        } else if (a == "-log-all") {
            log_all = true;
        } else if (a == "-limit" && i + 1 < argc) {
            limit = static_cast<std::size_t>(std::atoll(argv[++i]));
        } else if (a == "-jobs" && i + 1 < argc) {
            const long n = std::atoll(argv[++i]);
            if (n < 1) {
                std::fprintf(stderr, "-jobs must be >= 1\n");
                return 2;
            }
            jobs = static_cast<unsigned>(n);
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "unknown arg: %.*s\n",
                         int(a.size()), a.data());
            usage(argv[0]);
            return 2;
        }
    }
    if (dir.empty()) {
        usage(argv[0]);
        return 2;
    }

    std::vector<std::filesystem::path> paths;
    {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(dir, ec);
        if (ec) {
            std::fprintf(stderr, "cannot open %s: %s\n",
                         dir.c_str(), ec.message().c_str());
            return 2;
        }
        for (; it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file()) continue;
            paths.push_back(it->path());
        }
    }
    std::sort(paths.begin(), paths.end());
    if (limit > 0 && paths.size() > limit) {
        paths.resize(limit);
    }

    const auto& target = syz::Target::linux_amd64();
    const auto opts = BaselineOptions();

    // Cap workers at file count (no point spawning more threads than work).
    if (jobs > paths.size() && paths.size() > 0) {
        jobs = static_cast<unsigned>(paths.size());
    }

    std::fprintf(stderr,
                 "csource_emit_oracle: dir=%s files=%zu jobs=%u with_build=%s\n",
                 dir.c_str(), paths.size(), jobs, with_build ? "yes" : "no");

    const auto t_start = std::chrono::steady_clock::now();

    // Workers grab indices via an atomic counter — wait-free fan-out
    // beats a mutex-protected queue when the per-task work is in the
    // hundreds-of-ms range and contention would be on every grab.
    std::atomic<std::size_t> next_idx{0};
    std::atomic<std::size_t> processed{0};
    std::vector<Counts> per_thread(jobs);
    std::vector<std::thread> threads;
    threads.reserve(jobs);
    std::mutex log_mu;

    auto worker = [&](unsigned tid) {
        Counts& c = per_thread[tid];
        for (;;) {
            const std::size_t i = next_idx.fetch_add(1, std::memory_order_relaxed);
            if (i >= paths.size()) break;
            process_file(paths[i], target, opts, with_build, verbose, log_all, c);
            const std::size_t done =
                processed.fetch_add(1, std::memory_order_relaxed) + 1;
            // Log a heartbeat every 50 files so an operator running on a
            // 1k-seed corpus sees forward progress without -verbose.
            if (done % 50 == 0) {
                std::lock_guard<std::mutex> g(log_mu);
                std::fprintf(stderr, "  ... processed %zu/%zu\n",
                             done, paths.size());
            }
        }
    };
    for (unsigned t = 0; t < jobs; ++t) {
        threads.emplace_back(worker, t);
    }
    for (auto& th : threads) th.join();

    Counts counts;
    for (const auto& c : per_thread) counts.merge(c);

    const auto t_parallel_end = std::chrono::steady_clock::now();

    // Pass 2 — single-thread retry of parallel-pass cpp_failed cases.
    // Per Epic 4 plan §8 stop condition, < 5% empty stdout is the
    // expected stochastic regime; in practice 0.3-0.5% of progs hit
    // the wall budget at jobs >= 6 due to CPU contention. Re-running
    // those serially with no contention separates "real -D set
    // explosion" from "transient timeout under load" so the operator
    // gets a deterministic acceptance signal.
    if (!counts.cpp_failed_paths.empty()) {
        std::fprintf(stderr,
                     "csource_emit_oracle: parallel pass cpp_failed=%zu — "
                     "retrying serially…\n",
                     counts.cpp_failed_paths.size());
        Counts retry_counts;
        for (const auto& p : counts.cpp_failed_paths) {
            process_file(p, target, opts, with_build, verbose, log_all,
                         retry_counts);
        }
        // Apply retry results: every recovered file flips one cpp_failed
        // (and one write_internal + one internal.kCommonHeaderCppFailed)
        // back to whatever the retry produced. cpp_failed_paths in the
        // retry counts is the residual set that's still failing.
        counts.cpp_recovered = retry_counts.write_success +
                               retry_counts.write_unsupp;
        counts.write_internal -= counts.cpp_recovered;
        counts.cpp_failed     -= counts.cpp_recovered;
        // Adjust internal_class["kCommonHeaderCppFailed"] mirror.
        if (auto it = counts.internal_class.find("kCommonHeaderCppFailed");
            it != counts.internal_class.end()) {
            if (counts.cpp_recovered >= it->second) {
                counts.internal_class.erase(it);
            } else {
                it->second -= counts.cpp_recovered;
            }
        }
        // Roll the retry's write_success / write_unsupp / build_*
        // upward so the histogram reflects the post-retry truth.
        counts.write_success += retry_counts.write_success;
        counts.write_unsupp  += retry_counts.write_unsupp;
        for (const auto& [k, v] : retry_counts.unsupp_class) {
            counts.unsupp_class[k] += v;
        }
        counts.build_success += retry_counts.build_success;
        counts.build_fail    += retry_counts.build_fail;
        counts.build_skipped += retry_counts.build_skipped;
        for (const auto& [k, v] : retry_counts.build_first_line) {
            counts.build_first_line[k] += v;
        }
    }

    const auto t_end = std::chrono::steady_clock::now();
    const auto wall_parallel = std::chrono::duration_cast<std::chrono::milliseconds>(
        t_parallel_end - t_start).count();
    const auto wall_total = std::chrono::duration_cast<std::chrono::milliseconds>(
        t_end - t_start).count();
    std::fprintf(stderr,
                 "csource_emit_oracle: wall_parallel=%lldms wall_total=%lldms "
                 "cpp_recovered=%zu cpp_residual=%zu\n",
                 static_cast<long long>(wall_parallel),
                 static_cast<long long>(wall_total),
                 counts.cpp_recovered, counts.cpp_failed);

    print_histogram(counts, with_build);
    const bool ok = acceptance_pass(counts, with_build);
    std::fprintf(stderr, "result: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
