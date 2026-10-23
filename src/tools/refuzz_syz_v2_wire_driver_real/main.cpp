// refuzz-syz-v2-wire-driver-real: Layer-3 milestone II.6.
//
// Runs each program through KernelWireDriver wired to
// SyscallOrPseudoDispatcher (REAL syscalls, no mock). Captures per-call
// (ret, errno) and emits JSONL.
//
// SAFETY GATE
//   By default the tool only accepts files listed in the safe-corpus
//   manifest (`-safe-list`). The manifest names programs that have been
//   reviewed to be non-destructive on the host (close, getpid, exit,
//   pipe2, dup, ... — see tools/refuzz_safe_corpus/safe_list.txt).
//   Use `-allow-unsafe` to skip the gate; only do that inside an isolated
//   VM or container.
//
// USAGE
//   refuzz-syz-v2-wire-driver-real <indir> [-safe-list <path>]
//                                  [-out <jsonl>] [-allow-unsafe]

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/dispatcher/syscall_or_pseudo.hpp"
#include "worker/driver/kernel_wire_driver.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_set>
#include <vector>

namespace syz = ::refuzz::program::syz;
namespace rw  = ::refuzz::worker;

namespace {

struct SyzExecResult {
    int64_t  ret    = 0;
    int32_t  err    = 0;
    uint32_t reserved = 0;
};

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> list_dir(const std::string& path) {
    std::vector<std::string> out;
    DIR* d = opendir(path.c_str());
    if (d == nullptr) return out;
    while (auto* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        std::string full = path + "/" + n;
        struct stat st{};
        if (stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            out.push_back(n);
        }
    }
    closedir(d);
    std::sort(out.begin(), out.end());
    return out;
}

std::unordered_set<std::string> load_safe_list(const std::string& path) {
    std::unordered_set<std::string> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        // Strip whitespace + drop comments after '#'.
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        // ltrim/rtrim whitespace
        auto lo = line.find_first_not_of(" \t");
        auto hi = line.find_last_not_of(" \t");
        if (lo == std::string::npos) continue;
        out.insert(line.substr(lo, hi - lo + 1));
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    std::string indir;
    std::string safe_list_path;
    std::string out_path = "-";
    bool allow_unsafe = false;
    int runs = 1;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-safe-list" && i + 1 < argc) {
            safe_list_path = argv[++i];
        } else if (a == "-out" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (a == "-allow-unsafe") {
            allow_unsafe = true;
        } else if (a == "-runs" && i + 1 < argc) {
            runs = std::atoi(argv[++i]);
            if (runs <= 0) runs = 1;
        } else if (a[0] != '-' && indir.empty()) {
            indir = a;
        } else {
            std::fprintf(stderr,
                "usage: %s <indir> [-safe-list <path>] [-out <jsonl>] "
                "[-runs N] [-allow-unsafe]\n",
                argv[0]);
            return 2;
        }
    }
    if (indir.empty()) {
        std::fprintf(stderr,
            "usage: %s <indir> [-safe-list <path>] [-out <jsonl>] "
            "[-runs N] [-allow-unsafe]\n",
            argv[0]);
        return 2;
    }

    std::unordered_set<std::string> safe_list;
    if (!allow_unsafe) {
        if (safe_list_path.empty()) {
            std::fprintf(stderr,
                "ERROR: missing -safe-list. Provide a manifest of programs "
                "reviewed safe for host execution, OR pass -allow-unsafe "
                "(only in isolated VM/container).\n");
            return 2;
        }
        safe_list = load_safe_list(safe_list_path);
        if (safe_list.empty()) {
            std::fprintf(stderr,
                "ERROR: -safe-list %s is empty or unreadable.\n",
                safe_list_path.c_str());
            return 2;
        }
    }

    std::FILE* fout = (out_path == "-") ? stdout
                                        : std::fopen(out_path.c_str(), "w");
    if (fout == nullptr) {
        std::fprintf(stderr, "cannot open output: %s\n", out_path.c_str());
        return 2;
    }

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);
    auto files = list_dir(indir);

    int considered = 0, skipped_unsafe = 0, skipped_decode = 0;
    int skipped_kfuzz = 0, fail_encode = 0, driver_err = 0, ok = 0;

    constexpr std::size_t kOutBufSize = 256 * 1024;
    std::vector<uint8_t> out_buf(kOutBufSize);

    for (const auto& name : files) {
        if (!allow_unsafe && safe_list.find(name) == safe_list.end()) {
            ++skipped_unsafe;
            continue;
        }
        std::string text = read_file(indir + "/" + name);
        auto prog_or = dec.decode(text);
        if (!prog_or) { ++skipped_decode; continue; }
        const syz::Prog& prog = **prog_or;
        bool kfuzz = false;
        for (const auto& cup : prog.calls()) {
            const auto* m = cup->meta();
            if (m && m->attrs().kfuzztest) { kfuzz = true; break; }
        }
        if (kfuzz) { ++skipped_kfuzz; continue; }
        ++considered;

        auto bytes_or = syz::serialize_for_exec(prog);
        if (!bytes_or) { ++fail_encode; continue; }
        const auto& bytes = *bytes_or;

        // Each iteration uses a fresh driver to confirm no cross-run
        // state contamination via the thread-local scratch. We capture
        // every run, then check (when runs>1) that every iteration
        // returned the same vector of (ret,err).
        std::fprintf(fout, R"({"file":"%s","runs":[)", name.c_str());
        bool any_err = false;
        std::vector<std::vector<std::pair<int64_t, int32_t>>> all_runs;
        for (int r = 0; r < runs; ++r) {
            if (r != 0) std::fputc(',', fout);

            rw::KernelWireDriver driver(
                std::make_unique<rw::SyscallOrPseudoDispatcher>());

            uint32_t out_len = 0;
            const int rc = driver.Execute(
                bytes.data(),
                static_cast<uint32_t>(bytes.size()),
                out_buf.data(),
                static_cast<uint32_t>(out_buf.size()),
                &out_len);
            if (rc != 0) {
                std::fprintf(fout,
                    R"({"status":"driver_err","rc":%d})", rc);
                any_err = true;
                all_runs.push_back({});
                continue;
            }
            const auto* res = reinterpret_cast<const SyzExecResult*>(out_buf.data());
            const std::size_t n = out_len / sizeof(SyzExecResult);
            std::vector<std::pair<int64_t, int32_t>> this_run;
            this_run.reserve(n);
            std::fprintf(fout, R"({"status":"ok","results":[)");
            for (std::size_t i = 0; i < n; ++i) {
                if (i != 0) std::fputc(',', fout);
                std::fprintf(fout, R"({"ret":%lld,"err":%d})",
                             static_cast<long long>(res[i].ret),
                             res[i].err);
                this_run.emplace_back(res[i].ret, res[i].err);
            }
            std::fprintf(fout, "]}");
            all_runs.push_back(std::move(this_run));
        }

        // Cross-run consistency: in -runs mode, all iterations must
        // match byte-for-byte (same process → same pid/uid/gid → same
        // ret/err for the safe whitelist).
        bool consistent = true;
        for (std::size_t r = 1; r < all_runs.size(); ++r) {
            if (all_runs[r] != all_runs[0]) { consistent = false; break; }
        }
        std::fprintf(fout, R"(],"consistent":%s})", consistent ? "true" : "false");
        std::fputc('\n', fout);
        if (any_err || !consistent) ++driver_err; else ++ok;
    }

    if (fout != stdout) std::fclose(fout);

    std::fprintf(stderr,
        "real-syscall: files=%zu considered=%d ok=%d driver_err=%d "
        "skipped(unsafe)=%d skipped(decode)=%d skipped(kfuzz)=%d fail_encode=%d\n",
        files.size(), considered, ok, driver_err, skipped_unsafe,
        skipped_decode, skipped_kfuzz, fail_encode);
    return 0;
}
