// refuzz-syz-v2-wire-driver-smoke: Layer-2 (§3.3) integration probe.
//
// For each .syz in <indir>, runs the full pipeline:
//   TextDecoder.decode(text)
//     → Prog (v2 IR)
//     → serialize_for_exec(prog) → wire bytes
//     → KernelWireDriver(MockDispatcher).Execute(bytes)  (streaming decode)
// MockDispatcher records each (nr, args, argc) and returns a synthetic
// ret value, so we can prove the wire interpreter:
//   (a) walks the entire instruction stream without crashing,
//   (b) translates `call_id → SyscallMeta::nr` correctly via Target schema,
//   (c) resolves Const / Addr / Result args without touching invalid memory.
//
// This is NOT a kernel-execution test — it never enters the kernel.
// Layer-3 will add paired-VM acceptance.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/dispatcher/dispatcher.hpp"
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
#include <vector>

namespace syz = ::refuzz::program::syz;
namespace rw  = ::refuzz::worker;

namespace {

// MockDispatcher: records every dispatch, never enters the kernel.
class MockDispatcher final : public rw::IDispatcher {
public:
    struct Record {
        uint64_t nr;
        std::vector<intptr_t> args;
    };
    std::vector<Record> records;

    rw::PseudoResult Dispatch(uint64_t nr,
                              const intptr_t* args,
                              uint32_t argc,
                              rw::PseudoRuntimeContext* /*ctx*/) override {
        Record r;
        r.nr = nr;
        r.args.assign(args, args + argc);
        records.push_back(std::move(r));
        // Synthetic ret: 100 + records.size() (any non-zero distinct value).
        rw::PseudoResult res;
        res.ret = 100 + static_cast<int64_t>(records.size());
        res.err = 0;
        return res;
    }

    const char* Name() const override { return "mock"; }
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
        if (n.size() >= 4 && n.compare(n.size() - 4, 4, ".err") == 0) continue;
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

bool prog_has_kfuzztest(const syz::Prog& p) {
    for (const auto& cup : p.calls()) {
        const auto* m = cup->meta();
        if (m != nullptr && m->attrs().kfuzztest) return true;
    }
    return false;
}

// [v1 reject any non-zero CallProps — ROLLBACK: uncomment, remove v2]
// bool prog_has_unsupported_props(const syz::Prog& p) {
//     for (const auto& cup : p.calls()) {
//         const auto& props = cup->props();
//         if (props.fail_nth != 0 || props.async || props.rerun != 0) return true;
//     }
//     return false;
// }
//
// [v2 Epic 6 PR-6-A — fail_nth honored;async/rerun 仍 reject]
// True if any call carries Async / Rerun (which the driver still rejects
// per §10 N1/N2 — Epic 6 permanent non-goals). FailNth is **honored** end-
// to-end via fault_inject helpers (Epic 6 PR-6-A) — corpus seeds with
// fail_nth>0 are now exercised by the smoke oracle (this is the primary
// means of exercising the new fault-inject hook against real corpus on
// linux hosts where /proc/thread-self/fail-nth is available; CI hosts
// without CONFIG_FAULT_INJECTION just see all kCallFlagFaultInjected bits
// stay 0 — graceful per D-14, dispatch still completes).
bool prog_has_unsupported_props(const syz::Prog& p) {
    for (const auto& cup : p.calls()) {
        const auto& props = cup->props();
        if (props.async || props.rerun != 0) return true;
    }
    return false;
}

// Parse the leading "# requires: …" header lines. Returns true if the
// seed is in scope for the linux/amd64 wire-driver smoke. We only
// reject explicit `arch=` mismatches — `manual` seeds and other
// sandbox/threaded markers are kept because they decode fine and
// exercise the wire interpreter just as well; the §3.3 baseline
// already runs them. Empty / no-header seeds are accepted.
//
// Why not also filter `manual`: dropping `manual` would remove ~700
// seeds in the L3 corpus (syz_mount_image_*, syz_read_part_table_*,
// etc.) and tank smoke coverage from 823 to ~86. The `manual` flag
// means "operator-only kernel test" — orthogonal to whether the wire
// interpreter walks the program correctly.
bool seed_in_scope(const std::string& text) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        // Skip blank lines.
        const std::size_t nl = text.find('\n', pos);
        const std::string line = text.substr(pos, (nl == std::string::npos ? text.size() : nl) - pos);
        pos = (nl == std::string::npos) ? text.size() : nl + 1;
        // First non-comment line ends the header.
        std::size_t i = 0;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i == line.size()) continue;             // blank line: keep scanning
        if (line[i] != '#') break;                  // non-comment: stop
        // Found a comment line. Look for `requires:` token.
        const std::string body = line.substr(i + 1);
        const std::size_t req = body.find("requires:");
        if (req == std::string::npos) continue;
        const std::string tail = body.substr(req + 9);
        // Tokenize on whitespace; reject only on arch= mismatch.
        std::size_t t = 0;
        while (t < tail.size()) {
            while (t < tail.size() && (tail[t] == ' ' || tail[t] == '\t')) ++t;
            const std::size_t end = tail.find_first_of(" \t", t);
            const std::string tok = tail.substr(t, (end == std::string::npos ? tail.size() : end) - t);
            t = (end == std::string::npos) ? tail.size() : end;
            if (tok.empty()) continue;
            if (tok.compare(0, 5, "arch=") == 0 && tok.substr(5) != "amd64") {
                return false;
            }
        }
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <indir> [-v]\n", argv[0]);
        return 2;
    }
    const std::string indir = argv[1];
    const bool verbose = (argc >= 3 && std::strcmp(argv[2], "-v") == 0);

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    auto files = list_dir(indir);

    int total = 0, skip_decode = 0, skip_kfuzz = 0, fail_encode = 0;
    int skip_requires = 0, skip_props = 0;
    int driver_err = 0, ok = 0, count_mismatch = 0, nr_mismatch = 0;
    constexpr int kMaxOutput = 1024 * 1024;

    // Output buffer reused across iterations.
    std::vector<uint8_t> out_buf(kMaxOutput);

    for (const auto& name : files) {
        ++total;
        std::string text = read_file(indir + "/" + name);
        if (!seed_in_scope(text)) { ++skip_requires; continue; }
        auto prog_or = dec.decode(text);
        if (!prog_or) { ++skip_decode; continue; }
        const syz::Prog& prog = **prog_or;
        if (prog_has_kfuzztest(prog)) { ++skip_kfuzz; continue; }
        if (prog_has_unsupported_props(prog)) { ++skip_props; continue; }

        auto bytes_or = syz::serialize_for_exec(prog);
        if (!bytes_or) { ++fail_encode; continue; }
        const auto& bytes = *bytes_or;

        // Construct a fresh driver per program — KernelWireDriver is cheap
        // (no per-instance scratch; uses thread-local). MockDispatcher keeps
        // its records vector live so we can read it after Execute.
        auto disp_owner = std::make_unique<MockDispatcher>();
        MockDispatcher* disp = disp_owner.get();
        rw::KernelWireDriver driver(std::move(disp_owner));

        uint32_t out_len = 0;
        const int rc = driver.Execute(bytes.data(),
                                      static_cast<uint32_t>(bytes.size()),
                                      out_buf.data(),
                                      static_cast<uint32_t>(out_buf.size()),
                                      &out_len);
        if (rc != 0) {
            ++driver_err;
            if (verbose) std::fprintf(stderr, "driver-err %s rc=%d\n", name.c_str(), rc);
            continue;
        }

        // Acceptance check: dispatched call count matches prog.calls().
        if (disp->records.size() != prog.calls().size()) {
            ++count_mismatch;
            if (verbose) {
                std::fprintf(stderr, "count mismatch %s: dispatched=%zu prog=%zu\n",
                             name.c_str(), disp->records.size(), prog.calls().size());
            }
            continue;
        }

        // Per-call check: dispatched nr matches the target schema's nr for
        // each call's syscall.
        bool ok_this = true;
        for (std::size_t i = 0; i < disp->records.size(); ++i) {
            const auto* meta = prog.calls()[i]->meta();
            if (meta == nullptr) { ok_this = false; break; }
            if (disp->records[i].nr != meta->nr()) {
                ok_this = false;
                if (verbose) {
                    std::fprintf(stderr, "nr mismatch %s call %zu: got=%llu expected=%llu (%s)\n",
                                 name.c_str(), i,
                                 static_cast<unsigned long long>(disp->records[i].nr),
                                 static_cast<unsigned long long>(meta->nr()),
                                 meta->name().c_str());
                }
                break;
            }
        }
        if (!ok_this) { ++nr_mismatch; continue; }
        ++ok;
    }

    std::printf("total=%d ok=%d count_mismatch=%d nr_mismatch=%d "
                "driver_err=%d fail_encode=%d skip_decode=%d skip_kfuzz=%d "
                "skip_requires=%d skip_props=%d\n",
                total, ok, count_mismatch, nr_mismatch,
                driver_err, fail_encode, skip_decode, skip_kfuzz,
                skip_requires, skip_props);
    return (count_mismatch == 0 && nr_mismatch == 0 && driver_err == 0) ? 0 : 1;
}
