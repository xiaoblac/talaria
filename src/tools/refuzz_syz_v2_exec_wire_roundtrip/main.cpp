// refuzz-syz-v2-exec-wire-roundtrip: Layer-1 oracle for §3.3 decoder.
//
// For each .syz in <indir>, run:
//     TextDecoder.decode(text) → Prog (v2 IR)
//     serialize_for_exec(prog) → bytes
//     decode_exec_wire(bytes)  → WireProgram
//     encode_wire_program(wp)  → bytes'
// and assert bytes == bytes'. A mismatch indicates the decoder and
// encoder disagree on some part of the wire layout.
//
// Combined with §3.2's byte-equal-vs-syzkaller oracle, a passing
// roundtrip on the entire L3 corpus proves the wire is a bidirectional
// bijection with `prog.Prog.SerializeForExec` for every reFuzz-decoded
// program.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

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

namespace {

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

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <indir> [-q]\n", argv[0]);
        return 2;
    }
    const std::string indir = argv[1];
    const bool quiet = (argc >= 3 && std::strcmp(argv[2], "-q") == 0);

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    auto files = list_dir(indir);
    int total = 0, skip_decode = 0, skip_kfuzz = 0, fail_encode = 0;
    int fail_decode_wire = 0, mismatch = 0, ok = 0;
    int sample_count = 0;
    for (const auto& name : files) {
        ++total;
        std::string text = read_file(indir + "/" + name);
        auto result = dec.decode(text);
        if (!result) { ++skip_decode; continue; }
        const syz::Prog& prog = **result;
        if (prog_has_kfuzztest(prog)) { ++skip_kfuzz; continue; }

        auto bytes_or = syz::serialize_for_exec(prog);
        if (!bytes_or) { ++fail_encode; continue; }
        const auto& bytes = *bytes_or;

        auto wp_or = syz::decode_exec_wire(bytes);
        if (!wp_or) {
            ++fail_decode_wire;
            if (!quiet && sample_count < 5) {
                std::fprintf(stderr, "decode-fail %s @%zu: %s\n",
                             name.c_str(), wp_or.error().offset,
                             wp_or.error().message.c_str());
                ++sample_count;
            }
            continue;
        }
        auto bytes2 = syz::encode_wire_program(*wp_or);
        if (bytes == bytes2) {
            ++ok;
        } else {
            ++mismatch;
            if (!quiet && sample_count < 5) {
                std::size_t first = bytes.size();
                for (std::size_t i = 0; i < bytes.size() && i < bytes2.size(); ++i) {
                    if (bytes[i] != bytes2[i]) { first = i; break; }
                }
                std::fprintf(stderr,
                    "mismatch %s: sizes orig=%zu rt=%zu first-diff=%zu\n",
                    name.c_str(), bytes.size(), bytes2.size(), first);
                ++sample_count;
            }
        }
    }
    std::printf("total=%d ok=%d mismatch=%d fail_decode_wire=%d "
                "fail_encode=%d skip_decode=%d skip_kfuzz=%d\n",
                total, ok, mismatch, fail_decode_wire,
                fail_encode, skip_decode, skip_kfuzz);
    return (mismatch == 0 && fail_decode_wire == 0) ? 0 : 1;
}
