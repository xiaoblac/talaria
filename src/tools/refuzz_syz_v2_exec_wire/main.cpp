// refuzz-syz-v2-exec-wire: batch exec-wire encoder for the L3 corpus.
//
// Loads Target::linux_amd64() once, walks an input directory, decodes
// each .syz via the v2 TextDecoder (non-strict), then writes the
// SerializeForExec byte stream to <outdir>/<basename>. Files that fail
// to decode are skipped (no output, no .err — the §3.2 oracle considers
// them incomparable). Files whose syscall is KFuzzTest are also skipped.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
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

void write_file(const std::string& path, const std::vector<uint8_t>& body) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(body.data()),
            static_cast<std::streamsize>(body.size()));
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
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <indir> <outdir>\n", argv[0]);
        return 2;
    }
    const std::string indir  = argv[1];
    const std::string outdir = argv[2];

    mkdir(outdir.c_str(), 0755);

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    auto files = list_dir(indir);
    int ok = 0, skip_decode = 0, skip_kfuzz = 0, fail_encode = 0;
    for (const auto& name : files) {
        const std::string in_path  = indir + "/" + name;
        const std::string out_path = outdir + "/" + name;

        std::string text = read_file(in_path);
        auto result = dec.decode(text);
        if (!result) { skip_decode++; continue; }
        const syz::Prog& prog = **result;
        if (prog_has_kfuzztest(prog)) { skip_kfuzz++; continue; }

        auto bytes = syz::serialize_for_exec(prog);
        if (!bytes) { fail_encode++; continue; }
        write_file(out_path, *bytes);
        ok++;
    }
    std::printf("processed=%zu ok=%d skip_decode=%d skip_kfuzz=%d fail_encode=%d\n",
                files.size(), ok, skip_decode, skip_kfuzz, fail_encode);
    return 0;
}
