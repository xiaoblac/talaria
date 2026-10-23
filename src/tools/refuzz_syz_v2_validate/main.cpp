// refuzz-syz-v2-validate: batch validation oracle.
//
// Loads Target::linux_amd64() once, walks an input directory, decodes each
// .syz file, and runs validate() on the resulting Prog. Reports pass/fail
// counts and per-failure error messages.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/validation.hpp"

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

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> listDir(const std::string& path) {
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

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <indir> [-v]\n", argv[0]);
        return 2;
    }
    const std::string indir = argv[1];
    const bool verbose = (argc >= 3 && std::string(argv[2]) == "-v");

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    int decode_ok = 0, decode_fail = 0;
    int validate_ok = 0, validate_fail = 0;

    for (const auto& name : listDir(indir)) {
        const std::string text = readFile(indir + "/" + name);
        auto p = dec.decode(text);
        if (!p) {
            decode_fail++;
            if (verbose) {
                std::fprintf(stderr, "[decode-fail] %s: %s\n",
                             name.c_str(), p.error().message.c_str());
            }
            continue;
        }
        decode_ok++;
        auto v = syz::validate(**p);
        if (v) {
            validate_ok++;
        } else {
            validate_fail++;
            std::fprintf(stderr, "[validate-fail] %s: %s\n",
                         name.c_str(), v.error().message.c_str());
        }
    }

    std::printf("processed=%d decode_ok=%d decode_fail=%d "
                "validate_ok=%d validate_fail=%d\n",
                decode_ok + decode_fail,
                decode_ok, decode_fail,
                validate_ok, validate_fail);
    return validate_fail == 0 ? 0 : 1;
}
