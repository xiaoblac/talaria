// refuzz-syz-v2-text-batch: batch round-trip of .syz files.
//
// Loads Target::linux_amd64() once, then walks an input directory and
// writes the round-tripped canonical form of each .syz file (or any file)
// to <outdir>/<basename>. Files that fail to decode are written with empty
// content + a sidecar `<basename>.err` containing the error message.

#include "refuzz/program/syz/encoding.hpp"
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

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void writeFile(const std::string& path, const std::string& body) {
    std::ofstream f(path);
    f.write(body.data(), body.size());
}

std::vector<std::string> listDir(const std::string& path) {
    std::vector<std::string> out;
    DIR* d = opendir(path.c_str());
    if (d == nullptr) return out;
    while (auto* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        if (n.size() >= 4 && n.compare(n.size() - 4, 4, ".err") == 0) {
            continue;
        }
        std::string full = path + "/" + n;
        struct stat err_st{};
        if (stat((full + ".err").c_str(), &err_st) == 0 && S_ISREG(err_st.st_mode)) {
            continue;
        }
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
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <indir> <outdir>\n", argv[0]);
        return 2;
    }
    const std::string indir  = argv[1];
    const std::string outdir = argv[2];

    mkdir(outdir.c_str(), 0755);

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);
    syz::TextEncoder enc(target);

    auto files = listDir(indir);
    int ok = 0, fail = 0;
    for (const auto& name : files) {
        const std::string in_path  = indir + "/" + name;
        const std::string out_path = outdir + "/" + name;
        const std::string err_path = outdir + "/" + name + ".err";

        std::string text = readFile(in_path);
        auto result = dec.decode(text);
        if (!result) {
            const auto& e = result.error();
            writeFile(out_path, "");
            char buf[256];
            std::snprintf(buf, sizeof(buf), "line %d col %d: %s\n",
                          e.line, e.column, e.message.c_str());
            writeFile(err_path, buf);
            fail++;
            continue;
        }
        writeFile(out_path, enc.encode(**result));
        // Remove any stale .err sidecar from a previous run that wrote
        // into the same outdir. Without this a second invocation could
        // observe a phantom failure and pollute the comparator.
        std::remove(err_path.c_str());
        ok++;
    }
    std::printf("processed=%zu ok=%d fail=%d\n", files.size(), ok, fail);
    return 0;
}
