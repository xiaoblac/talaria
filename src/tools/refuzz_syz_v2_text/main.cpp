// refuzz-syz-v2-text: read a .syz file, parse via reFuzz v2 IR text codec,
// re-emit via the v2 encoder. Intended for byte-level oracle diff against
// syzkaller Go-side prog.Deserialize → prog.Serialize.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file.syz>\n", argv[0]);
        return 2;
    }
    std::ifstream f(argv[1]);
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string text = ss.str();

    const auto& target = refuzz::program::syz::Target::linux_amd64();
    refuzz::program::syz::TextDecoder dec(
        target, refuzz::program::syz::DecodeMode::kNonStrict);

    auto result = dec.decode(text);
    if (!result) {
        const auto& err = result.error();
        std::fprintf(stderr, "decode error at line %d col %d: %s\n",
                     err.line, err.column, err.message.c_str());
        return 1;
    }

    refuzz::program::syz::TextEncoder enc(target);
    const std::string out = enc.encode(**result);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}
