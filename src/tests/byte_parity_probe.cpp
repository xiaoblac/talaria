// One-shot probe: for each fixture, run reFuzz minimize, encode to
// canonical text, diff against golden body. Report per-fixture
// byte-equal status + first divergence line.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace syz = refuzz::program::syz;

struct Spec {
    std::string                       name;
    refuzz::crash::MinimizeMode       mode = refuzz::crash::MinimizeMode::kCrashSnapshot;
    int                               call_index = -1;
    std::string                       body;
    std::string                       golden_body;
};

std::string ReadFile(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}

void StripHeader(const std::string& text, std::string& out) {
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] != '#') {
            out.append(line); out.push_back('\n');
        }
    }
}

void ParseHeader(const std::string& text, Spec& s) {
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] != '#') {
            s.body.append(line); s.body.push_back('\n');
            continue;
        }
        std::string d = line.substr(1);
        size_t pos = d.find_first_not_of(" \t");
        if (pos != std::string::npos) d = d.substr(pos);
        std::istringstream ds(d);
        std::string kv;
        while (ds >> kv) {
            auto eq = kv.find('=');
            if (eq == std::string::npos) continue;
            std::string k = kv.substr(0, eq), v = kv.substr(eq+1);
            if (k == "mode") {
                using M = refuzz::crash::MinimizeMode;
                if (v == "corpus" || v == "crash_snapshot") s.mode = M::kCrashSnapshot;
                else if (v == "crash") s.mode = M::kCrash;
                else if (v == "calls_only") s.mode = M::kCallsOnly;
            } else if (k == "call_index") {
                s.call_index = std::atoi(v.c_str());
            }
        }
    }
}

int main() {
    const auto& target = syz::Target::linux_amd64();
    std::filesystem::path root("tests/data/minimize_golden");
    std::vector<std::filesystem::path> fixtures;
    for (const auto& e : std::filesystem::directory_iterator(root / "in")) {
        if (e.path().extension() == ".txt") fixtures.push_back(e.path());
    }
    std::sort(fixtures.begin(), fixtures.end());

    int byte_equal = 0, byte_diff = 0;
    for (const auto& fp : fixtures) {
        Spec s;
        s.name = fp.stem().string();
        std::string in_text = ReadFile(fp);
        ParseHeader(in_text, s);
        std::string golden_text = ReadFile(root / "out" / (s.name + ".golden"));
        StripHeader(golden_text, s.golden_body);

        syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);
        auto prog_or = dec.decode(s.body);
        if (!prog_or || !prog_or.value()) {
            std::fprintf(stdout, "%s: DECODE_FAIL\n", s.name.c_str()); continue;
        }
        refuzz::crash::TestFunc T = [](const std::vector<uint8_t>&) {
            return std::pair<bool, std::string>{true, ""};
        };
        refuzz::crash::StopFunc S = []() { return false; };
        refuzz::crash::ProgramMinimizer m;
        auto [r, _] = m.MinimizeProgTyped(*prog_or.value(), std::move(T),
                                          std::move(S), s.mode, s.call_index);
        if (r == nullptr) {
            std::fprintf(stdout, "%s: NULL\n", s.name.c_str()); continue;
        }
        syz::TextEncoder enc(target);
        std::string my_text = enc.encode(*r);
        if (my_text == s.golden_body) {
            std::fprintf(stdout, "BYTE_EQUAL  %s\n", s.name.c_str());
            ++byte_equal;
        } else {
            std::fprintf(stdout, "BYTE_DIFF   %s\n  reFuzz: %s  golden: %s",
                         s.name.c_str(), my_text.c_str(), s.golden_body.c_str());
            ++byte_diff;
        }
    }
    std::fprintf(stdout, "\nBYTE PARITY: %d equal / %d diff (out of %zu)\n",
                 byte_equal, byte_diff, fixtures.size());
    return 0;
}
