// refuzz-syz-v2-gen — bulk program generator (§3.4).
//
// Drives the v2 mutator engine through the standard mutator/ contract
// (IMutatorEngine + MutatorManager) and writes each Mutate() output as
// a canonical .syz text file. The same artifact is consumed by:
//   * validate-on-generated oracle (§3.4 acceptance a)
//   * text-RT-on-generated oracle (§3.4 acceptance b)
//   * histogram-coverage oracle   (§3.4 acceptance c)
//
// The tool is a client of `IMutatorEngine`, not of the generator's
// free functions: it intentionally goes through MutatorManager →
// EngineHandle → Mutate(empty_seed) so that the engine boundary is
// the only cross-module surface.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <sys/stat.h>

namespace {

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s -outdir <dir> [-count N=100] [-ncalls lo:hi=2:8] "
        "[-seed S] [-policy NAME]\n",
        argv0);
}

void write_text(const std::string& path, const std::string& body) {
    std::ofstream f(path);
    f.write(body.data(), body.size());
}

} // namespace

int main(int argc, char** argv) {
    std::string outdir;
    std::string policy;
    int count = 100;
    int lo = 2;
    int hi = 8;
    uint64_t seed = std::random_device{}();
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "-count" && i + 1 < argc) count = std::atoi(argv[++i]);
        else if (a == "-ncalls" && i + 1 < argc) {
            std::string s = argv[++i];
            auto colon = s.find(':');
            if (colon != std::string::npos) {
                lo = std::atoi(s.substr(0, colon).c_str());
                hi = std::atoi(s.substr(colon + 1).c_str());
            } else {
                lo = hi = std::atoi(s.c_str());
            }
        } else if (a == "-seed" && i + 1 < argc) {
            seed = std::strtoull(argv[++i], nullptr, 10);
        } else if (a == "-policy" && i + 1 < argc) {
            policy = argv[++i];
        } else {
            usage(argv[0]); return 2;
        }
    }
    if (outdir.empty() || count <= 0 || lo <= 0 || hi < lo) { usage(argv[0]); return 2; }

    mkdir(outdir.c_str(), 0755);

    const auto& target = ::refuzz::program::syz::Target::linux_amd64();

    // Plug v2 engine into a private MutatorManager. Tool owns the manager;
    // the engine handle stays valid for the loop's lifetime. We construct
    // the engine directly (not via catalog) because the catalog factory
    // takes default ncalls range, and the tool wants user-controlled
    // values. Catalog registration still exists (mutator_catalog.cpp) for
    // control-side assembly.
    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target,
        /*corpus_store=*/nullptr,
        seed, lo, hi);

    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);

    // Engine plumbing smoke: optionally switch policy and report the
    // active name. With no -policy flag the engine starts on its
    // default (syz_v2_balanced); §3.4 oracle output is unchanged
    // because empty seeds always fall through to generation regardless
    // of mutation policy. ActivePolicyName is reported AFTER at least
    // one Mutate call because policy switch is lazy-applied at the top
    // of Mutate (mutator/design.md §7.3).
    auto& engine_handle = manager.Handle().Get();
    if (!policy.empty()) {
        const bool ok_switch = engine_handle.SwitchPolicyByName(policy);
        std::fprintf(stderr,
                     "engine=%s requested-policy=%s switch=%s\n",
                     engine_handle.Name().c_str(),
                     policy.c_str(),
                     ok_switch ? "ok" : "rejected");
    }

    refuzz::fuzzer::Seed empty_seed{};

    int ok = 0, gen_or_encode_fail = 0;
    for (int i = 0; i < count; ++i) {
        auto bytes = engine_handle.Mutate(empty_seed);
        if (bytes.empty()) {
            ++gen_or_encode_fail;
            continue;
        }
        char name[32];
        std::snprintf(name, sizeof(name), "%06d.syz", i);
        std::string text(bytes.begin(), bytes.end());
        write_text(outdir + "/" + name, text);
        ++ok;
    }
    std::printf("requested=%d ok=%d gen_or_encode_fail=%d seed=%llu\n",
                count, ok, gen_or_encode_fail,
                static_cast<unsigned long long>(seed));
    std::fprintf(stderr, "active-policy=%s\n",
                 engine_handle.ActivePolicyName().c_str());
    return 0;
}
