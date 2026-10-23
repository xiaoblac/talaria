// refuzz-syz-v2-mutate — bulk mutator harness (§3.5).
//
// Reads .syz text files from -indir, drives SyzV2MutatorEngine through
// the standard mutator/ contract (IMutatorEngine + MutatorManager),
// and writes each Mutate() output as a canonical .syz text file under
// -outdir. The same artifact is consumed by:
//   * mutate-validate oracle  (§3.5 acceptance)
//   * mutate-resource-integrity oracle (§3.5 acceptance)
//   * mutate-fixed-point oracle (§3.5 acceptance)
//
// In M0 every op returns false, so the engine emits the original
// payload byte-for-byte for every non-empty seed; in subsequent
// milestones the same tool drives real mutations.

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

namespace {

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s -indir <dir> -outdir <dir> [-count N=1000] "
        "[-policy NAME=syz_v2_balanced] [-seed S]\n",
        argv0);
}

std::string slurp_file(const std::string& path) {
    std::ifstream f(path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void write_text(const std::string& path, const std::string& body) {
    std::ofstream f(path);
    f.write(body.data(), body.size());
}

// In-memory ICorpusStore so splice op (§3.5 M2) can sample donors from
// the same -indir input set the tool reads. The §3.5 acceptance bar
// runs splice on L3 corpus, so it makes sense to expose -indir as
// donor source by default — no separate -corpus flag.
class IndirCorpusStore final : public refuzz::fuzzer::ICorpusStore {
public:
    bool AddSeed(refuzz::fuzzer::Seed seed) override {
        const uint64_t id = seed.seed_id;
        order_.push_back(id);
        seeds_[id] = std::make_shared<refuzz::fuzzer::Seed>(std::move(seed));
        return true;
    }
    refuzz::fuzzer::SeedHandle GetSeed(uint64_t id) const override {
        auto it = seeds_.find(id);
        return it == seeds_.end() ? nullptr : it->second;
    }
    void ForEachSeed(const refuzz::fuzzer::SeedVisitor& visitor) const override {
        if (!visitor) return;
        for (const uint64_t id : order_) {
            auto it = seeds_.find(id);
            if (it != seeds_.end()) visitor(*it->second);
        }
    }
    std::optional<uint64_t> SampleSeedId(std::mt19937_64& rng) const override {
        if (order_.empty()) return std::nullopt;
        std::uniform_int_distribution<size_t> dist(0, order_.size() - 1);
        return order_[dist(rng)];
    }
    void MarkInteresting(uint64_t) override {}
    size_t Size() const override { return seeds_.size(); }

private:
    std::vector<uint64_t> order_;
    std::unordered_map<uint64_t,
                       std::shared_ptr<refuzz::fuzzer::Seed>> seeds_;
};

// Match refuzz-syz-v2-validate convention: any regular file in dir is a
// candidate. The L3 corpus files at sys/linux/test/ have no extension.
std::vector<std::string> list_corpus_files(const std::string& dir) {
    std::vector<std::string> files;
    DIR* d = opendir(dir.c_str());
    if (!d) return files;
    while (struct dirent* e = readdir(d)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        struct stat st{};
        if (stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            files.push_back(full);
        }
    }
    closedir(d);
    return files;
}

} // namespace

int main(int argc, char** argv) {
    std::string indir;
    std::string outdir;
    std::string policy = "syz_v2_balanced";
    int count = 1000;
    uint64_t seed = std::random_device{}();

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-indir" && i + 1 < argc) indir = argv[++i];
        else if (a == "-outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "-count" && i + 1 < argc) count = std::atoi(argv[++i]);
        else if (a == "-policy" && i + 1 < argc) policy = argv[++i];
        else if (a == "-seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 10);
        else { usage(argv[0]); return 2; }
    }
    if (indir.empty() || outdir.empty() || count <= 0) { usage(argv[0]); return 2; }

    auto files = list_corpus_files(indir);
    if (files.empty()) {
        std::fprintf(stderr, "no regular files found in %s\n", indir.c_str());
        return 2;
    }
    mkdir(outdir.c_str(), 0755);

    const auto& target = ::refuzz::program::syz::Target::linux_amd64();

    // Build an in-memory corpus store from the same -indir set so the
    // splice op (§3.5 M2) has donor candidates. seed_id is the file
    // index; payload is the file body. Tool ownership: store outlives
    // the engine (declared first, dropped last).
    //
    // [arch parity NOTE — 2026-05-11]
    // 这里**故意不**走 MakeRegistryMaterializer(kSyzProg, target) + StrictTyped
    // 过滤——跟 production CorpusDiskIO::LoadAll 行为不一致。后果:
    //   - sys/linux/test L3 corpus 自带 ~37 个 arm64-only prog
    //     (syz_kvm_setup_syzos_vm$arm64 / ioctl$KVM_ARM_VCPU_INIT 等),
    //   - 它们直接被 AddSeed 塞进 corpus_store,mutator decode 失败时
    //     按 syz_v2_engine.cpp:287-289 契约**透传原 bytes**,
    //   - oracle 跑完 refuzz-syz-v2-validate 会看到 decode_fail ≈ 46/1000
    //     (跟 indir baseline 37/861 同比例),所有 single-op + balanced
    //     都一致。
    // production(kernel profile) 已用 CorpusLoadPolicy::StrictTyped +
    // (kSyzProg, linux/amd64) materializer 在 LoadAll 阶段把 arm64 prog drop,
    // 这条 oracle 路径不影响生产。
    //
    // **以后改的时候记得**:
    //   1) 加新 arch 时是横向 — 新 profile 自报 build_decoder
    //      (eg. MakeRegistryMaterializer(kSyzProg, linux/arm64)),
    //      不要改现有 amd64 严格过滤;
    //   2) 若要让 oracle decode_fail=0(跟 production 字节一致),在此处接
    //      materializer 过滤 + drop 即可 — 但 oracle 行为变化要同步更新
    //      run_all_oracles.sh 的 decode_fail 阈值与本文件注释。
    IndirCorpusStore corpus_store;
    for (size_t i = 0; i < files.size(); ++i) {
        refuzz::fuzzer::Seed s;
        s.seed_id = static_cast<uint64_t>(i);
        std::string body = slurp_file(files[i]);
        s.payload = std::vector<uint8_t>(body.begin(), body.end());
        corpus_store.AddSeed(std::move(s));
    }

    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target,
        /*corpus_store=*/&corpus_store,
        seed);

    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);

    auto& engine_handle = manager.Handle().Get();
    const bool ok_switch = engine_handle.SwitchPolicyByName(policy);
    if (!ok_switch) {
        std::fprintf(stderr,
                     "policy %s rejected by engine; valid names: "
                     "syz_v2_balanced, syz_v2_splice_heavy, syz_v2_insert_call, "
                     "syz_v2_mutate_arg, syz_v2_remove_call, syz_v2_squash_any\n",
                     policy.c_str());
        return 2;
    }

    std::mt19937_64 picker(seed ^ 0xC2B2AE3D27D4EB4FULL);
    std::uniform_int_distribution<size_t> pick(0, files.size() - 1);

    int ok = 0, mutate_empty = 0;
    for (int i = 0; i < count; ++i) {
        const std::string& path = files[pick(picker)];
        refuzz::fuzzer::Seed s;
        s.seed_id = static_cast<uint64_t>(i);
        std::string body = slurp_file(path);
        s.payload = std::vector<uint8_t>(body.begin(), body.end());

        auto bytes = engine_handle.Mutate(s);
        if (bytes.empty()) {
            ++mutate_empty;
            continue;
        }
        char name[64];
        std::snprintf(name, sizeof(name), "%06d.syz", i);
        write_text(outdir + "/" + name,
                   std::string(bytes.begin(), bytes.end()));
        ++ok;
    }

    std::printf("requested=%d ok=%d mutate_empty=%d in_files=%zu seed=%llu policy=%s\n",
                count, ok, mutate_empty, files.size(),
                static_cast<unsigned long long>(seed),
                engine_handle.ActivePolicyName().c_str());
    return 0;
}
