// refuzz-corpus-memprobe — MEASURE the real in-memory footprint of a materialized
// corpus. Decodes each <root>/<seed_id>/payload.bin → Prog, runs the same
// SegmentizeMountImages the fuzz-loop materializer uses, HOLDS every Prog in
// memory, and reports actual RSS growth + the SEGS image bytes carried per seed.
//
// Answers "does the corpus really occupy that much, and where" with a measurement
// (held Prog RSS) instead of arithmetic inference.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/mount_image_segment.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace syz = ::refuzz::program::syz;

namespace {

long RssKb() {
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            long kb = 0;
            std::sscanf(line.c_str(), "VmRSS: %ld", &kb);
            return kb;
        }
    }
    return 0;
}

bool ReadFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool IsDir(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

std::vector<std::string> ListSorted(const std::string& path) {
    std::vector<std::string> e;
    DIR* d = ::opendir(path.c_str());
    if (!d) return e;
    while (auto* ent = ::readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        e.push_back(std::move(n));
    }
    ::closedir(d);
    std::sort(e.begin(), e.end());
    return e;
}

struct NodeStats {
    std::uint64_t nodes = 0;
    std::uint64_t struct_bytes = 0;   // sum of sizeof(node) — live object size
    std::uint64_t data_bytes = 0;     // DataArg payload (image bytes)
    std::uint64_t vec_overhead = 0;   // vector capacity-beyond-size (over-alloc)
    std::uint64_t n_const = 0, n_ptr = 0, n_data = 0, n_group = 0, n_union = 0, n_other = 0;
};

void Walk(const syz::Arg* a, NodeStats& s) {
    if (a == nullptr) return;
    ++s.nodes;
    switch (a->arg_kind()) {
        case syz::ArgKind::kConst:
            ++s.n_const; s.struct_bytes += sizeof(syz::ConstArg); break;
        case syz::ArgKind::kPointer: {
            ++s.n_ptr; s.struct_bytes += sizeof(syz::PointerArg);
            Walk(static_cast<const syz::PointerArg*>(a)->res(), s); break;
        }
        case syz::ArgKind::kData: {
            ++s.n_data; s.struct_bytes += sizeof(syz::DataArg);
            const auto& d = static_cast<const syz::DataArg*>(a)->data();
            s.data_bytes += d.size();
            s.vec_overhead += (d.capacity() - d.size());
            break;
        }
        case syz::ArgKind::kGroup: {
            ++s.n_group; s.struct_bytes += sizeof(syz::GroupArg);
            const auto& in = static_cast<const syz::GroupArg*>(a)->inner();
            s.vec_overhead += (in.capacity() - in.size()) * sizeof(void*);
            for (const auto& c : in) Walk(c.get(), s);
            break;
        }
        case syz::ArgKind::kUnion: {
            ++s.n_union; s.struct_bytes += sizeof(syz::UnionArg);
            Walk(static_cast<const syz::UnionArg*>(a)->option(), s); break;
        }
        default:
            ++s.n_other; s.struct_bytes += 64; break;
    }
}

NodeStats ProgStats(const syz::Prog& prog) {
    NodeStats s;
    for (const auto& call : prog.calls()) {
        if (call == nullptr) continue;
        for (const auto& arg : call->args()) Walk(arg.get(), s);
    }
    return s;
}

std::size_t ImageBytes(const syz::Prog& prog) { return ProgStats(prog).data_bytes; }

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <corpus_root>\n", argv[0]);
        return 2;
    }
    const std::string root = argv[1];
    if (!IsDir(root)) {
        std::fprintf(stderr, "not a dir: %s\n", root.c_str());
        return 1;
    }

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder decoder(target, syz::DecodeMode::kNonStrict);

    const long rss0 = RssKb();
    std::vector<std::unique_ptr<syz::Prog>> held;   // hold every Prog resident
    std::size_t n = 0, fail = 0, mount_seeds = 0;
    std::uint64_t img_total = 0, payload_total = 0, img_max = 0;
    NodeStats agg;
    std::uint64_t total_calls = 0;
    std::uint64_t max_nodes = 0, max_nodes_calls = 0;

    for (const auto& name : ListSorted(root)) {
        const std::string pp = root + "/" + name + "/payload.bin";
        std::string text;
        if (!ReadFile(pp, text)) continue;
        payload_total += text.size();
        auto r = decoder.decode(text);
        if (!r) { ++fail; continue; }
        auto prog = std::move(*r);
        syz::SegmentizeMountImages(*prog, target);
        NodeStats s = ProgStats(*prog);
        agg.nodes += s.nodes; agg.struct_bytes += s.struct_bytes; agg.data_bytes += s.data_bytes;
        agg.vec_overhead += s.vec_overhead;
        agg.n_const += s.n_const; agg.n_ptr += s.n_ptr; agg.n_data += s.n_data;
        agg.n_group += s.n_group; agg.n_union += s.n_union; agg.n_other += s.n_other;
        total_calls += prog->calls().size();
        if (s.nodes > max_nodes) { max_nodes = s.nodes; max_nodes_calls = prog->calls().size(); }
        if (s.data_bytes > 0) { ++mount_seeds; img_total += s.data_bytes; img_max = std::max<std::uint64_t>(img_max, s.data_bytes); }
        held.push_back(std::move(prog));
        ++n;
    }
    const long rss1 = RssKb();

    const double mb = 1024.0 * 1024.0;
    std::printf("seeds_held=%zu  decode_fail=%zu  mount_image_seeds=%zu  total_calls=%llu (avg %.1f/seed)\n",
                n, fail, mount_seeds, (unsigned long long)total_calls, n ? total_calls*1.0/n : 0);
    std::printf("payload_on_disk = %.1f MB (%.1f KB/seed)   SEGS image = %.1f MB (avg %.1f KB, max %.1f KB)\n",
                payload_total/mb, n?payload_total/1024.0/n:0, img_total/mb,
                mount_seeds?img_total/1024.0/mount_seeds:0, img_max/1024.0);
    std::printf("RSS held = %.1f MB  →  %.1f KB/seed   (rss %ld→%ld kB,  %.1fx payload)\n",
                (rss1-rss0)/mb*1024, n?(rss1-rss0)*1.0/n:0, rss0, rss1,
                payload_total?(rss1-rss0)*1024.0/payload_total:0);
    std::printf("--- AST node breakdown ---\n");
    std::printf("total AST nodes = %llu  (avg %.0f nodes/seed, %.1f nodes/syscall)   MAX prog: %llu nodes / %llu calls\n",
                (unsigned long long)agg.nodes, n?agg.nodes*1.0/n:0,
                total_calls?agg.nodes*1.0/total_calls:0,
                (unsigned long long)max_nodes, (unsigned long long)max_nodes_calls);
    std::printf("by kind: const=%llu ptr=%llu data=%llu group=%llu union=%llu other=%llu\n",
                (unsigned long long)agg.n_const,(unsigned long long)agg.n_ptr,(unsigned long long)agg.n_data,
                (unsigned long long)agg.n_group,(unsigned long long)agg.n_union,(unsigned long long)agg.n_other);
    std::printf("sizeof: Const=%zu Pointer=%zu Data=%zu Group=%zu Union=%zu\n",
                sizeof(syz::ConstArg),sizeof(syz::PointerArg),sizeof(syz::DataArg),
                sizeof(syz::GroupArg),sizeof(syz::UnionArg));
    std::printf("LIVE struct bytes (Σsizeof) = %.1f MB   vector over-alloc = %.1f MB   image data = %.1f MB\n",
                agg.struct_bytes/mb, agg.vec_overhead/mb, agg.data_bytes/mb);
    std::printf("=> accounted live = %.1f MB ; RSS held = %.1f MB ; GAP(malloc overhead/frag) = %.1f MB (%.0f%%)\n",
                (agg.struct_bytes+agg.data_bytes)/mb, (rss1-rss0)/mb*1024,
                ((rss1-rss0)*1024.0-(agg.struct_bytes+agg.data_bytes))/mb,
                (rss1-rss0)?100.0*((rss1-rss0)*1024.0-(agg.struct_bytes+agg.data_bytes))/((rss1-rss0)*1024.0):0);
    return 0;
}
