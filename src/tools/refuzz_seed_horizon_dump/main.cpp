// refuzz-seed-horizon-dump — emit the STATIC resource-precondition model the
// in-engine SeedHorizon signal builds future(seed) on (docs/plans/
// structural-horizon-seed-value.md: the SpecHorizon-RD resource-frontier horizon).
//
// Read off the finalized Target, independent of any execution, so it already
// names handoffs no seed has taken yet (§1). For every resource TYPE it emits the
// kind hierarchy (subtype → supertype chain) and two DE-FLATTENER counts that turn
// the flat resource graph into the rarity-discounted horizon — the corrections
// that separate this from the prior flat Layer-A (89 distinct values / 270-way fd
// tie / lost to backward):
//   * producer_count(T) : # syscalls that can create T → inverse-producer edge
//                         weight 1/producer_count(T) (de-flattens the producers).
//   * consumer_count(T) : # syscalls that consume/use T → exposes the hub: the
//                         generic `fd` kind is wanted by hundreds of consumers
//                         (heavily discounted) while a specific leaf is wanted by
//                         few (high specificity) — this is what KILLS the
//                         hub-inheritance that flattened the prior resource graph.
// Plus, per syscall, which resource types it produces / consumes / uses.
//
// Usage: refuzz-seed-horizon-dump [-out PATH]   (default: stdout)
// Output: a single JSON object {os,arch,revision,resources[],syscalls[]}.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace refuzz_syz = ::refuzz::program::syz;

namespace {

// Minimal JSON string escape. Resource/syscall names are C identifiers plus
// '$', '_', digits — no control chars — but escape '"' and '\\' defensively.
std::string esc(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 2);
    for (char c : s) {
        if (c == '"' || c == '\\') o.push_back('\\');
        o.push_back(c);
    }
    return o;
}

void emit_str_array(std::string& out, const std::vector<std::string>& v)
{
    out.push_back('[');
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out.push_back(',');
        out.push_back('"');
        out += esc(v[i]);
        out.push_back('"');
    }
    out.push_back(']');
}

// Dedup the resource-type names a syscall references in one direction.
std::vector<std::string> res_names(const std::vector<const refuzz_syz::ResourceDesc*>& rs)
{
    std::set<std::string> uniq;
    for (const auto* r : rs) {
        if (r) uniq.insert(r->name());
    }
    return {uniq.begin(), uniq.end()};
}

} // namespace

int main(int argc, char** argv)
{
    const char* out_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    const auto& target = refuzz_syz::Target::linux_amd64();

    // De-flattener counts (distinct producing / consuming syscalls per resource
    // TYPE). producer_count → inverse-producer edge weight; consumer_count →
    // hub-discount (generic `fd` huge → killed; specific leaf small → kept).
    std::map<std::string, int> producer_count;
    std::map<std::string, int> consumer_count;
    for (const auto& sc : target.syscalls()) {
        std::set<std::string> produced;
        for (const auto* r : sc->creates_resources()) {
            if (r) produced.insert(r->name());
        }
        for (const auto& n : produced) ++producer_count[n];

        // input_resources ONLY: uses_resources() = created ∪ consumed here, so
        // counting it would miscount producers of T as consumers of T.
        std::set<std::string> consumed;  // distinct consumed types per call
        for (const auto* r : sc->input_resources()) {
            if (r) consumed.insert(r->name());
        }
        for (const auto& n : consumed) ++consumer_count[n];
    }

    // Static ChoiceTable — the call-transition prior (prog/prio.go analogue),
    // built WITHOUT a corpus so only the STATIC (resource/arg-derived) component
    // is present; the dynamic co-occurrence term (= backward) is excluded by
    // construction. prios()[i][j] = static priority of issuing call j after i.
    refuzz::mutator::syz_v2::ChoiceTable choice_table;
    choice_table.build(target);
    const auto& prios = choice_table.prios();
    constexpr size_t kTopSucc = 24;  // sparse: top-K static successors per call

    std::string out;
    out.reserve(1 << 20);
    out += "{\n";
    out += "\"os\":\"" + esc(target.os()) + "\",";
    out += "\"arch\":\"" + esc(target.arch()) + "\",";
    out += "\"revision\":\"" + esc(target.revision()) + "\",\n";

    // resources: name + kind hierarchy (kind[0] is the broadest base, last is
    // the type itself). A produced type P satisfies a consumer wanting type W
    // iff W appears in P's kind list (subtype satisfies supertype).
    out += "\"resources\":[\n";
    const auto& descs = target.resource_arena().descs();
    for (size_t i = 0; i < descs.size(); ++i) {
        const auto& d = descs[i];
        const auto pc = producer_count.find(d->name());
        const auto cc = consumer_count.find(d->name());
        out += "{\"name\":\"" + esc(d->name()) + "\",\"kind\":";
        emit_str_array(out, d->kind());
        out += ",\"producer_count\":" +
               std::to_string(pc == producer_count.end() ? 0 : pc->second);
        out += ",\"consumer_count\":" +
               std::to_string(cc == consumer_count.end() ? 0 : cc->second);
        out += "}";
        if (i + 1 < descs.size()) out += ",";
        out += "\n";
    }
    out += "],\n";

    // syscalls: produces / consumes / uses, by resource-type name.
    out += "\"syscalls\":[\n";
    const auto& calls = target.syscalls();
    for (size_t i = 0; i < calls.size(); ++i) {
        const auto& sc = calls[i];
        out += "{\"name\":\"" + esc(sc->name()) + "\",";
        out += "\"produces\":";
        emit_str_array(out, res_names(sc->creates_resources()));
        out += ",\"consumes\":";
        emit_str_array(out, res_names(sc->input_resources()));
        out += ",\"uses\":";
        emit_str_array(out, res_names(sc->uses_resources()));
        // top-K static call-transition successors as [succ_id, prio] pairs
        // (sparse). succ_id indexes this same syscalls[] array.
        out += ",\"succ\":[";
        if (i < prios.size()) {
            const auto& row = prios[i];
            std::vector<std::pair<int32_t, int>> cand;
            cand.reserve(row.size());
            for (size_t j = 0; j < row.size(); ++j) {
                if (j != i && row[j] > 0) {
                    cand.emplace_back(row[j], static_cast<int>(j));
                }
            }
            const size_t k = std::min(kTopSucc, cand.size());
            std::partial_sort(cand.begin(), cand.begin() + k, cand.end(),
                              [](const auto& a, const auto& b) { return a.first > b.first; });
            for (size_t t = 0; t < k; ++t) {
                if (t) out += ",";
                out += "[" + std::to_string(cand[t].second) + "," +
                       std::to_string(cand[t].first) + "]";
            }
        }
        out += "]";
        out += "}";
        if (i + 1 < calls.size()) out += ",";
        out += "\n";
    }
    out += "]\n}\n";

    if (out_path) {
        FILE* f = std::fopen(out_path, "wb");
        if (!f) {
            std::fprintf(stderr, "cannot open %s for write\n", out_path);
            return 1;
        }
        std::fwrite(out.data(), 1, out.size(), f);
        std::fclose(f);
        std::fprintf(stderr, "wrote %zu bytes: %zu resources, %zu syscalls\n",
                     out.size(), descs.size(), calls.size());
    } else {
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return 0;
}
