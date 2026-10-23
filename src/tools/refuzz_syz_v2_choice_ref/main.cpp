// refuzz-syz-v2-choice-ref — emit a choice-table reference report
// matching `tools/syzgen choice-ref` JSON shape (§3.6 M0 oracle).
//
// Usage: refuzz-syz-v2-choice-ref [-out PATH]
//
// Output: JSON with the same structure as Go's choice_ref.go. We only
// emit the `anchors` block byte-equal to Go; the `phase / step / kind /
// generated_at_utc / syzkaller / target` headers are stable strings —
// the diff oracle compares only the `anchors` array (jq path) for
// byte equality.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

// Match docs/syzkaller-integration/reports/.../choiceRefAnchorsLinuxAmd64.
const std::vector<std::string> kAnchorsLinuxAmd64 = {
    "openat",
    "socket",
    "pipe",
    "pipe2",
    "dup",
    "accept",
    "close",
    "read",
    "write",
    "ioctl",
    "mmap",
    "epoll_create1",
    "eventfd2",
    "signalfd4",
    "timerfd_create",
    "inotify_init1",
    "memfd_create",
    "pidfd_open",
};

constexpr int kTopK = 20;

void usage(const char* argv0) {
    std::fprintf(stderr, "usage: %s [-out PATH]\n", argv0);
}

std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    std::string out_path;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-out" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    namespace mut_v2 = ::refuzz::mutator::syz_v2;
    namespace syz    = ::refuzz::program::syz;

    const auto& target = syz::Target::linux_amd64();

    // This oracle is byte-equal-vs-Go: Go side calls
    // `target.CalculatePriorities(nil, nil)` (tools/syzgen/choice_ref.go)
    // which has no pseudo filter; the C++ ChoiceTable build only excludes
    // syz's (disabled) calls + the (empty here) enable/disable whitelist.
    mut_v2::ChoiceTable ct;
    ct.build(target);

    // Build name → SyscallMeta map for anchor lookup.
    std::vector<const syz::SyscallMeta*> by_id(target.syscalls().size(), nullptr);
    std::unordered_map<std::string, const syz::SyscallMeta*> by_name;
    for (const auto& sc_up : target.syscalls()) {
        if (!sc_up) continue;
        if (sc_up->id() < by_id.size()) by_id[sc_up->id()] = sc_up.get();
        by_name.emplace(sc_up->name(), sc_up.get());
    }

    std::ostringstream os;
    os << "{\n";
    os << "  \"phase\": \"C\",\n";
    os << "  \"step\": \"C1\",\n";
    os << "  \"kind\": \"choice_table_reference\",\n";
    os << "  \"generated_at_utc\": \"\",\n";
    os << "  \"syzkaller\": {\n";
    os << "    \"pin\": \"\",\n";
    os << "    \"observed\": \"\",\n";
    os << "    \"pinned\": false\n";
    os << "  },\n";
    os << "  \"target\": {\n";
    os << "    \"os\": \"linux\",\n";
    os << "    \"arch\": \"amd64\"\n";
    os << "  },\n";
    os << "  \"anchors\": [";

    bool first_anchor = true;
    for (const std::string& name : kAnchorsLinuxAmd64) {
        auto it = by_name.find(name);
        if (it == by_name.end()) {
            std::fprintf(stderr,
                         "anchor syscall %s not found in target linux/amd64\n",
                         name.c_str());
            return 1;
        }
        const syz::SyscallMeta* sc = it->second;
        const uint64_t id = sc->id();
        const auto& row = ct.prios()[id];

        // row_sum = sum of all prios (including disabled cols and self;
        // mirror Go which sums the whole row).
        int64_t row_sum = 0;
        for (int32_t v : row) row_sum += v;

        // top_edges: enabled-only, exclude self, sort by (prio desc,
        // name asc), keep top-K.
        struct Edge { std::string name; int id; int32_t prio; };
        std::vector<Edge> edges;
        for (size_t j = 0; j < row.size(); ++j) {
            if (row[j] == 0 || j == id) continue;
            const syz::SyscallMeta* dst = (j < by_id.size()) ? by_id[j] : nullptr;
            if (dst == nullptr) continue;
            if (!ct.enabled_call(j)) continue;
            edges.push_back(Edge{dst->name(), static_cast<int>(j), row[j]});
        }
        std::sort(edges.begin(), edges.end(), [](const Edge& a, const Edge& b) {
            if (a.prio != b.prio) return a.prio > b.prio;
            return a.name < b.name;
        });
        if (static_cast<int>(edges.size()) > kTopK) edges.resize(kTopK);

        if (!first_anchor) os << ",";
        first_anchor = false;
        os << "\n    {\n";
        os << "      \"name\": \"" << escape_json(name) << "\",\n";
        os << "      \"id\": " << id << ",\n";
        os << "      \"selectable\": " << (ct.enabled_call(id) ? "true" : "false") << ",\n";
        os << "      \"row_sum\": " << row_sum << ",\n";
        if (edges.empty()) {
            os << "      \"top_edges\": null\n";
        } else {
            os << "      \"top_edges\": [\n";
            for (size_t i = 0; i < edges.size(); ++i) {
                os << "        {\n";
                os << "          \"name\": \"" << escape_json(edges[i].name) << "\",\n";
                os << "          \"id\": " << edges[i].id << ",\n";
                os << "          \"prio\": " << edges[i].prio << "\n";
                os << "        }" << (i + 1 < edges.size() ? "," : "") << "\n";
            }
            os << "      ]\n";
        }
        os << "    }";
    }

    os << "\n  ]\n}\n";

    const std::string body = os.str();
    if (out_path.empty()) {
        std::fwrite(body.data(), 1, body.size(), stdout);
    } else {
        std::ofstream f(out_path);
        f.write(body.data(), body.size());
        std::fprintf(stderr, "wrote %s (%zu anchors)\n",
                     out_path.c_str(), kAnchorsLinuxAmd64.size());
    }
    return 0;
}
