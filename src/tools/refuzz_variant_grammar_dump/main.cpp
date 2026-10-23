// refuzz-variant-grammar-dump — per-variant cmd const VALUES + input resources,
// read STRUCTURALLY off the finalized Target (the syzlang grammar), NOT by name.
//
// This is the grammar side of the structural variant->handler binding: a
// cmd-dispatched variant (ioctl$X / setsockopt$Y) fixes its discriminant as a
// `const[VALUE]` in the grammar; that VALUE is the exact join key into the kernel's
// ioctl/ops dispatch tables (extracted from .rodata). We emit, per variant, every
// top-level const arg value (the cmd/level/optname discriminants) and the resource
// types it consumes (the fd it operates on). No name matching anywhere.
//
// docs/plans/variant-handler-binding-report.md. Usage: refuzz-variant-grammar-dump  (stdout JSONL)

#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <string>

namespace syz = refuzz::program::syz;

static std::string esc(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '"' || c == '\\') {
            o += '\\';
        }
        o += c;
    }
    return o;
}

int main()
{
    const auto& target = syz::Target::linux_amd64();
    std::string out;
    out.reserve(1 << 20);
    for (const auto& sc : target.syscalls()) {
        if (!sc) {
            continue;
        }
        out += "{\"name\":\"" + esc(sc->name()) + "\",\"consts\":[";
        bool first = true;
        for (const auto& f : sc->args()) {
            // top-level const discriminants (ioctl cmd / setsockopt level+optname).
            if (const syz::ConstType* ct = syz::as_const(f.type())) {
                if (!first) {
                    out += ",";
                }
                out += std::to_string(ct->val());
                first = false;
            }
        }
        out += "],\"resources\":[";
        first = true;
        for (const auto* r : sc->input_resources()) {
            if (r != nullptr) {
                if (!first) {
                    out += ",";
                }
                out += "\"" + esc(r->name()) + "\"";
                first = false;
            }
        }
        out += "]}\n";
    }
    std::fputs(out.c_str(), stdout);
    return 0;
}
