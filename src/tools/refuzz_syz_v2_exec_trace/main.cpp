// refuzz-syz-v2-exec-trace: Layer-3 milestone I.3 — C++-side trace
// dumper.
//
// For each .syz in <indir>:
//   TextDecoder.decode(text) → Prog (v2 IR)
//   serialize_for_exec(prog) → wire bytes
//   decode_exec_wire(bytes)  → WireProgram
//   walk WireProgram, emit JSONL line matching the schema in
//   program/include/refuzz/program/syz/exec_trace.hpp.
//
// Two key independence properties vs the Go reference dumper:
//   (1) info source: Go reads prog.Prog; we read wire bytes.
//   (2) extraction logic: Go runs writeArg-equivalent dispatch from
//       IR types; we read variant tags out of WireArg.
// Byte-equal JSONL on the L3 corpus therefore proves the wire is a
// faithful preservation of the call dispatch shape — stronger than the
// §3.2 byte-equal-vs-syzkaller and Layer-1 round-trip oracles, which
// only prove byte-level equivalence; this proves semantic equivalence
// of "what the kernel sees per call".

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_trace.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdio>
#include <span>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <variant>
#include <vector>

namespace syz = ::refuzz::program::syz;

namespace {

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> list_dir(const std::string& path) {
    std::vector<std::string> out;
    DIR* d = opendir(path.c_str());
    if (d == nullptr) return out;
    while (auto* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        if (n.size() >= 4 && n.compare(n.size() - 4, 4, ".err") == 0) continue;
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

bool prog_has_kfuzztest(const syz::Prog& p) {
    for (const auto& cup : p.calls()) {
        const auto* m = cup->meta();
        if (m != nullptr && m->attrs().kfuzztest) return true;
    }
    return false;
}

// Emit the JSON-quoted file basename. Only [\x20-\x7e] minus '"' and '\'
// appear in our corpus; for safety still escape '"' and '\'.
void emit_quoted(std::FILE* f, const std::string& s) {
    std::fputc('"', f);
    for (char c : s) {
        if (c == '"' || c == '\\') std::fputc('\\', f);
        std::fputc(c, f);
    }
    std::fputc('"', f);
}

void emit_hex(std::FILE* f, std::span<const uint8_t> bytes) {
    static const char* hex_chars = "0123456789abcdef";
    std::fputc('"', f);
    for (uint8_t b : bytes) {
        std::fputc(hex_chars[b >> 4], f);
        std::fputc(hex_chars[b & 0x0F], f);
    }
    std::fputc('"', f);
}

void emit_const_tag(std::FILE* f, uint64_t sz, uint64_t v, uint64_t bo,
                    uint64_t bl, uint64_t ps, uint64_t fmt) {
    std::fprintf(f,
        R"({"k":"C","sz":%llu,"v":%llu,"f":%llu,"bo":%llu,"bl":%llu,"ps":%llu})",
        static_cast<unsigned long long>(sz),
        static_cast<unsigned long long>(v),
        static_cast<unsigned long long>(fmt),
        static_cast<unsigned long long>(bo),
        static_cast<unsigned long long>(bl),
        static_cast<unsigned long long>(ps));
}

void emit_arg(std::FILE* f, const syz::WireArg& a) {
    if (auto* w = std::get_if<syz::WireConst>(&a)) {
        emit_const_tag(f, w->size, w->val, w->bf_off, w->bf_len, w->pid_stride,
                       static_cast<uint64_t>(w->fmt));
        return;
    }
    if (auto* w = std::get_if<syz::WireResult>(&a)) {
        std::fprintf(f,
            R"({"k":"R","sz":%llu,"f":%llu,"d":%llu,"a":%llu,"def":%llu})",
            static_cast<unsigned long long>(w->size),
            static_cast<unsigned long long>(w->fmt),
            static_cast<unsigned long long>(w->op_div),
            static_cast<unsigned long long>(w->op_add),
            static_cast<unsigned long long>(w->default_val));
        return;
    }
    if (auto* w = std::get_if<syz::WireAddr>(&a)) {
        std::fprintf(f, R"({"k":"P","sz":%u,"o":%llu})",
            static_cast<unsigned>(w->ptr_size),
            static_cast<unsigned long long>(w->addr));
        return;
    }
    if (auto* w = std::get_if<syz::WireData>(&a)) {
        std::fprintf(f, R"({"k":"D","h":)");
        emit_hex(f, w->data);
        std::fprintf(f, R"(,"r":%s})", w->readable ? "true" : "false");
        return;
    }
    // WireCsum doesn't appear as a call arg in upstream — skip silently.
    std::fprintf(f, R"({"k":"?"})");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <indir> [-o <out.jsonl>]\n", argv[0]);
        return 2;
    }
    const std::string indir = argv[1];
    std::string outpath = "-";
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outpath = argv[++i];
        }
    }

    std::FILE* fout = (outpath == "-") ? stdout : std::fopen(outpath.c_str(), "w");
    if (fout == nullptr) {
        std::fprintf(stderr, "cannot open output: %s\n", outpath.c_str());
        return 2;
    }

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);

    auto files = list_dir(indir);
    int considered = 0, skip_decode = 0, skip_kfuzz = 0, fail_encode = 0;
    int fail_decode_wire = 0, emitted = 0;
    for (const auto& name : files) {
        std::string text = read_file(indir + "/" + name);
        auto prog_or = dec.decode(text);
        if (!prog_or) { ++skip_decode; continue; }
        const syz::Prog& prog = **prog_or;
        if (prog_has_kfuzztest(prog)) { ++skip_kfuzz; continue; }
        ++considered;

        auto bytes_or = syz::serialize_for_exec(prog);
        if (!bytes_or) { ++fail_encode; continue; }
        auto wp_or = syz::decode_exec_wire(*bytes_or);
        if (!wp_or) { ++fail_decode_wire; continue; }
        const auto& wp = *wp_or;

        // Emit JSONL line: walk the wire's WireCall instructions in order.
        std::fprintf(fout, R"({"file":)");
        emit_quoted(fout, name);
        std::fprintf(fout, R"(,"calls":[)");
        bool first_call = true;
        for (const auto& instr : wp.instrs) {
            const auto* cl = std::get_if<syz::WireCall>(&instr);
            if (cl == nullptr) continue;
            if (!first_call) std::fputc(',', fout);
            first_call = false;
            // Translate call_id → kernel NR via Target schema.
            uint64_t nr = 0;
            if (cl->call_id < target.syscalls().size()) {
                nr = target.syscalls()[cl->call_id]->nr();
            }
            std::fprintf(fout, R"({"nr":%llu,"args":[)",
                         static_cast<unsigned long long>(nr));
            for (std::size_t i = 0; i < cl->args.size(); ++i) {
                if (i != 0) std::fputc(',', fout);
                emit_arg(fout, cl->args[i]);
            }
            std::fprintf(fout, "]}");
        }
        std::fprintf(fout, "]}\n");
        ++emitted;
    }

    if (fout != stdout) std::fclose(fout);

    std::fprintf(stderr,
        "cpp trace: files=%zu considered=%d emitted=%d skip_decode=%d "
        "skip_kfuzz=%d fail_encode=%d fail_decode_wire=%d\n",
        files.size(), considered, emitted, skip_decode, skip_kfuzz,
        fail_encode, fail_decode_wire);
    return 0;
}
