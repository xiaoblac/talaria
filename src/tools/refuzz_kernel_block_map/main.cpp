// refuzz-kernel-block-map — function-granularity block map from a filtered
// kernel objdump (headers + j*/call lines, e.g. run/seed_horizon/vmlinux_cf.txt).
//
// The block-residual mask's STATIC input (docs/plans/structural-horizon-seed-value.md:
// the SpecHorizon-RD block-residual term). For each function it emits the trace-pc
// block COUNT and start address. The in-engine SeedHorizon signal maps a covered
// PC (raw KCOV pc - 5 = the trace-pc call-site) to its function by range and
// computes residual = block_count - covered-in-function, so a covered consumer
// node keeps POSITIVE, decaying mass while its handler still has uncovered blocks
// — with NO dispatch recovery / LLVM bitcode needed (the covered PC names its own
// function; the function's uncovered sibling blocks are the foresight).
//
// One trace-pc call site == one basic block == one KCOV coverage unit, so the
// block count is exactly the function's KCOV universe size.
//
// Usage: refuzz-kernel-block-map [-in vmlinux_cf.txt] [-out PATH]
// Output: one line per function with >=1 block:  <hex_start>\t<block_count>\t<name>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

int main(int argc, char** argv)
{
    const char* in_path  = "run/seed_horizon/vmlinux_cf.txt";
    const char* out_path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            in_path = argv[++i];
        } else if (std::strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    std::ifstream in(in_path);
    if (!in) {
        std::fprintf(stderr, "cannot open %s\n", in_path);
        return 1;
    }
    std::FILE* out = out_path ? std::fopen(out_path, "wb") : stdout;
    if (!out) {
        std::fprintf(stderr, "cannot open %s for write\n", out_path);
        return 1;
    }

    std::string line;
    std::string cur_start;   // current function start address (hex, no 0x)
    std::string cur_name;
    long long   cur_blocks = 0;
    long long   n_funcs = 0, n_blocks = 0, n_emitted = 0;

    auto flush = [&]() {
        if (!cur_name.empty() && cur_blocks > 0) {
            std::fprintf(out, "%s\t%lld\t%s\n", cur_start.c_str(), cur_blocks,
                         cur_name.c_str());
            ++n_emitted;
        }
    };

    while (std::getline(in, line)) {
        // Function header: "<hex> <name>:" — no tab, ends with ':', has " <".
        if (!line.empty() && line.back() == ':' &&
            line.find('\t') == std::string::npos) {
            const size_t lt = line.find(" <");
            if (lt != std::string::npos) {
                flush();
                cur_start.assign(line, 0, lt);
                const size_t a = line.find('<');
                const size_t b = line.rfind('>');
                cur_name = (a != std::string::npos && b != std::string::npos && b > a)
                               ? line.substr(a + 1, b - a - 1)
                               : std::string();
                cur_blocks = 0;
                ++n_funcs;
                continue;
            }
        }
        // A trace-pc call site == one instrumented basic block.
        if (line.find("__sanitizer_cov_trace_pc>") != std::string::npos &&
            line.find("call") != std::string::npos) {
            ++cur_blocks;
            ++n_blocks;
        }
    }
    flush();

    if (out != stdout) {
        std::fclose(out);
    }
    std::fprintf(stderr, "functions=%lld blocks=%lld emitted(>=1 block)=%lld\n",
                 n_funcs, n_blocks, n_emitted);
    return 0;
}
