// refuzz_xiuos_triage — Phase 2 §C #22 follow-up.
//
// CLI utility that reads an on-disk XiuosCrashBucket directory (the layout
// XiuosCrashBucket::WriteRecord persists: <dir>/<bucket_key>/<hash16>.bin
// plus <hash16>.json sidecar) and prints a human-readable summary per
// bucket:
//
//   - trap_pc + mcause parsed from the bucket key
//   - mcause decoded against the RISC-V mcause name table (M-mode)
//   - trap_pc resolved to function + file:line via addr2line on the ELF
//     (if --elf is provided)
//   - each repro payload decoded via XiuosDecodeProgram, summarized
//     (call_count + first few API ids; with --verbose: full call dump)
//
// Usage:
//   refuzz_xiuos_triage --bucket-dir <path> [--elf <path>] [--verbose]
//                       [--no-symbols] [--addr2line <bin>]
//
// Symbol resolution is opt-in: the tool works without --elf (just prints
// the raw trap_pc hex). When --elf is given, the tool shells out to
// addr2line; failing that, it falls back to "?". The current XiUOS worker
// (kernel/refuzz/refuzz_worker.c) never produces XIUOS_STATUS_TRAP today
// — this tool is the consumer-side glue for when the worker's trap path
// or a deeper mutator gets there.

#include "refuzz/program/xiuos/xiuos_program.hpp"

#include <unistd.h>  // popen / pclose

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace progx = refuzz::program::xiuos;

namespace {

struct Args {
    std::filesystem::path bucket_dir;
    std::filesystem::path elf_path;     // empty = no symbol resolution
    std::string           addr2line_bin = "addr2line";
    bool                  no_symbols = false;
    bool                  verbose = false;
};

void PrintUsage(const char* prog) {
    std::fprintf(stderr,
        "usage: %s --bucket-dir <path> [--elf <path>] [--verbose]\n"
        "       [--no-symbols] [--addr2line <bin>]\n"
        "\n"
        "Reads on-disk XiuosCrashBucket layout and prints a per-bucket\n"
        "summary. Use --elf to resolve trap_pc to function + file:line\n"
        "via addr2line; omit it to print raw addresses only.\n",
        prog);
}

bool ParseArgs(int argc, char** argv, Args& out) {
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", argv[i]);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--bucket-dir") {
            const char* v = next(); if (!v) return false;
            out.bucket_dir = v;
        } else if (a == "--elf") {
            const char* v = next(); if (!v) return false;
            out.elf_path = v;
        } else if (a == "--addr2line") {
            const char* v = next(); if (!v) return false;
            out.addr2line_bin = v;
        } else if (a == "--no-symbols") {
            out.no_symbols = true;
        } else if (a == "--verbose" || a == "-v") {
            out.verbose = true;
        } else if (a == "--help" || a == "-h") {
            PrintUsage(argv[0]);
            std::exit(0);
        } else {
            std::fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return false;
        }
    }
    if (out.bucket_dir.empty()) {
        std::fprintf(stderr, "--bucket-dir is required\n");
        return false;
    }
    return true;
}

// Parse "xiuos-trap-pc_0xPPPP-mcause_0xMMMM" → (trap_pc, mcause).
bool ParseBucketKey(const std::string& key,
                    std::uint32_t& trap_pc, std::uint32_t& mcause) {
    unsigned long long pc = 0, mc = 0;
    int n = std::sscanf(key.c_str(),
                        "xiuos-trap-pc_0x%llx-mcause_0x%llx", &pc, &mc);
    if (n != 2) return false;
    trap_pc = static_cast<std::uint32_t>(pc);
    mcause  = static_cast<std::uint32_t>(mc);
    return true;
}

// RISC-V M-mode mcause decode. Returns nullptr for codes we don't know.
const char* RiscvMcauseName(std::uint32_t mcause) {
    const bool is_interrupt = (mcause & 0x80000000u) != 0u;
    const std::uint32_t code = mcause & 0x7fffffffu;
    if (is_interrupt) {
        switch (code) {
        case 1:  return "supervisor software interrupt";
        case 3:  return "machine software interrupt";
        case 5:  return "supervisor timer interrupt";
        case 7:  return "machine timer interrupt";
        case 9:  return "supervisor external interrupt";
        case 11: return "machine external interrupt";
        default: return nullptr;
        }
    }
    switch (code) {
    case 0:  return "instruction address misaligned";
    case 1:  return "instruction access fault";
    case 2:  return "illegal instruction";
    case 3:  return "breakpoint";
    case 4:  return "load address misaligned";
    case 5:  return "load access fault";
    case 6:  return "store/amo address misaligned";
    case 7:  return "store/amo access fault";
    case 8:  return "environment call from U-mode";
    case 9:  return "environment call from S-mode";
    case 11: return "environment call from M-mode";
    case 12: return "instruction page fault";
    case 13: return "load page fault";
    case 15: return "store/amo page fault";
    default: return nullptr;
    }
}

const char* XiuosApiName(progx::XiuosApiId id) {
    switch (id) {
    case progx::XiuosApiId::SemCreate:      return "SEM_CREATE";
    case progx::XiuosApiId::SemDelete:      return "SEM_DELETE";
    case progx::XiuosApiId::SemObtain:      return "SEM_OBTAIN";
    case progx::XiuosApiId::SemAbandon:     return "SEM_ABANDON";
    case progx::XiuosApiId::SemSetValue:    return "SEM_SET_VALUE";
    case progx::XiuosApiId::MutexCreate:    return "MUTEX_CREATE";
    case progx::XiuosApiId::MutexDelete:    return "MUTEX_DELETE";
    case progx::XiuosApiId::MutexObtain:    return "MUTEX_OBTAIN";
    case progx::XiuosApiId::MutexAbandon:   return "MUTEX_ABANDON";
    case progx::XiuosApiId::MsgqCreate:     return "MSGQ_CREATE";
    case progx::XiuosApiId::MsgqDelete:     return "MSGQ_DELETE";
    case progx::XiuosApiId::MsgqSend:       return "MSGQ_SEND";
    case progx::XiuosApiId::MsgqRecv:       return "MSGQ_RECV";
    case progx::XiuosApiId::MsgqUrgentSend: return "MSGQ_URGENT_SEND";
    case progx::XiuosApiId::MsgqReinit:     return "MSGQ_REINIT";
    case progx::XiuosApiId::EventCreate:    return "EVENT_CREATE";
    case progx::XiuosApiId::EventDelete:    return "EVENT_DELETE";
    case progx::XiuosApiId::EventTrigger:   return "EVENT_TRIGGER";
    case progx::XiuosApiId::EventProcess:   return "EVENT_PROCESS";
    case progx::XiuosApiId::TimerCreate:    return "TIMER_CREATE";
    case progx::XiuosApiId::TimerDelete:    return "TIMER_DELETE";
    case progx::XiuosApiId::TimerStartRun:  return "TIMER_START_RUN";
    case progx::XiuosApiId::TimerQuitRun:   return "TIMER_QUIT_RUN";
    case progx::XiuosApiId::TimerModify:    return "TIMER_MODIFY";
    case progx::XiuosApiId::TaskSpawnBlockSem:      return "TASK_SPAWN_BLOCK_SEM";
    case progx::XiuosApiId::TaskSpawnBlockEvent:    return "TASK_SPAWN_BLOCK_EVENT";
    case progx::XiuosApiId::TaskSpawnBlockMsgqRecv: return "TASK_SPAWN_BLOCK_MSGQ_RECV";
    case progx::XiuosApiId::TaskTerminate:          return "TASK_TERMINATE";
    case progx::XiuosApiId::TaskPrioSet:            return "TASK_PRIO_SET";
    case progx::XiuosApiId::WqCreate:        return "WQ_CREATE";
    case progx::XiuosApiId::WqDeinit:        return "WQ_DEINIT";
    case progx::XiuosApiId::WqSubmit:        return "WQ_SUBMIT";
    case progx::XiuosApiId::WqSubmitDelayed: return "WQ_SUBMIT_DELAYED";
    case progx::XiuosApiId::ResourceSnapshot:return "RESOURCE_SNAPSHOT";
    }
    return "?";
}

bool ReadWholeFile(const std::filesystem::path& path,
                   std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.seekg(0, std::ios::end);
    const auto sz = in.tellg();
    if (sz < 0) return false;
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(sz), 0);
    if (!out.empty()) {
        in.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(out.size()));
    }
    return in.good() || in.eof();
}

std::string ShellQuote(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (const char c : s) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

// Run `<addr2line> -e <elf> -f -C -p <addr>`. Returns the first line of
// output, or empty on failure. Uses popen — single-shot, fine for a CLI.
std::string AddrToLine(const std::string& addr2line_bin,
                       const std::filesystem::path& elf,
                       std::uint32_t addr) {
    const auto quoted_addr2line = ShellQuote(addr2line_bin);
    const auto quoted_elf = ShellQuote(elf.string());
    char addr_buf[16];
    std::snprintf(addr_buf, sizeof(addr_buf), "0x%08x", addr);
    const std::string cmd = quoted_addr2line + " -e " + quoted_elf +
                            " -f -C -p " + addr_buf + " 2>/dev/null";
    FILE* fp = ::popen(cmd.c_str(), "r");
    if (!fp) return {};
    char buf[1024];
    std::string line;
    if (std::fgets(buf, sizeof(buf), fp) != nullptr) {
        line = buf;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
    }
    ::pclose(fp);
    return line;
}

// One-line summary of a decoded program: "5 calls: SEM_CREATE SEM_OBTAIN ..."
// Truncates the call list at 6 entries.
std::string SummarizeProgram(const progx::XiuosDecodedProgram& p) {
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%zu calls", p.calls.size());
    std::string s = buf;
    if (p.calls.empty()) return s;
    s += ": ";
    const std::size_t take = std::min<std::size_t>(p.calls.size(), 6);
    for (std::size_t i = 0; i < take; ++i) {
        if (i > 0) s += ' ';
        s += XiuosApiName(p.calls[i].api_id);
    }
    if (p.calls.size() > take) s += " …";
    return s;
}

void PrintVerboseCalls(const progx::XiuosDecodedProgram& p) {
    for (std::size_t i = 0; i < p.calls.size(); ++i) {
        const auto& c = p.calls[i];
        std::printf("        [%2zu] %s argc=%u",
                    i, XiuosApiName(c.api_id), c.argc);
        if (c.argc > 0) {
            std::printf(" args=(");
            for (std::size_t k = 0; k < c.argc; ++k) {
                if (k > 0) std::printf(", ");
                std::printf("0x%08x", c.args[k]);
            }
            std::printf(")");
        }
        if (c.flags != 0) std::printf(" flags=0x%04x", c.flags);
        std::printf("\n");
    }
}

struct PayloadEntry {
    std::filesystem::path bin;
    std::filesystem::path json;        // may not exist
    std::uintmax_t        bin_size = 0;
};

struct BucketSummary {
    std::string                   bucket_key;
    std::filesystem::path         dir;
    std::uint32_t                 trap_pc = 0;
    std::uint32_t                 mcause = 0;
    std::vector<PayloadEntry>     payloads;
};

bool LoadBucket(const std::filesystem::path& dir, BucketSummary& out) {
    out.bucket_key = dir.filename().string();
    out.dir = dir;
    if (!ParseBucketKey(out.bucket_key, out.trap_pc, out.mcause)) {
        return false;
    }
    std::error_code ec;
    for (const auto& f : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!f.is_regular_file(ec) || ec) continue;
        if (f.path().extension() != ".bin") continue;
        PayloadEntry e;
        e.bin = f.path();
        const auto sib = f.path();
        auto json = sib;
        json.replace_extension(".json");
        std::error_code ec2;
        if (std::filesystem::exists(json, ec2) && !ec2) {
            e.json = std::move(json);
        }
        e.bin_size = f.file_size(ec);
        if (ec) e.bin_size = 0;
        out.payloads.push_back(std::move(e));
    }
    std::sort(out.payloads.begin(), out.payloads.end(),
              [](const PayloadEntry& a, const PayloadEntry& b) {
                  return a.bin.filename().string() < b.bin.filename().string();
              });
    return true;
}

void PrintBucket(const BucketSummary& b,
                 const Args& args) {
    std::printf("BUCKET %s\n", b.bucket_key.c_str());
    std::printf("  trap_pc=0x%08" PRIx32 "  mcause=0x%08" PRIx32,
                b.trap_pc, b.mcause);
    if (const char* name = RiscvMcauseName(b.mcause)) {
        std::printf(" (%s)", name);
    }
    std::printf("\n");

    if (!args.elf_path.empty() && !args.no_symbols && b.trap_pc != 0) {
        const auto sym = AddrToLine(args.addr2line_bin, args.elf_path,
                                    b.trap_pc);
        if (!sym.empty()) {
            std::printf("  symbol: %s\n", sym.c_str());
        }
    }

    std::printf("  payloads: %zu\n", b.payloads.size());
    for (const auto& p : b.payloads) {
        std::printf("    - %s (%llu bytes)",
                    p.bin.filename().string().c_str(),
                    static_cast<unsigned long long>(p.bin_size));

        std::vector<std::uint8_t> bytes;
        if (ReadWholeFile(p.bin, bytes)) {
            try {
                const auto decoded = progx::XiuosDecodeProgram(
                    std::span<const std::uint8_t>(bytes.data(), bytes.size()));
                std::printf(" — %s\n", SummarizeProgram(decoded).c_str());
                if (args.verbose) {
                    PrintVerboseCalls(decoded);
                }
            } catch (const std::exception& exc) {
                std::printf(" — DECODE_FAILED: %s\n", exc.what());
            }
        } else {
            std::printf(" — READ_FAILED\n");
        }
    }
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    Args args;
    if (!ParseArgs(argc, argv, args)) {
        PrintUsage(argv[0]);
        return 1;
    }
    if (!std::filesystem::is_directory(args.bucket_dir)) {
        std::fprintf(stderr, "bucket dir does not exist: %s\n",
                     args.bucket_dir.string().c_str());
        return 1;
    }
    if (!args.elf_path.empty() && !std::filesystem::exists(args.elf_path)) {
        std::fprintf(stderr, "WARN: --elf %s does not exist; running without symbols\n",
                     args.elf_path.string().c_str());
        args.elf_path.clear();
    }

    std::vector<BucketSummary> buckets;
    std::error_code ec;
    for (const auto& e :
            std::filesystem::directory_iterator(args.bucket_dir, ec)) {
        if (ec) break;
        if (!e.is_directory(ec) || ec) continue;
        BucketSummary b;
        if (LoadBucket(e.path(), b)) {
            buckets.push_back(std::move(b));
        }
    }

    std::sort(buckets.begin(), buckets.end(),
              [](const BucketSummary& a, const BucketSummary& b) {
                  if (a.trap_pc != b.trap_pc) return a.trap_pc < b.trap_pc;
                  return a.mcause < b.mcause;
              });

    std::size_t total_payloads = 0;
    for (const auto& b : buckets) total_payloads += b.payloads.size();

    std::printf("# refuzz_xiuos_triage — bucket_dir=%s%s%s\n",
                args.bucket_dir.string().c_str(),
                args.elf_path.empty() ? "" : " elf=",
                args.elf_path.empty() ? "" : args.elf_path.string().c_str());
    std::printf("# buckets=%zu total_payloads=%zu\n\n",
                buckets.size(), total_payloads);

    if (buckets.empty()) {
        std::printf("(no buckets found — XIUOS_STATUS_TRAP has not been "
                    "observed in this run)\n");
        return 0;
    }

    for (const auto& b : buckets) {
        PrintBucket(b, args);
    }
    return 0;
}
