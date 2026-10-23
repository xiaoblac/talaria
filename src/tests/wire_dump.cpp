// One-shot dump tool for diagnosing the worker_dead crash storm.
// Reads a wire-format program file and prints decoded structure.

#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <variant>
#include <vector>

using namespace refuzz::program::syz;

static const char* BinFmtName(BinaryFormat f) {
    switch (f) {
    case BinaryFormat::kNative:    return "native";
    case BinaryFormat::kBigEndian: return "be";
    case BinaryFormat::kStrDec:    return "strdec";
    case BinaryFormat::kStrHex:    return "strhex";
    case BinaryFormat::kStrOct:    return "stroct";
    }
    return "?";
}

static void PrintArg(const WireArg& a) {
    if (auto* x = std::get_if<WireConst>(&a)) {
        std::printf("Const(size=%llu val=0x%llx fmt=%s bf_off=%llu bf_len=%llu pid=%llu)",
            (unsigned long long)x->size, (unsigned long long)x->val,
            BinFmtName(x->fmt),
            (unsigned long long)x->bf_off, (unsigned long long)x->bf_len,
            (unsigned long long)x->pid_stride);
    } else if (auto* x = std::get_if<WireAddr>(&a)) {
        std::printf("Addr(ptr=%u addr=0x%llx)",
            x->ptr_size, (unsigned long long)x->addr);
    } else if (auto* x = std::get_if<WireResult>(&a)) {
        std::printf("Result(size=%llu idx=%llu div=%llu add=%llu default=0x%llx fmt=%s)",
            (unsigned long long)x->size, (unsigned long long)x->idx,
            (unsigned long long)x->op_div, (unsigned long long)x->op_add,
            (unsigned long long)x->default_val, BinFmtName(x->fmt));
    } else if (auto* x = std::get_if<WireData>(&a)) {
        std::printf("Data(size=%zu readable=%d)", x->data.size(), (int)x->readable);
    } else if (auto* x = std::get_if<WireCsum>(&a)) {
        std::printf("Csum(kind=%llu size=%llu chunks=%zu)",
            (unsigned long long)x->csum_kind, (unsigned long long)x->size,
            x->chunks.size());
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <prog.bin>\n", argv[0]);
        return 2;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "open failed: %s\n", argv[1]);
        return 1;
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    std::printf("file_size=%zu\n", bytes.size());
    if (bytes.size() >= 16) {
        std::printf("first16=");
        for (size_t i = 0; i < 16; ++i) std::printf("%02x ", bytes[i]);
        std::printf("\n");
    }

    auto result = decode_exec_wire(bytes);
    if (!result) {
        std::printf("DECODE_ERROR offset=%zu msg=%s\n",
                    result.error().offset, result.error().message.c_str());
        return 1;
    }
    const auto& wp = *result;
    std::printf("decode_OK num_calls=%llu instrs=%zu\n",
                (unsigned long long)wp.num_calls, wp.instrs.size());

    int call_seq = 0;
    size_t copyin_count = 0, copyout_count = 0, setprops_count = 0, call_count = 0;
    uint64_t max_call_id = 0;
    size_t max_args = 0;

    for (size_t i = 0; i < wp.instrs.size(); ++i) {
        const auto& ins = wp.instrs[i];
        if (auto* c = std::get_if<WireCopyin>(&ins)) {
            ++copyin_count;
            std::printf("[%4zu] COPYIN addr=0x%llx arg=", i,
                        (unsigned long long)c->addr);
            PrintArg(c->arg);
            std::printf("\n");
        } else if (auto* c = std::get_if<WireCopyout>(&ins)) {
            ++copyout_count;
            std::printf("[%4zu] COPYOUT idx=%llu addr=0x%llx size=%llu\n", i,
                (unsigned long long)c->idx, (unsigned long long)c->addr,
                (unsigned long long)c->size);
        } else if (auto* c = std::get_if<WireSetProps>(&ins)) {
            ++setprops_count;
            std::printf("[%4zu] SETPROPS fail_nth=%lld async=%d rerun=%lld\n", i,
                (long long)c->fail_nth, (int)c->async, (long long)c->rerun);
        } else if (auto* c = std::get_if<WireCall>(&ins)) {
            ++call_count;
            if (c->call_id > max_call_id) max_call_id = c->call_id;
            if (c->args.size() > max_args) max_args = c->args.size();
            std::printf("[%4zu] CALL #%d call_id=%llu copyout_idx=0x%llx num_args=%zu\n",
                i, call_seq++, (unsigned long long)c->call_id,
                (unsigned long long)c->copyout_idx, c->args.size());
            for (size_t j = 0; j < c->args.size(); ++j) {
                std::printf("           arg[%zu]=", j);
                PrintArg(c->args[j]);
                std::printf("\n");
            }
        }
    }

    std::printf("\nSUMMARY\n");
    std::printf("  num_calls(header)=%llu  CALL_instrs=%zu\n",
                (unsigned long long)wp.num_calls, call_count);
    std::printf("  copyin=%zu copyout=%zu setprops=%zu\n",
                copyin_count, copyout_count, setprops_count);
    std::printf("  max_call_id=%llu  max_args=%zu\n",
                (unsigned long long)max_call_id, max_args);

    // ---- Verify call_id lookup against linux_amd64 schema ----
    std::printf("\nSCHEMA LOOKUP (Target::linux_amd64() syscalls vector)\n");
    const auto& target = Target::linux_amd64();
    const auto& sc = target.syscalls();
    std::printf("  syscalls.size()=%zu\n", sc.size());
    size_t null_count = 0;
    for (size_t i = 0; i < sc.size(); ++i) {
        if (sc[i] == nullptr) ++null_count;
    }
    std::printf("  null_entries_total=%zu\n", null_count);

    std::printf("\nPER-CALL VALIDATION\n");
    bool any_bad = false;
    for (size_t i = 0; i < wp.instrs.size(); ++i) {
        if (auto* c = std::get_if<WireCall>(&wp.instrs[i])) {
            const uint64_t id = c->call_id;
            const char* status;
            const char* nm = "?";
            uint64_t nr = 0;
            if (id >= sc.size()) {
                status = "OUT_OF_RANGE";
                any_bad = true;
            } else if (sc[id] == nullptr) {
                status = "NULL_ENTRY (would SIGSEGV on ->nr())";
                any_bad = true;
            } else {
                status = "ok";
                nm = sc[id]->name().c_str();
                nr = sc[id]->nr();
            }
            std::printf("  call_id=%llu  size=%zu  status=%s  nr=%llu  name=%s\n",
                        (unsigned long long)id, sc.size(), status,
                        (unsigned long long)nr, nm);
        }
    }
    std::printf("any_bad=%d\n", (int)any_bad);
    return 0;
}
