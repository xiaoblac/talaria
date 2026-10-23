// refuzz-exec-trace-wire-dump
//
// Read production exec-oracle trace files, extract HostMessage.ExecRequest.Data
// with the existing trace_reader, decode the syzkaller exec wire, and emit one
// JSONL record per WireCall. This is intentionally outside refuzz_exec_oracle:
// it is a read-only diagnostic tool for joining per-call mismatches back to the
// original captured syscall arguments.

#include "trace_reader.hpp"

#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <utility>
#include <variant>
#include <span>
#include <vector>

namespace replayer = ::refuzz::oracle::replayer;
namespace syz = ::refuzz::program::syz;

namespace {

struct Options {
    std::filesystem::path trace_dir;
    std::string output = "-";
    std::size_t max_data = 64;
    bool full_data = false;
};

struct CopyinDump {
    std::size_t instr_index = 0;
    uint64_t addr = 0;
    syz::WireArg arg;
};

struct CopyoutDump {
    std::size_t instr_index = 0;
    uint64_t idx = 0;
    uint64_t addr = 0;
    uint64_t size = 0;
};

struct SetPropsDump {
    std::size_t instr_index = 0;
    int64_t fail_nth = 0;
    bool async = false;
    int64_t rerun = 0;
};

struct CallDump {
    std::size_t instr_index = 0;
    std::size_t call_idx = 0;
    syz::WireCall call;
    std::vector<CopyinDump> copyins;
    std::vector<CopyoutDump> copyouts;
    std::vector<SetPropsDump> props;
};

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s -trace-dir <dir> [-o <out.jsonl>] "
        "[-max-data <bytes>|-full-data]\n",
        argv0);
}

bool parse_size(const char* s, std::size_t& out) {
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (end == s || *end != '\0') return false;
    if (v > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    out = static_cast<std::size_t>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-trace-dir") == 0 && i + 1 < argc) {
            opt.trace_dir = argv[++i];
            continue;
        }
        if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            opt.output = argv[++i];
            continue;
        }
        if (std::strcmp(argv[i], "-max-data") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], opt.max_data)) return false;
            continue;
        }
        if (std::strcmp(argv[i], "-full-data") == 0) {
            opt.full_data = true;
            continue;
        }
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        }
        return false;
    }
    return !opt.trace_dir.empty();
}

void json_string(std::FILE* f, const std::string& s) {
    std::fputc('"', f);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  std::fputs("\\\"", f); break;
        case '\\': std::fputs("\\\\", f); break;
        case '\b': std::fputs("\\b", f); break;
        case '\f': std::fputs("\\f", f); break;
        case '\n': std::fputs("\\n", f); break;
        case '\r': std::fputs("\\r", f); break;
        case '\t': std::fputs("\\t", f); break;
        default:
            if (c < 0x20) {
                std::fprintf(f, "\\u%04x", static_cast<unsigned>(c));
            } else {
                std::fputc(static_cast<int>(c), f);
            }
            break;
        }
    }
    std::fputc('"', f);
}

void hex_u64(std::FILE* f, const char* key, uint64_t v) {
    std::fprintf(f, R"(,"%s":"0x%llx")", key,
                 static_cast<unsigned long long>(v));
}

void hex_bytes(std::FILE* f, std::span<const uint8_t> bytes,
               std::size_t max_data, bool full_data) {
    static constexpr char kHex[] = "0123456789abcdef";
    const std::size_t n = full_data ? bytes.size() : std::min(bytes.size(), max_data);
    std::fputc('"', f);
    for (std::size_t i = 0; i < n; ++i) {
        const uint8_t b = bytes[i];
        std::fputc(kHex[b >> 4], f);
        std::fputc(kHex[b & 0x0f], f);
    }
    std::fputc('"', f);
}

void emit_csum_chunks(std::FILE* f, const syz::WireCsum& w) {
    std::fputc('[', f);
    for (std::size_t i = 0; i < w.chunks.size(); ++i) {
        const auto& ch = w.chunks[i];
        if (i != 0) std::fputc(',', f);
        std::fprintf(f,
            R"({"kind":%u,"addr_or_value":%llu)",
            static_cast<unsigned>(ch.kind),
            static_cast<unsigned long long>(ch.addr_or_value));
        hex_u64(f, "addr_or_value_hex", ch.addr_or_value);
        std::fprintf(f, R"(,"size":%llu})",
                     static_cast<unsigned long long>(ch.size));
    }
    std::fputc(']', f);
}

void emit_arg(std::FILE* f, const syz::WireArg& a, const Options& opt) {
    if (const auto* w = std::get_if<syz::WireConst>(&a)) {
        std::fprintf(f,
            R"({"k":"const","size":%llu,"val":%llu)",
            static_cast<unsigned long long>(w->size),
            static_cast<unsigned long long>(w->val));
        hex_u64(f, "val_hex", w->val);
        std::fprintf(f,
            R"(,"fmt":%u,"bf_off":%llu,"bf_len":%llu,"pid_stride":%llu})",
            static_cast<unsigned>(w->fmt),
            static_cast<unsigned long long>(w->bf_off),
            static_cast<unsigned long long>(w->bf_len),
            static_cast<unsigned long long>(w->pid_stride));
        return;
    }
    if (const auto* w = std::get_if<syz::WireAddr>(&a)) {
        std::fprintf(f, R"({"k":"addr","ptr_size":%u,"addr":%llu)",
                     static_cast<unsigned>(w->ptr_size),
                     static_cast<unsigned long long>(w->addr));
        hex_u64(f, "addr_hex", w->addr);
        std::fputc('}', f);
        return;
    }
    if (const auto* w = std::get_if<syz::WireResult>(&a)) {
        std::fprintf(f,
            R"({"k":"result","size":%llu,"fmt":%u,"idx":%llu,"op_div":%llu,"op_add":%llu,"default":%llu)",
            static_cast<unsigned long long>(w->size),
            static_cast<unsigned>(w->fmt),
            static_cast<unsigned long long>(w->idx),
            static_cast<unsigned long long>(w->op_div),
            static_cast<unsigned long long>(w->op_add),
            static_cast<unsigned long long>(w->default_val));
        hex_u64(f, "default_hex", w->default_val);
        std::fputc('}', f);
        return;
    }
    if (const auto* w = std::get_if<syz::WireData>(&a)) {
        const bool truncated = !opt.full_data && w->data.size() > opt.max_data;
        std::fprintf(f, R"({"k":"data","len":%zu,"readable":%s,"truncated":%s,"hex":)",
                     w->data.size(),
                     w->readable ? "true" : "false",
                     truncated ? "true" : "false");
        hex_bytes(f, w->data, opt.max_data, opt.full_data);
        std::fputc('}', f);
        return;
    }
    if (const auto* w = std::get_if<syz::WireCsum>(&a)) {
        std::fprintf(f, R"({"k":"csum","size":%llu,"csum_kind":%llu,"chunks":)",
                     static_cast<unsigned long long>(w->size),
                     static_cast<unsigned long long>(w->csum_kind));
        emit_csum_chunks(f, *w);
        std::fputc('}', f);
        return;
    }
    std::fputs(R"({"k":"unknown"})", f);
}

std::vector<CallDump> collect_calls(const syz::WireProgram& wp) {
    std::vector<CallDump> calls;
    std::vector<CopyinDump> pending_copyins;
    std::vector<SetPropsDump> pending_props;

    for (std::size_t i = 0; i < wp.instrs.size(); ++i) {
        const auto& instr = wp.instrs[i];
        if (const auto* ci = std::get_if<syz::WireCopyin>(&instr)) {
            pending_copyins.push_back(CopyinDump{i, ci->addr, ci->arg});
            continue;
        }
        if (const auto* sp = std::get_if<syz::WireSetProps>(&instr)) {
            pending_props.push_back(SetPropsDump{i, sp->fail_nth, sp->async, sp->rerun});
            continue;
        }
        if (const auto* co = std::get_if<syz::WireCopyout>(&instr)) {
            if (!calls.empty()) {
                calls.back().copyouts.push_back(CopyoutDump{i, co->idx, co->addr, co->size});
            }
            continue;
        }
        if (const auto* cl = std::get_if<syz::WireCall>(&instr)) {
            CallDump out;
            out.instr_index = i;
            out.call_idx = calls.size();
            out.call = *cl;
            out.copyins = std::move(pending_copyins);
            out.props = std::move(pending_props);
            pending_copyins.clear();
            pending_props.clear();
            calls.push_back(std::move(out));
            continue;
        }
    }
    return calls;
}

void emit_copyins(std::FILE* f, const std::vector<CopyinDump>& copyins,
                  const Options& opt) {
    std::fputc('[', f);
    for (std::size_t i = 0; i < copyins.size(); ++i) {
        const auto& ci = copyins[i];
        if (i != 0) std::fputc(',', f);
        std::fprintf(f, R"({"instr_index":%zu,"addr":%llu)",
                     ci.instr_index,
                     static_cast<unsigned long long>(ci.addr));
        hex_u64(f, "addr_hex", ci.addr);
        std::fputs(R"(,"arg":)", f);
        emit_arg(f, ci.arg, opt);
        std::fputc('}', f);
    }
    std::fputc(']', f);
}

void emit_copyouts(std::FILE* f, const std::vector<CopyoutDump>& copyouts) {
    std::fputc('[', f);
    for (std::size_t i = 0; i < copyouts.size(); ++i) {
        const auto& co = copyouts[i];
        if (i != 0) std::fputc(',', f);
        std::fprintf(f,
            R"({"instr_index":%zu,"idx":%llu,"addr":%llu)",
            co.instr_index,
            static_cast<unsigned long long>(co.idx),
            static_cast<unsigned long long>(co.addr));
        hex_u64(f, "addr_hex", co.addr);
        std::fprintf(f, R"(,"size":%llu})",
                     static_cast<unsigned long long>(co.size));
    }
    std::fputc(']', f);
}

void emit_props(std::FILE* f, const std::vector<SetPropsDump>& props) {
    std::fputc('[', f);
    for (std::size_t i = 0; i < props.size(); ++i) {
        const auto& p = props[i];
        if (i != 0) std::fputc(',', f);
        std::fprintf(f,
            R"({"instr_index":%zu,"fail_nth":%lld,"async":%s,"rerun":%lld})",
            p.instr_index,
            static_cast<long long>(p.fail_nth),
            p.async ? "true" : "false",
            static_cast<long long>(p.rerun));
    }
    std::fputc(']', f);
}

void emit_args(std::FILE* f, const std::vector<syz::WireArg>& args,
               const Options& opt) {
    std::fputc('[', f);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i != 0) std::fputc(',', f);
        emit_arg(f, args[i], opt);
    }
    std::fputc(']', f);
}

void emit_call_record(std::FILE* f, const Options& opt,
                      const replayer::SessionInfo& session,
                      const replayer::ExecRequestEvent& ev,
                      const syz::WireProgram& wp,
                      const CallDump& dump) {
    const auto& target = syz::Target::linux_amd64();
    const syz::SyscallMeta* meta = nullptr;
    if (dump.call.call_id < target.syscalls().size()) {
        meta = target.syscalls()[dump.call.call_id].get();
    }

    std::fprintf(f,
        R"({"kind":"call","session_id":%llu,"req_id":%lld,"seq":%llu,"call_idx":%zu)",
        static_cast<unsigned long long>(session.session_id),
        static_cast<long long>(ev.req_id),
        static_cast<unsigned long long>(ev.seq),
        dump.call_idx);
    std::fputs(R"(,"trace_file":)", f);
    json_string(f, session.file_path);
    std::fprintf(f,
        R"(,"request_type":%llu,"request_flags":%llu,"exec_env_flags":%llu,"exec_exec_flags":%llu,"sandbox_arg":%lld)",
        static_cast<unsigned long long>(ev.request_type),
        static_cast<unsigned long long>(ev.request_flags),
        static_cast<unsigned long long>(ev.exec_env_flags),
        static_cast<unsigned long long>(ev.exec_exec_flags),
        static_cast<long long>(ev.sandbox_arg));
    std::fprintf(f,
        R"(,"payload_len":%zu,"wire_num_calls":%llu,"wire_instr_count":%zu,"instr_index":%zu)",
        ev.payload.size(),
        static_cast<unsigned long long>(wp.num_calls),
        wp.instrs.size(),
        dump.instr_index);
    std::fprintf(f,
        R"(,"call_id":%llu,"nr":%llu,"copyout_idx":%llu)",
        static_cast<unsigned long long>(dump.call.call_id),
        static_cast<unsigned long long>(meta ? meta->nr() : 0),
        static_cast<unsigned long long>(dump.call.copyout_idx));
    hex_u64(f, "nr_hex", meta ? meta->nr() : 0);
    hex_u64(f, "copyout_idx_hex", dump.call.copyout_idx);
    std::fputs(R"(,"syscall":)", f);
    json_string(f, meta ? meta->name() : "<bad-call-id>");
    std::fputs(R"(,"call_name":)", f);
    json_string(f, meta ? meta->call_name() : "<bad-call-id>");
    std::fprintf(f,
        R"(,"meta_timeout":%llu,"meta_prog_timeout":%llu)",
        static_cast<unsigned long long>(meta ? meta->attrs().timeout : 0),
        static_cast<unsigned long long>(meta ? meta->attrs().prog_timeout : 0));
    std::fputs(R"(,"props":)", f);
    emit_props(f, dump.props);
    std::fputs(R"(,"args":)", f);
    emit_args(f, dump.call.args, opt);
    std::fputs(R"(,"copyins":)", f);
    emit_copyins(f, dump.copyins, opt);
    std::fputs(R"(,"copyouts":)", f);
    emit_copyouts(f, dump.copyouts);
    std::fputs("}\n", f);
}

void emit_decode_error(std::FILE* f, const replayer::SessionInfo& session,
                       const replayer::ExecRequestEvent& ev,
                       const syz::WireDecodeError& err) {
    std::fprintf(f,
        R"({"kind":"decode_error","session_id":%llu,"req_id":%lld,"seq":%llu)",
        static_cast<unsigned long long>(session.session_id),
        static_cast<long long>(ev.req_id),
        static_cast<unsigned long long>(ev.seq));
    std::fputs(R"(,"trace_file":)", f);
    json_string(f, session.file_path);
    std::fprintf(f, R"(,"payload_len":%zu,"offset":%zu,"message":)",
                 ev.payload.size(), err.offset);
    json_string(f, err.message);
    std::fputs("}\n", f);
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    std::FILE* out = stdout;
    if (opt.output != "-") {
        out = std::fopen(opt.output.c_str(), "w");
        if (out == nullptr) {
            std::perror(opt.output.c_str());
            return 2;
        }
    }

    const auto sessions = replayer::CollectAndSortTraces(opt.trace_dir);
    if (sessions.empty()) {
        std::fprintf(stderr, "wire_dump: no exec_trace_*.bin in %s\n",
                     opt.trace_dir.c_str());
        if (out != stdout) std::fclose(out);
        return 1;
    }

    std::size_t request_count = 0;
    std::size_t call_count = 0;
    std::size_t decode_errors = 0;
    bool ok = true;

    for (const auto& seed : sessions) {
        replayer::SessionInfo current = seed;
        replayer::TraceCallbacks cbs;
        cbs.on_session_open = [&](const replayer::SessionInfo& si) {
            current = si;
        };
        cbs.on_exec_request = [&](const replayer::ExecRequestEvent& ev) {
            ++request_count;
            const auto decoded = syz::decode_exec_wire(ev.payload);
            if (!decoded) {
                ++decode_errors;
                emit_decode_error(out, current, ev, decoded.error());
                return;
            }
            const auto calls = collect_calls(*decoded);
            call_count += calls.size();
            for (const auto& call : calls) {
                emit_call_record(out, opt, current, ev, *decoded, call);
            }
        };
        cbs.on_truncated_tail = [&](const std::string& where) {
            std::fprintf(stderr, "wire_dump: truncated tail in %s at %s\n",
                         seed.file_path.c_str(), where.c_str());
        };
        if (!replayer::ReplayOneFile(seed, cbs)) {
            std::fprintf(stderr, "wire_dump: failed to read %s\n",
                         seed.file_path.c_str());
            ok = false;
        }
    }

    if (out != stdout) std::fclose(out);
    std::fprintf(stderr,
        "wire_dump: sessions=%zu requests=%zu calls=%zu decode_errors=%zu\n",
        sessions.size(), request_count, call_count, decode_errors);
    return ok ? 0 : 1;
}
