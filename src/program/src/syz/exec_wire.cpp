// Implementation of refuzz/program/syz/exec_wire.hpp.
//
// Port of prog/encodingexec.go. Produces a binary-varint stream that is
// byte-equal to syzkaller's prog.Prog.SerializeForExec for any input the
// C++ TextDecoder accepts.

#include "refuzz/program/syz/exec_wire.hpp"

#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/csum.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::program::syz {

namespace {

// Special instruction codes (mirror of prog/encodingexec.go iota chain).
constexpr uint64_t kExecInstrEOF      = ~uint64_t{0};        // ^uint64(0)
constexpr uint64_t kExecInstrCopyin   = ~uint64_t{1};        // ^uint64(1)
constexpr uint64_t kExecInstrCopyout  = ~uint64_t{2};        // ^uint64(2)
constexpr uint64_t kExecInstrSetProps = ~uint64_t{3};        // ^uint64(3)

// Arg type codes.
constexpr uint64_t kExecArgConst   = 0;
constexpr uint64_t kExecArgAddr32  = 1;
constexpr uint64_t kExecArgAddr64  = 2;
constexpr uint64_t kExecArgResult  = 3;
constexpr uint64_t kExecArgData    = 4;
constexpr uint64_t kExecArgCsum    = 5;
constexpr uint64_t kExecArgDataReadable = uint64_t{1} << 63;

constexpr uint64_t kExecArgCsumInet      = 0;
constexpr uint64_t kExecArgCsumChunkData  = 0;
constexpr uint64_t kExecArgCsumChunkConst = 1;

// Per-prog state for one SerializeForExec call.
struct ArgInfo {
    uint64_t addr = 0;       // physical addr, used for copyin
    uint64_t idx  = 0;       // copyout index
    bool     ret  = false;   // populated for the syscall return value
    bool     has_addr = false;
};

struct ExecCtx {
    const Target*                            target = nullptr;
    std::vector<uint8_t>                     buf;
    std::unordered_map<const Arg*, ArgInfo>  args;
    uint64_t                                 copyout_seq = 0;
    // Per-call csum state, refreshed each call.
    std::unordered_map<Arg*, CsumInfo>       csum_map;
    std::unordered_set<Arg*>                 csum_uses;
    // [v2 Epic 7 PR-12 B2] Per-path classification:write_arg 5 个 silent-no-op
    // 路径 fail 时填这里;serialize_for_exec 把它拼到 ExecError。host_events.txt
    // grep `[kCategory]` 即可分类 broken-IR distribution(B2 audit 输入)。
    // 不在 ExecError 里做 enum/code —— 只跟 host log scrape 协作,降耦合。
    std::string                              err_msg;
    // [v2 Epic 7 PR-12 B2 — Step 2.5 evidence] 为了把 [kResult] 失败钉死成
    // "topo reversed (mutator GenState 缺 prefix 语义)" 还是 "dangling pointer
    // (ResultArg dtor 漏 null consumer)" 还是 "OK 顺序但未注册 (encoder bug)",
    // write_arg [kResult] fail 时搜 producer 在 prog 的 call idx,与
    // current_call_idx 对比生成结构化诊断。一次性 evidence-gathering,Step 3
    // root-cause fix 后这段诊断可保留 (cheap on cold path) 也可以删。
    const Prog*                              prog_ref = nullptr;
    std::size_t                              current_call_idx = 0;
};

// Mirror of binary.AppendVarint (zig-zag uint64 → little-endian 7-bit groups).
void write_varint(std::vector<uint8_t>& buf, uint64_t v) {
    uint64_t ux = v << 1;
    if ((v >> 63) != 0) ux = ~ux;
    while (ux >= 0x80) {
        buf.push_back(static_cast<uint8_t>(ux) | uint8_t{0x80});
        ux >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(ux));
}

inline void write(ExecCtx& w, uint64_t v) { write_varint(w.buf, v); }

// True iff this arg's address must be remembered for later instructions.
// Matches upstream: an arg is "used" if it's a ResultArg referenced
// elsewhere (we precompute that set in serialize_for_exec and stuff it
// into csum_uses), or it participates in a checksum.
bool will_be_used(const ExecCtx& w, Arg* a) {
    if (w.csum_map.find(a) != w.csum_map.end()) return true;
    if (w.csum_uses.find(a) != w.csum_uses.end()) return true;
    return false;
}

// Forward declarations.
// [v1 write_arg → void — ROLLBACK: 还原 void; 注意 5 处 silent return 路径
//  会让 caller (write_copyin/serialize_call) 产生 partial wire,decoder 端
//  把后续 opcode 当 arg kind 读出 "unknown arg kind 0xfffffffffffffffe"
//  (= kExecInstrCopyin)。详 Epic 7 PR-10 修复记录。]
// [v2 Epic 7 PR-10 — 当前版本: write_arg → bool,silent no-op 改成 explicit
//  failure,caller 必须 propagate。serialize_for_exec 整体 fail-closed:任一
//  arg encode 失败 → 返 ExecError,绝不输出 partial wire。]
[[nodiscard]] bool write_arg(ExecCtx& w, Arg* a);
void write_const_arg(ExecCtx& w, uint64_t size, uint64_t val,
                     uint64_t bf_off, uint64_t bf_len, uint64_t pid_stride,
                     BinaryFormat bf);

void write_const_arg(ExecCtx& w, uint64_t size, uint64_t val,
                     uint64_t bf_off, uint64_t bf_len, uint64_t pid_stride,
                     BinaryFormat bf) {
    write(w, kExecArgConst);
    const uint64_t meta = size
                        | (static_cast<uint64_t>(bf) << 8)
                        | (bf_off << 16)
                        | (bf_len << 24)
                        | (pid_stride << 32);
    write(w, meta);
    write(w, val);
}

// [v2 Epic 7 PR-10 — write_arg 改 bool;每条 silent return 都改 explicit
//  return false (caller fail-closed)]
//
// 历史(v1): 5 处分支 `return;` 沉默地不产出 arg 字节;调用方 (write_copyin /
// serialize_call 的 args 循环) 已经写了 COPYIN+addr / args_count 等前缀字节,
// 后续没 arg 字节让 decoder 读 → decoder 把下一个 instr opcode (eg.
// kExecInstrCopyin = ~uint64{1} = 0xFFFFFFFFFFFFFFFE) 当 arg kind 读 →
// "unknown arg kind 0xfffffffffffffffe" — 这是 Step 8 corpus 1.5% exec_error
// 的实际根因 (非 signal、非 threaded 问题)。
//
// 修复策略:write_arg 改成 [[nodiscard]] bool;5 处 silent return → return
// false。caller 收到 false → 立即 set w.err 并 bail;serialize_for_exec
// 顶层 fail-closed 返 ExecError,绝不返回 partial wire bytes。
bool write_arg(ExecCtx& w, Arg* a) {
    switch (a->arg_kind()) {
        case ArgKind::kConst: {
            auto* ca = static_cast<ConstArg*>(a);
            const auto* t = a->type();
            const auto [val, stride] = ca->value_with_pid_stride();
            BinaryFormat fmt = BinaryFormat::kNative;
            uint64_t unit_size = 0;
            uint64_t bf_off    = 0;
            uint64_t bf_len    = 0;
            if (t != nullptr) {
                unit_size = t->unit_size();
                bf_off    = t->bitfield_offset();
                bf_len    = t->bitfield_length();
                switch (t->kind()) {
                    case TypeKind::kInt:
                    case TypeKind::kConst:
                    case TypeKind::kFlags:
                    case TypeKind::kLen:
                    case TypeKind::kProc:
                    case TypeKind::kCsum:
                        fmt = static_cast<const IntTypeCommon*>(t)->format();
                        break;
                    case TypeKind::kResource:
                        fmt = static_cast<const ResourceType*>(t)->format();
                        break;
                    default:
                        break;
                }
            }
            write_const_arg(w, unit_size, val, bf_off, bf_len, stride, fmt);
            return true;
        }
        case ArgKind::kResult: {
            auto* ra = static_cast<ResultArg*>(a);
            const auto* t = a->type();
            BinaryFormat fmt = BinaryFormat::kNative;
            if (auto* rt = as_resource(t)) fmt = rt->format();
            if (ra->res() == nullptr) {
                write_const_arg(w, ra->size(), ra->val(), 0, 0, 0, fmt);
                return true;
            }
            auto it = w.args.find(ra->res());
            if (it == w.args.end()) {
                // [v1 silent return — ROLLBACK: 还原 `return;`,允许 partial wire]
                // [v2 PR-10] first-pass discovery 漏 → 显式失败,caller 提交 ExecError。
                // 旧 comment 说"emit zero index let oracle catch" 其实只是 return,
                // wire 已错位。
                // [v2 PR-12 B2 — Step 2.5 evidence inline] 搜 ra->res() 在 prog
                // 的 call idx,与 current_call_idx 对比,分类:
                //   * TOPO_REVERSED (producer_idx > consumer_idx) — 用户假设:
                //     mutator GenState 把整个 prog 灌进 resources_,insert_call
                //     在 mid 插新 call 时新 consumer 选到后面 call 的 producer
                //   * DANGLING (producer 不在任何 call) — 理论上 ResultArg dtor
                //     会 null surviving consumer.res_,不该发生;若出现说明
                //     ownership 假设也错
                //   * BEFORE_BUT_UNREGISTERED (producer_idx < consumer_idx 但
                //     args 找不到) — 极少见,encoder 注册逻辑 bug 或 inner-arg
                //     ResultArg 没走 will_be_used 注册路径
                if (w.err_msg.empty()) {
                    std::size_t producer_idx = static_cast<std::size_t>(-1);
                    const char* classification = "DANGLING";
                    if (w.prog_ref != nullptr) {
                        const auto& calls_ref = w.prog_ref->calls();
                        const Arg* target_producer = static_cast<const Arg*>(ra->res());
                        for (std::size_t j = 0; j < calls_ref.size(); ++j) {
                            const Call* cc = calls_ref[j].get();
                            if (cc == nullptr) continue;
                            if (cc->ret() != nullptr &&
                                static_cast<const Arg*>(cc->ret()) == target_producer) {
                                producer_idx = j;
                                break;
                            }
                            bool inner_hit = false;
                            foreach_arg(const_cast<Call*>(cc), [&](Arg* inner_a, ArgCtx*) {
                                if (inner_hit) return;
                                if (static_cast<const Arg*>(inner_a) == target_producer) {
                                    inner_hit = true;
                                }
                            });
                            if (inner_hit) { producer_idx = j; break; }
                        }
                        if (producer_idx == static_cast<std::size_t>(-1)) {
                            classification = "DANGLING";
                        } else if (producer_idx > w.current_call_idx) {
                            classification = "TOPO_REVERSED";
                        } else {
                            classification = "BEFORE_BUT_UNREGISTERED";
                        }
                    }
                    char buf[320];
                    if (producer_idx == static_cast<std::size_t>(-1)) {
                        std::snprintf(buf, sizeof(buf),
                            "non-encodable arg [kResult]: unknown res reference "
                            "diag={consumer_call_idx=%zu producer_call_idx=N/A class=%s} "
                            "(prog has %zu calls)",
                            w.current_call_idx, classification,
                            w.prog_ref ? w.prog_ref->calls().size() : 0);
                    } else {
                        std::snprintf(buf, sizeof(buf),
                            "non-encodable arg [kResult]: unknown res reference "
                            "diag={consumer_call_idx=%zu producer_call_idx=%zu class=%s} "
                            "(prog has %zu calls)",
                            w.current_call_idx, producer_idx, classification,
                            w.prog_ref ? w.prog_ref->calls().size() : 0);
                    }
                    w.err_msg = buf;
                }
                return false;
            }
            write(w, kExecArgResult);
            const uint64_t meta = ra->size() | (static_cast<uint64_t>(fmt) << 8);
            write(w, meta);
            write(w, it->second.idx);
            write(w, ra->op_div());
            write(w, ra->op_add());
            uint64_t default_val = 0;
            if (auto* rt = as_resource(t)) default_val = rt->default_value();
            write(w, default_val);
            return true;
        }
        case ArgKind::kPointer: {
            auto* pa = static_cast<PointerArg*>(a);
            switch (pa->size()) {
                case 4: write(w, kExecArgAddr32); break;
                case 8: write(w, kExecArgAddr64); break;
                // [v1 silent return — ROLLBACK: 还原 `return;`]
                // [v2 PR-10] non-standard ptr size → 显式失败,IR invariant 违反
                // [v2 PR-12 B2] per-path err msg classification
                default:
                    if (w.err_msg.empty()) {
                        char buf[128];
                        std::snprintf(buf, sizeof(buf),
                            "non-encodable arg [kPointer]: invalid ptr size=%llu "
                            "(expected 4 or 8; type->size() out of sync)",
                            static_cast<unsigned long long>(pa->size()));
                        w.err_msg = buf;
                    }
                    return false;
            }
            const uint64_t off = w.target->physical_addr(pa) - w.target->data_offset();
            write(w, off);
            return true;
        }
        case ArgKind::kData: {
            auto* da = static_cast<DataArg*>(a);
            const auto& data = da->data();
            // [v1 silent return on empty — ROLLBACK: 还原 `if (empty) return;`]
            // [v2 PR-10] 0-size data 上游会 panic;reFuzz 显式失败让 mutator IR
            // invariant 在 serialize 前被发现,而非 wire 错位后 decoder 端报错。
            // [v2 PR-12 B2] per-path err msg classification
            if (data.empty()) {
                if (w.err_msg.empty()) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                        "non-encodable arg [kData]: data.empty() but size()=%llu "
                        "(out_size set without data — likely mutator set_out_size "
                        "on IN/INOUT dir or hints replacer cleared data without "
                        "restoring out path)",
                        static_cast<unsigned long long>(da->size()));
                    w.err_msg = buf;
                }
                return false;
            }
            write(w, kExecArgData);
            uint64_t flags = static_cast<uint64_t>(data.size());
            if (auto* bt = as_buffer(a->type()); bt && bt->is_readable_data_type()) {
                flags |= kExecArgDataReadable;
            }
            write(w, flags);
            w.buf.insert(w.buf.end(), data.begin(), data.end());
            return true;
        }
        case ArgKind::kUnion: {
            auto* ua = static_cast<UnionArg*>(a);
            // [v1 silent return on null option — ROLLBACK: 还原 `if (option != null)`
            //  分支,null 时空 break,wire 错位]
            // [v2 PR-10] 显式失败 + propagate option 的 write_arg 结果
            // [v2 PR-12 B2] per-path err msg classification
            if (ua->option() == nullptr) {
                if (w.err_msg.empty()) {
                    w.err_msg = "non-encodable arg [kUnion]: option() == nullptr "
                                "(mutator dropped variant without re-selecting; "
                                "all UnionArg must have a non-null option after "
                                "default_arg or mutation)";
                }
                return false;
            }
            return write_arg(w, ua->option());
        }
        case ArgKind::kGroup:
            // [v1 silent return — ROLLBACK: 还原空 break]
            // [v2 PR-10] Groups never appear at the leaf of writeArg in upstream — the
            // copyin loop stops at struct/union boundaries and recurses into children
            // separately. Reaching here indicates bad IR;显式失败让 caller fail-closed。
            // [v2 PR-12 B2] per-path err msg classification
            if (w.err_msg.empty()) {
                w.err_msg = "non-encodable arg [kGroup]: appeared at write_arg leaf "
                            "(foreach_arg should have recursed into struct/array "
                            "children — IR shape bug or stale walker)";
            }
            return false;
    }
    return false;  // unreachable;defensive — switch should cover all ArgKind
}

// [v1 write_copyin → void — ROLLBACK: 还原 void,失败时 partial wire 流到
//  decoder 端报 unknown arg kind]
// [v2 PR-10 — bool + fail-closed: 任一 write_arg false → 整条 program 编码失败,
//  caller serialize_for_exec 返 ExecError]
[[nodiscard]] bool write_copyin(ExecCtx& w, Call* c) {
    bool ok = true;
    foreach_arg(c, [&](Arg* a, ArgCtx* ctx) {
        if (!ok) return;  // 已失败,后续 arg 不再写
        if (ctx->base == nullptr) return;
        uint64_t addr = w.target->physical_addr(ctx->base) - w.target->data_offset()
                      + ctx->offset;
        if (a->type() != nullptr) addr -= a->type()->unit_offset();
        if (will_be_used(w, a)) {
            ArgInfo info;
            info.addr     = addr;
            info.has_addr = true;
            w.args[a] = info;
        }
        if (a->arg_kind() == ArgKind::kGroup || a->arg_kind() == ArgKind::kUnion) return;
        const Type* t = a->type();
        if (a->dir() == Dir::kOut || is_pad(t)
                || (a->size() == 0 && (t == nullptr || !t->is_bitfield()))) {
            return;
        }
        write(w, kExecInstrCopyin);
        write(w, addr);
        if (!write_arg(w, a)) {
            ok = false;
            // 注意:COPYIN+addr 已经写进 w.buf,但 serialize_for_exec 顶层会
            // 丢弃整个 buf (返 ExecError 不返 bytes),所以 partial wire 不会
            // 流到 worker。
        }
    });
    return ok;
}

void write_checksums(ExecCtx& w) {
    if (w.csum_map.empty()) return;
    std::vector<Arg*> csum_args;
    csum_args.reserve(w.csum_map.size());
    for (const auto& kv : w.csum_map) csum_args.push_back(kv.first);

    // Upstream sorts ascending by addr then iterates backwards (descending).
    // We do the same so output ordering matches.
    std::sort(csum_args.begin(), csum_args.end(), [&](Arg* x, Arg* y) {
        const auto ix = w.args.find(x);
        const auto iy = w.args.find(y);
        const uint64_t ax = (ix != w.args.end()) ? ix->second.addr : 0;
        const uint64_t ay = (iy != w.args.end()) ? iy->second.addr : 0;
        return ax < ay;
    });

    for (auto it = csum_args.rbegin(); it != csum_args.rend(); ++it) {
        Arg* arg = *it;
        const auto& info = w.csum_map[arg];
        write(w, kExecInstrCopyin);
        write(w, w.args[arg].addr);
        write(w, kExecArgCsum);
        write(w, arg->size());
        if (info.kind == CsumKind::kInet) {
            write(w, kExecArgCsumInet);
            write(w, info.chunks.size());
            for (const auto& ch : info.chunks) {
                if (ch.kind == CsumChunkKind::kArg) {
                    write(w, kExecArgCsumChunkData);
                    write(w, w.args[ch.arg].addr);
                    write(w, ch.arg->size());
                } else {
                    write(w, kExecArgCsumChunkConst);
                    write(w, ch.value);
                    write(w, ch.size);
                }
            }
        }
    }
}

void write_call_props(ExecCtx& w, const CallProps& p) {
    write(w, kExecInstrSetProps);
    // Order matches upstream prog.CallProps: FailNth (int), Async (bool), Rerun (int).
    write(w, static_cast<uint64_t>(p.fail_nth));
    write(w, p.async ? uint64_t{1} : uint64_t{0});
    write(w, static_cast<uint64_t>(p.rerun));
}

void write_copyout(ExecCtx& w, Call* c,
                   const std::unordered_set<const Arg*>& result_uses) {
    foreach_arg(c, [&](Arg* a, ArgCtx*) {
        if (a->arg_kind() != ArgKind::kResult) return;
        if (result_uses.find(a) == result_uses.end()) return;
        auto& info = w.args[a];
        if (info.ret) return;     // already counted by serialize_call
        info.idx     = w.copyout_seq++;
        info.has_addr = true;
        write(w, kExecInstrCopyout);
        write(w, info.idx);
        write(w, info.addr);
        write(w, a->size());
    });
}

// [v1 serialize_call → void — ROLLBACK: 还原 void;v2 fail-closed 让任一 arg
//  encode 失败 → 整条 program 返 ExecError,绝不输出 partial wire]
// [v2 PR-10] bool + propagate write_copyin / write_arg 失败到 serialize_for_exec
[[nodiscard]] bool serialize_call(ExecCtx& w, Call* c,
                                  const std::unordered_set<const Arg*>& result_uses) {
    if (c->meta() != nullptr && c->meta()->attrs().kfuzztest) {
        // serialize_for_exec rejects KFuzzTest programs before the write pass.
        return true;
    }
    if (!write_copyin(w, c)) return false;
    write_checksums(w);
    const auto& p = c->props();
    if (p.fail_nth != 0 || p.async || p.rerun != 0) {
        write_call_props(w, p);
    }
    if (c->meta() == nullptr) return true;  // 空 call,不写 call id,语义同 v1
    write(w, c->meta()->id());
    if (c->ret() != nullptr && result_uses.find(c->ret()) != result_uses.end()) {
        ArgInfo info;
        info.idx     = w.copyout_seq++;
        info.ret     = true;
        info.has_addr = true;
        w.args[c->ret()] = info;
        write(w, info.idx);
    } else {
        write(w, kExecNoCopyout);
    }
    write(w, c->args().size());
    for (auto& up : c->mutable_args()) {
        if (!write_arg(w, up.get())) return false;  // [v2 PR-10] propagate
    }
    write_copyout(w, c, result_uses);
    return true;
}

// First pass: discover the set of ResultArgs whose value is referenced
// by another ResultArg later in the program. Mirror of upstream
// "len(res.uses) != 0" — uses is a runtime-maintained set; we recompute
// it from the IR.
std::unordered_set<const Arg*> collect_result_uses(const Prog& prog) {
    std::unordered_set<const Arg*> out;
    for (const auto& cup : prog.calls()) {
        Call* c = cup.get();
        foreach_arg(c, [&](Arg* a, ArgCtx*) {
            if (a->arg_kind() != ArgKind::kResult) return;
            auto* ra = static_cast<ResultArg*>(a);
            if (ra->res() != nullptr) {
                out.insert(ra->res());
            }
        });
    }
    return out;
}

} // namespace

std::expected<std::vector<uint8_t>, ExecError>
serialize_for_exec(const Prog& prog) {
    refuzz::program::codec_counters::OnEncodeWire();
    if (prog.target() == nullptr) {
        return std::unexpected(ExecError{"prog.target is null"});
    }
    for (const auto& cup : prog.calls()) {
        const Call* c = cup.get();
        if (c != nullptr && c->meta() != nullptr && c->meta()->attrs().kfuzztest) {
            return std::unexpected(ExecError{
                "encodingexec: KFuzzTest serialization not supported"});
        }
    }
    ExecCtx w;
    w.target = prog.target();
    w.buf.reserve(4096);
    // [v2 PR-12 B2 — Step 2.5] cross-call producer search 用 prog 引用;
    // 不持有 ownership,只用于失败诊断 read。
    w.prog_ref = &prog;

    // Compute result-uses set + extend csum_uses with cross-call result
    // references. The upstream "willBeUsed" depends on
    // len(ResultArg.uses)>0 OR a csum reference. We pre-compute uses here.
    auto result_uses = collect_result_uses(prog);
    // willBeUsed needs to see result_uses in addition to csum maps. We
    // synthesize that by stuffing them into csum_uses for the duration —
    // semantically identical (any arg in either set gets an addr recorded).
    // ResultArg references are per-program, so we install once and never
    // clear, matching upstream args[arg]=argInfo persistence.
    for (const Arg* a : result_uses) {
        w.csum_uses.insert(const_cast<Arg*>(a));
    }

    write(w, prog.calls().size());
    const auto& calls_vec = prog.calls();
    for (std::size_t call_i = 0; call_i < calls_vec.size(); ++call_i) {
        Call* c = calls_vec[call_i].get();
        // [v2 PR-12 B2 — Step 2.5] 标记当前 call idx,write_arg [kResult]
        // 失败诊断会读 w.current_call_idx + w.prog_ref 搜 producer 反推 idx。
        w.current_call_idx = call_i;
        // Per-call csum analysis. Replace (do NOT augment) csum_uses for
        // each call, but preserve cross-call result-uses. The upstream
        // code rebuilds csum_map/csum_uses each call; result_uses is a
        // separate trigger.
        auto analysis = calc_checksums_call(c);
        w.csum_map = std::move(analysis.csum_map);
        // Reset csum_uses to (per-call csum hits) ∪ (program-wide result_uses).
        std::unordered_set<Arg*> uses_now = std::move(analysis.csum_uses);
        for (const Arg* a : result_uses) {
            uses_now.insert(const_cast<Arg*>(a));
        }
        w.csum_uses = std::move(uses_now);
        // [v2 Epic 7 PR-10] fail-closed: 任一 write_arg silent-no-op 路径触发
        // → serialize_call 返 false → 整条 program 返 ExecError,partial wire
        // 字节留在 w.buf 但**不**返回给 caller(下面 std::unexpected),IR-invariant
        // violation 暴露在 host 端而不是流到 worker 引发 decode_fail 风暴。
        // [v2 PR-12 B2] per-path classification:w.err_msg 由 write_arg 内 5 个
        // 路径填(`[kResult]/[kPointer]/[kData]/[kUnion]/[kGroup]` tag),传到
        // ExecError → dispatcher host_events.txt `err=` 字段;B2 audit 据此分类。
        if (!serialize_call(w, c, result_uses)) {
            std::string msg = "encodingexec: ";
            if (!w.err_msg.empty()) {
                msg += w.err_msg;
            } else {
                // 兜底:不该发生(write_arg 5 路径必填 err_msg);留在这里防 future
                // 引入新 fail 路径忘填。
                msg += "non-encodable arg (silent-no-op IR path; unspecified — "
                       "see exec_wire.cpp:write_arg) — "
                       "kResult/kPointer-size/kData-empty/kUnion-null-option/kGroup-leaf";
            }
            return std::unexpected(ExecError{std::move(msg)});
        }
    }
    write(w, kExecInstrEOF);

    if (w.buf.size() > kExecBufferSize) {
        char m[80];
        std::snprintf(m, sizeof(m), "encodingexec: too large program (%zu/%zu)",
                      w.buf.size(), kExecBufferSize);
        return std::unexpected(ExecError{m});
    }
    if (w.copyout_seq > kExecMaxCommands) {
        char m[80];
        std::snprintf(m, sizeof(m), "encodingexec: too many resources (%llu/%zu)",
                      static_cast<unsigned long long>(w.copyout_seq), kExecMaxCommands);
        return std::unexpected(ExecError{m});
    }
    return std::move(w.buf);
}

} // namespace refuzz::program::syz
