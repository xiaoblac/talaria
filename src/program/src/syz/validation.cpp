// Implementation of refuzz/program/syz/validation.hpp.
//
// 1:1 port of syzkaller's prog/validation.go onto reFuzz v2 IR. The only
// structural difference is that ResultArg.uses is reconstructed once at
// the start (build_uses_map walker) rather than maintained as an IR field.

#include "refuzz/program/syz/validation.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <expected>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::program::syz {

namespace {

// True if this is a PtrType produced by ANY squashing. The encoder/decoder
// rewrites such PointerArg.type() to point at an ANY-wrapper distinct
// from the original syscall arg type, so validate must accept the mismatch.
// Mirrors `is_any_ptr` in encoding.cpp: shape is `ptr → array → union[ANYUNION]`.
bool is_any_ptr_type(const Type* t) {
    auto* pt = as_ptr(t);
    if (pt == nullptr) return false;
    auto* at = as_array(pt->elem());
    if (at == nullptr) return false;
    auto* ut = as_union(at->elem());
    return ut != nullptr && ut->name() == "ANYUNION";
}

class ValidCtx {
public:
    ValidCtx(const Target& target, const ValidateOptions& opts)
        : target_(target), opts_(opts) {}

    std::expected<void, std::string> validate_prog(const Prog& prog);

private:
    void build_uses_map(const Prog& prog);

    std::expected<void, std::string> validate_call(const Call& c);
    std::expected<void, std::string> validate_ret(const Call& c);
    std::expected<void, std::string> validate_arg(const Arg* arg, const Type* typ, Dir dir);

    std::expected<void, std::string> validate_const   (const ConstArg* a, Dir dir);
    std::expected<void, std::string> validate_result  (const ResultArg* a, Dir dir);
    std::expected<void, std::string> validate_data    (const DataArg* a, Dir dir);
    std::expected<void, std::string> validate_group   (const GroupArg* a, Dir dir);
    std::expected<void, std::string> validate_union   (const UnionArg* a, Dir dir);
    std::expected<void, std::string> validate_pointer (const PointerArg* a, Dir dir);

    const Target&                   target_;
    ValidateOptions                 opts_;
    std::unordered_set<const Arg*>  args_;
    // ResultArg.uses reconstruction: producer → list of consumers.
    std::unordered_map<const ResultArg*, std::vector<const ResultArg*>> uses_map_;
    // Track ResultArg uses observed during validation; checked at end vs
    // uses_map_ to detect out-of-tree references.
    std::unordered_map<const ResultArg*, const ResultArg*> uses_seen_;
    const Call*                     current_call_ = nullptr;
};

// ---------------------------------------------------------------
// build_uses_map: walk the whole prog before validation and index
// every ResultArg-with-res into uses_map_[res] → consumers.
// ---------------------------------------------------------------

void ValidCtx::build_uses_map(const Prog& prog) {
    uses_map_.clear();
    for (const auto& cup : prog.calls()) {
        Call* c = const_cast<Call*>(cup.get());
        foreach_arg(c, [&](Arg* a, ArgCtx*) {
            if (auto* ra = dynamic_cast<ResultArg*>(a)) {
                if (ra->res() != nullptr) {
                    uses_map_[ra->res()].push_back(ra);
                }
            }
        });
    }
}

// ---------------------------------------------------------------
// Top-level validate
// ---------------------------------------------------------------

std::expected<void, std::string> ValidCtx::validate_prog(const Prog& prog) {
    build_uses_map(prog);

    for (std::size_t i = 0; i < prog.calls().size(); ++i) {
        const Call& c = *prog.calls()[i];
        if (c.meta() == nullptr) {
            return std::unexpected("call does not have meta information");
        }
        current_call_ = &c;
        if (auto r = validate_call(c); !r) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "call #%zu %s: ", i, c.meta()->name().c_str());
            return std::unexpected(std::string(buf) + r.error());
        }
    }
    current_call_ = nullptr;

    // Sanity: every uses-link we observed must point to an in-tree ResultArg.
    for (auto& [user, producer] : uses_seen_) {
        if (args_.count(user) == 0) {
            return std::unexpected("use refers to an out-of-tree ResultArg");
        }
    }
    return {};
}

// ---------------------------------------------------------------
// validate_call / validate_ret
// ---------------------------------------------------------------

std::expected<void, std::string> ValidCtx::validate_call(const Call& c) {
    if (!opts_.is_unsafe && c.meta()->attrs().disabled) {
        return std::unexpected("use of a disabled call");
    }
    if (c.props().rerun > 0 && c.props().fail_nth > 0) {
        return std::unexpected("rerun > 0 && fail_nth > 0");
    }
    if (c.args().size() != c.meta()->args().size()) {
        char buf[96];
        std::snprintf(buf, sizeof(buf),
                      "wrong number of arguments, want %zu, got %zu",
                      c.meta()->args().size(), c.args().size());
        return std::unexpected(buf);
    }
    for (std::size_t i = 0; i < c.args().size(); ++i) {
        if (auto r = validate_arg(c.args()[i].get(),
                                  c.meta()->args()[i].type(), Dir::kIn);
            !r) {
            return r;
        }
    }
    // checkConditions (conditional union sanity) is skipped for now — we
    // don't yet implement Call.setDefaultConditions in v2. Add a hook
    // here when conditional fields are wired up.
    return validate_ret(c);
}

std::expected<void, std::string> ValidCtx::validate_ret(const Call& c) {
    if (c.meta()->ret() == nullptr) {
        if (c.ret() != nullptr) {
            return std::unexpected("return value without type");
        }
        return {};
    }
    if (c.ret() == nullptr) {
        return std::unexpected("return value is absent");
    }
    const ResultArg* r = c.ret();
    if (r->res() != nullptr || r->val() != 0 ||
        r->op_div() != 0 || r->op_add() != 0) {
        return std::unexpected("return value is not empty");
    }
    return validate_arg(r, c.meta()->ret(), Dir::kOut);
}

// ---------------------------------------------------------------
// validate_arg: dispatch + common checks
// ---------------------------------------------------------------

std::expected<void, std::string> ValidCtx::validate_arg(
    const Arg* arg, const Type* typ, Dir dir) {
    if (arg == nullptr) return std::unexpected("nil arg");
    if (args_.count(arg) != 0) {
        return std::unexpected("arg referenced multiple times in tree");
    }
    if (arg->type() == nullptr) {
        return std::unexpected("no arg type");
    }
    if (typ != nullptr && typ->kind() == TypeKind::kPtr) {
        dir = Dir::kIn;        // pointers are always in
    }
    if (arg->dir() != dir && dir != Dir::kInOut) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "arg type %s has wrong dir %d, expect %d",
                      arg->type()->name().c_str(),
                      static_cast<int>(arg->dir()),
                      static_cast<int>(dir));
        return std::unexpected(buf);
    }
    // ANY-squashed pointers: arg.type() is rewritten to an ANY wrapper,
    // distinct from the syscall's original ptr type. Skip identity check
    // for those; downstream PtrType-internal checks still run.
    if (arg->type() != typ && !is_any_ptr_type(arg->type())) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "bad arg type %s, expect %s",
                      arg->type()->name().c_str(),
                      typ != nullptr ? typ->name().c_str() : "(null)");
        return std::unexpected(buf);
    }
    if (current_call_ != nullptr &&
        current_call_->meta()->attrs().no_squash &&
        is_any_ptr_type(arg->type())) {
        return std::unexpected(
            std::string("ANY argument for no_squash call ") +
            current_call_->meta()->name());
    }
    args_.insert(arg);

    switch (arg->arg_kind()) {
        case ArgKind::kConst:
            return validate_const(static_cast<const ConstArg*>(arg), dir);
        case ArgKind::kResult:
            return validate_result(static_cast<const ResultArg*>(arg), dir);
        case ArgKind::kData:
            return validate_data(static_cast<const DataArg*>(arg), dir);
        case ArgKind::kGroup:
            return validate_group(static_cast<const GroupArg*>(arg), dir);
        case ArgKind::kUnion:
            return validate_union(static_cast<const UnionArg*>(arg), dir);
        case ArgKind::kPointer:
            return validate_pointer(static_cast<const PointerArg*>(arg), dir);
    }
    return std::unexpected("unknown arg kind");
}

// ---------------------------------------------------------------
// Per-kind validators
// ---------------------------------------------------------------

std::expected<void, std::string> ValidCtx::validate_const(const ConstArg* a, Dir /*dir*/) {
    const Type* t = a->type();
    switch (t->kind()) {
        case TypeKind::kInt: {
            if (a->dir() == Dir::kOut && !is_default_arg(a)) {
                return std::unexpected("out int arg has bad const value");
            }
            break;
        }
        case TypeKind::kProc: {
            const auto* pt = static_cast<const ProcType*>(t);
            if (a->val() >= pt->values_per_proc() && !is_default_arg(a)) {
                return std::unexpected("per-proc arg has bad value");
            }
            break;
        }
        case TypeKind::kCsum: {
            if (a->val() != 0) {
                return std::unexpected("csum arg has nonzero value");
            }
            break;
        }
        case TypeKind::kConst:
        case TypeKind::kFlags:
        case TypeKind::kLen:
            break;
        default:
            return std::unexpected(
                std::string("const arg has bad type ") + t->name());
    }
    if (a->dir() == Dir::kOut && t->kind() != TypeKind::kLen) {
        if (!is_default_arg(a)) {
            return std::unexpected(
                std::string("output arg ") + t->name() + " has non-default value");
        }
    }
    return {};
}

std::expected<void, std::string> ValidCtx::validate_result(const ResultArg* a, Dir /*dir*/) {
    const auto* rt = as_resource(a->type());
    if (rt == nullptr) {
        return std::unexpected("result arg has bad type");
    }

    // Walk reconstructed uses_map_: every consumer must back-link to us.
    auto it = uses_map_.find(a);
    if (it != uses_map_.end()) {
        for (const ResultArg* u : it->second) {
            if (u == nullptr) {
                return std::unexpected("nil reference in uses");
            }
            if (u->res() != a) {
                return std::unexpected("result arg has broken uses link");
            }
            uses_seen_[u] = a;
        }
    }

    if (a->dir() == Dir::kOut && a->val() != 0) {
        uint64_t def = 0;
        if (rt->desc() != nullptr && !rt->desc()->values().empty()) {
            def = rt->desc()->values()[0];
        }
        if (a->val() != def) {
            return std::unexpected("out resource arg has bad const value");
        }
    }
    if (a->res() != nullptr) {
        // Forward-link must hit an arg that we've already validated.
        if (args_.count(a->res()) == 0) {
            return std::unexpected("result arg references out-of-tree result");
        }
        // Reverse-link must list us as a consumer.
        auto pit = uses_map_.find(a->res());
        bool linked = false;
        if (pit != uses_map_.end()) {
            for (const ResultArg* u : pit->second) {
                if (u == a) { linked = true; break; }
            }
        }
        if (!linked) {
            return std::unexpected("result arg has broken back-link");
        }
    }
    if (a->dir() == Dir::kIn) {
        auto in_it = uses_map_.find(a);
        if (in_it != uses_map_.end() && !in_it->second.empty()) {
            return std::unexpected("input result arg is used");
        }
    }
    if (it != uses_map_.end() && !it->second.empty() && a->size() > 8) {
        return std::unexpected("used result arg is bigger than int64");
    }
    return {};
}

std::expected<void, std::string> ValidCtx::validate_data(const DataArg* a, Dir /*dir*/) {
    const auto* bt = as_buffer(a->type());
    if (bt == nullptr) {
        return std::unexpected("data arg has bad type");
    }
    if (a->dir() == Dir::kOut && !a->data().empty()) {
        return std::unexpected("output data arg has data");
    }
    if (!bt->var_len() && bt->size() != a->size()) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "data arg has wrong size %llu, want %llu",
                      static_cast<unsigned long long>(a->size()),
                      static_cast<unsigned long long>(bt->size()));
        return std::unexpected(buf);
    }
    if (bt->buffer_kind() == BufferKind::kFilename && !opts_.is_unsafe) {
        // Conservative escaping check: any segment "..".
        const auto& d = a->data();
        for (std::size_t i = 0; i + 1 < d.size(); ++i) {
            if (d[i] == '.' && d[i + 1] == '.') {
                if (i == 0 || d[i - 1] == '/' || d[i - 1] == '\\') {
                    if (i + 2 == d.size() || d[i + 2] == '/' ||
                        d[i + 2] == '\\' || d[i + 2] == 0) {
                        return std::unexpected("escaping filename");
                    }
                }
            }
        }
    }
    return {};
}

std::expected<void, std::string> ValidCtx::validate_group(const GroupArg* a, Dir dir) {
    if (auto* st = as_struct(a->type())) {
        if (a->inner().size() != st->fields().size()) {
            return std::unexpected("struct arg has wrong number of fields");
        }
        for (std::size_t i = 0; i < a->inner().size(); ++i) {
            if (auto r = validate_arg(a->inner()[i].get(),
                                      st->fields()[i].type(),
                                      st->fields()[i].dir(dir)); !r) {
                return r;
            }
        }
        return {};
    }
    if (auto* at = as_array(a->type())) {
        const bool fixed = at->array_kind() == ArrayKind::kRangeLen &&
                           at->range_begin() == at->range_end();
        if (fixed && a->inner().size() != at->range_begin()) {
            return std::unexpected("array has wrong number of elements");
        }
        for (const auto& up : a->inner()) {
            if (auto r = validate_arg(up.get(), at->elem(), dir); !r) {
                return r;
            }
        }
        return {};
    }
    return std::unexpected("group arg has bad type");
}

std::expected<void, std::string> ValidCtx::validate_union(const UnionArg* a, Dir dir) {
    const auto* ut = as_union(a->type());
    if (ut == nullptr) {
        return std::unexpected("union arg has bad type");
    }
    if (a->index() < 0 || a->index() >= static_cast<int>(ut->fields().size())) {
        return std::unexpected("union arg has bad index");
    }
    if (a->transient() && !opts_.ignore_transient) {
        return std::unexpected("union arg is transient (incomplete)");
    }
    const Field& opt = ut->fields()[a->index()];
    return validate_arg(a->option(), opt.type(), opt.dir(dir));
}

std::expected<void, std::string> ValidCtx::validate_pointer(const PointerArg* a, Dir /*dir*/) {
    const Type* t = a->type();
    if (auto* vm = as_vma(t)) {
        (void)vm;
        if (a->res() != nullptr) {
            return std::unexpected("vma arg has data");
        }
    } else if (auto* pt = as_ptr(t)) {
        if (a->res() != nullptr) {
            if (auto r = validate_arg(a->res(), pt->elem(), pt->elem_dir()); !r) {
                return r;
            }
        }
        if (a->vma_size() != 0) {
            return std::unexpected("pointer arg has nonzero vma size");
        }
        if (a->dir() == Dir::kOut) {
            return std::unexpected("pointer arg has output direction");
        }
    } else {
        return std::unexpected("ptr arg has bad type");
    }

    if (a->is_special()) {
        const uint64_t neg = static_cast<uint64_t>(-static_cast<int64_t>(a->address()));
        if (neg >= target_.special_pointers().size()) {
            return std::unexpected("special ptr arg has bad value");
        }
        // [v2 PR-D] non-optional ptr 不能用 special pointer 编码 — Plan B
        // 由 opts_.strict_invariant 启用 (default off,保持现有 caller 行为)。
        // 兜底 PR-B (generator depth fallback) 之外的所有来源:corpus seed /
        // 第三方 mutator / future regression。非 optional ptr field 必须有
        // 真实 res 或 vma_size>0,产 special pointer (NULL/0xff..ff/0x99..99
        // /kernel/vdso) 就是定义违反 — 该 syscall coverage 永远走不进。
        // task 10 baseline 跑完确认现存 corpus 不误报后,考虑翻默认 + 在
        // serialize_for_exec 入口主动 validate (Part 3 follow-up)。
        // 显式 cast 是防御性的:line 416 已 implicit 守住 t 是 ptr 类型
        // (vma 路径 vma_size>0 → is_special 必 false 不进本分支),但 inline
        // cast 让 future 路径绕过时也安全。
        if (opts_.strict_invariant) {
            if (auto* pt = as_ptr(t); pt != nullptr && !pt->optional()) {
                return std::unexpected("non-optional ptr arg used as special pointer");
            }
        }
    } else {
        uint64_t maxMem = target_.num_pages() * target_.page_size();
        uint64_t addr   = a->address();
        uint64_t size   = a->vma_size();
        if (size == 0 && a->res() != nullptr) {
            size = a->res()->size();
        }
        if (opts_.is_unsafe) {
            // Allow 2 surrounding pages for DataMmapProg.
            addr   += target_.page_size();
            maxMem += 2 * target_.page_size();
        }
        if (addr >= maxMem || addr + size > maxMem) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "ptr has bad address 0x%llx (vma=%llu size=%llu)",
                          static_cast<unsigned long long>(a->address()),
                          static_cast<unsigned long long>(a->vma_size()),
                          static_cast<unsigned long long>(size));
            return std::unexpected(buf);
        }
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------

std::expected<void, ValidateError>
validate(const Prog& prog, const ValidateOptions& opts) {
    if (prog.target() == nullptr) {
        ValidateError e{};
        e.message = "prog has null target";
        return std::unexpected(e);
    }
    ValidCtx ctx(*prog.target(), opts);
    auto r = ctx.validate_prog(prog);
    if (r) return {};
    ValidateError e{};
    e.message = r.error();
    return std::unexpected(e);
}

} // namespace refuzz::program::syz
