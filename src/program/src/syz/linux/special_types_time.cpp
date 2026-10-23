// Port of upstream sys/linux/init.go::generateTimespec.
// Handles both `timespec` and `timeval`; the only difference is that
// timeval expresses microseconds (so the few-ms-ahead arm divides by
// 1e3 instead of multiplying by 1e6).

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <memory>
#include <string>
#include <vector>

namespace refuzz::program::syz::linux_special_types {

namespace {

constexpr std::uint64_t kTimeoutMs1 = 10;
constexpr std::uint64_t kTimeoutMs2 = 60;
constexpr std::uint64_t kSecUnreachable = 2'000'000'000ULL;

// ResultArg with res=nullptr is the textual / exec-wire equivalent of
// a const value for an IntType field. We use ResultArg consistently to
// match upstream (MakeResultArg) and to keep the clock_gettime arm's
// reference-by-result pattern uniform with arms 1-3.
std::unique_ptr<ResultArg> make_result_const(const Type* t, Dir d,
                                             std::uint64_t v) {
    auto a = std::make_unique<ResultArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_val(v);
    return a;
}

std::unique_ptr<ResultArg> make_result_ref(const Type* t, Dir d,
                                           ResultArg* producer) {
    auto a = std::make_unique<ResultArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_res(producer);
    return a;
}

std::unique_ptr<GroupArg> make_group(const Type* t, Dir d,
                                     std::vector<std::unique_ptr<Arg>> inner) {
    auto g = std::make_unique<GroupArg>();
    g->set_type(t);
    g->set_dir(d);
    g->set_inner(std::move(inner));
    return g;
}

// Build a clock_gettime(CLOCK_REALTIME, &tp) call whose tp is a fresh
// timespec-shaped GroupArg with two ResultArg(out, val=0) inner fields.
// Returns {clock_gettime Call, tp_inner_args}; the caller references
// tp_inner_args[0]/[1] from the consumer timespec output.
struct ClockGettimePieces {
    std::unique_ptr<Call> call;
    ResultArg* tp_sec;
    ResultArg* tp_nsec;
};

ClockGettimePieces build_clock_gettime_call(Target::IGen* g) {
    const Target& target = g->target();
    const SyscallMeta* meta = target.find_syscall("clock_gettime");
    if (meta == nullptr || meta->args().size() < 2) return {};

    const Type* clockid_type = meta->args()[0].type();
    const Type* ptr_arg_type = meta->args()[1].type();
    if (ptr_arg_type == nullptr ||
        ptr_arg_type->kind() != TypeKind::kPtr) return {};
    const auto* ptr_t = static_cast<const PtrType*>(ptr_arg_type);
    const Type* elem = ptr_t->elem();
    if (elem == nullptr || elem->kind() != TypeKind::kStruct) return {};
    const auto* struct_t = static_cast<const StructType*>(elem);
    if (struct_t->fields().size() < 2) return {};

    auto sec_inner  = make_result_const(struct_t->fields()[0].type(),
                                        Dir::kOut, 0);
    auto nsec_inner = make_result_const(struct_t->fields()[1].type(),
                                        Dir::kOut, 0);
    ResultArg* sec_raw  = sec_inner.get();
    ResultArg* nsec_raw = nsec_inner.get();

    std::vector<std::unique_ptr<Arg>> inner;
    inner.push_back(std::move(sec_inner));
    inner.push_back(std::move(nsec_inner));
    auto tp = make_group(struct_t, Dir::kOut, std::move(inner));

    std::vector<std::unique_ptr<Call>> alloc_calls;
    auto tpaddr = g->alloc(ptr_t, Dir::kIn, std::move(tp), &alloc_calls);
    if (tpaddr == nullptr) return {};

    const std::uint64_t* clock_realtime =
        target.find_const("CLOCK_REALTIME");
    const std::uint64_t clockid_val =
        clock_realtime != nullptr ? *clock_realtime : 0;

    auto clockid_arg = std::make_unique<ConstArg>();
    clockid_arg->set_type(clockid_type);
    clockid_arg->set_dir(Dir::kIn);
    clockid_arg->set_val(clockid_val);

    auto call = std::make_unique<Call>();
    call->set_meta(meta);
    std::vector<std::unique_ptr<Arg>> args;
    args.push_back(std::move(clockid_arg));
    args.push_back(std::move(tpaddr));
    call->set_args(std::move(args));
    if (meta->ret() != nullptr) {
        auto ret = std::make_unique<ResultArg>();
        ret->set_type(meta->ret());
        ret->set_dir(Dir::kOut);
        call->set_ret(std::move(ret));
    }

    return {std::move(call), sec_raw, nsec_raw};
}

std::unique_ptr<Arg>
generate_timespec(Target::IGen* g, const Type* typ, Dir dir,
                  const Arg* /*old*/,
                  std::vector<std::unique_ptr<Call>>* extra_calls) {
    if (typ == nullptr || typ->kind() != TypeKind::kStruct) return nullptr;
    const auto* struct_t = static_cast<const StructType*>(typ);
    if (struct_t->fields().size() < 2) return nullptr;

    const Type* sec_t  = struct_t->fields()[0].type();
    const Type* nsec_t = struct_t->fields()[1].type();
    const bool usec = (typ->name() == "timeval");

    // Arm 1 (1/4): zero — "now" relative or "past" absolute.
    if (g->n_out_of(1, 4)) {
        std::vector<std::unique_ptr<Arg>> inner;
        inner.push_back(make_result_const(sec_t,  dir, 0));
        inner.push_back(make_result_const(nsec_t, dir, 0));
        return make_group(struct_t, dir, std::move(inner));
    }

    // Arm 2 (1/3): few-ms-ahead.
    if (g->n_out_of(1, 3)) {
        std::uint64_t nsec = kTimeoutMs1 * 1'000'000ULL;
        if (g->n_out_of(1, 2)) nsec = kTimeoutMs2 * 1'000'000ULL;
        if (usec) nsec /= 1'000;
        std::vector<std::unique_ptr<Arg>> inner;
        inner.push_back(make_result_const(sec_t,  dir, 0));
        inner.push_back(make_result_const(nsec_t, dir, nsec));
        return make_group(struct_t, dir, std::move(inner));
    }

    // Arm 3 (1/2): unreachable future.
    if (g->n_out_of(1, 2)) {
        std::vector<std::unique_ptr<Arg>> inner;
        inner.push_back(make_result_const(sec_t,  dir, kSecUnreachable));
        inner.push_back(make_result_const(nsec_t, dir, 0));
        return make_group(struct_t, dir, std::move(inner));
    }

    // Default arm: clock_gettime(CLOCK_REALTIME, &tp), reference its
    // outputs and add a small fixed delta. Requires the target to
    // expose clock_gettime; if absent, fall back to the few-ms-ahead
    // shape so the body never returns nullptr.
    auto pieces = build_clock_gettime_call(g);
    if (pieces.call == nullptr) {
        std::uint64_t nsec = kTimeoutMs1 * 1'000'000ULL;
        if (usec) nsec /= 1'000;
        std::vector<std::unique_ptr<Arg>> inner;
        inner.push_back(make_result_const(sec_t,  dir, 0));
        inner.push_back(make_result_const(nsec_t, dir, nsec));
        return make_group(struct_t, dir, std::move(inner));
    }

    if (extra_calls != nullptr) extra_calls->push_back(std::move(pieces.call));

    auto sec_arg  = make_result_ref(sec_t,  dir, pieces.tp_sec);
    auto nsec_arg = make_result_ref(nsec_t, dir, pieces.tp_nsec);
    std::uint64_t msec = kTimeoutMs1;
    if (g->n_out_of(1, 2)) msec = kTimeoutMs2;
    if (usec) {
        nsec_arg->set_op_div(1'000);
        nsec_arg->set_op_add(msec * 1'000);
    } else {
        nsec_arg->set_op_add(msec * 1'000'000);
    }
    std::vector<std::unique_ptr<Arg>> inner;
    inner.push_back(std::move(sec_arg));
    inner.push_back(std::move(nsec_arg));
    return make_group(struct_t, dir, std::move(inner));
}

} // namespace

Target::SpecialTypeFn make_timespec_fn() {
    return generate_timespec;
}

} // namespace refuzz::program::syz::linux_special_types
