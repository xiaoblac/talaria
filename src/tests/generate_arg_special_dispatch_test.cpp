// PR-3-B3 — SpecialType dispatch hook in generate_arg.
//
// generate_arg must route Struct / Union types whose name is registered
// in Target::SpecialTypes through the registered fn (with old=nullptr,
// dir != Out). generate_arg_no_special must skip the dispatch and run
// the per-kind default walk regardless of registration.
//
// Three deterministic cases over a tiny synthetic Target:
//   1. DispatchFiresForRegisteredStruct
//        `dispatch_probe` is registered as a SpecialType and its body
//        returns an empty GroupArg. The default per-kind walk would
//        return one inner arg for the single struct field.
//   2. NoSpecialBypassesRegistration
//        For the same type, generate_arg_no_special must skip the
//        SpecialType and return the default one-field GroupArg.
//   3. DirOutDisablesDispatch
//        With dir == kOut, the dispatch hook is gated off (mirror of
//        upstream rand.go:740 `dir != DirOut`). generate_arg(dir=Out)
//        on the same type must therefore return the default walk.

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;

struct ProbeTarget {
    syz::Target target{"test", "dispatch"};
    const syz::StructType* typ = nullptr;
    int special_calls = 0;

    ProbeTarget() {
        target.set_page_size(4096);
        target.set_num_pages(16);

        auto* field_t = target.arena().make<syz::IntType>();
        field_t->set_name("dispatch_probe_int");
        field_t->set_size(8);
        field_t->set_align(8);

        auto* struct_t = target.arena().make<syz::StructType>();
        struct_t->set_name("dispatch_probe");
        struct_t->set_size(8);
        struct_t->set_align(8);
        std::vector<syz::Field> fields;
        fields.emplace_back("value", field_t);
        struct_t->set_fields(std::move(fields));
        typ = struct_t;

        target.register_special_type(
            "dispatch_probe",
            [this](syz::Target::IGen* gen, const syz::Type* t,
                   syz::Dir d, const syz::Arg* old,
                   std::vector<std::unique_ptr<syz::Call>>* extra_calls)
                -> std::unique_ptr<syz::Arg> {
                (void)gen;
                (void)old;
                (void)extra_calls;
                ++special_calls;
                auto g = std::make_unique<syz::GroupArg>();
                g->set_type(t);
                g->set_dir(d);
                g->set_inner({});
                return g;
            });
    }
};

std::size_t group_inner_size(const syz::Arg* arg) {
    CHECK(arg != nullptr);
    CHECK(arg->arg_kind() == syz::ArgKind::kGroup);
    return static_cast<const syz::GroupArg*>(arg)->inner().size();
}

void test_dispatch_fires_for_registered_struct() {
    ProbeTarget f;
    CHECK(f.target.find_special_type("dispatch_probe") != nullptr);

    mut_v2::RandGen  r(0xB3000000ULL);
    mut_v2::GenState s(f.target);
    auto gr = mut_v2::generate_arg(r, s, f.typ, syz::Dir::kIn);

    CHECK(f.special_calls == 1);
    CHECK(group_inner_size(gr.arg.get()) == 0);
    CHECK(gr.calls.empty());
}

void test_no_special_bypasses_registration() {
    ProbeTarget f;

    mut_v2::RandGen  r(0xB3010000ULL);
    mut_v2::GenState s(f.target);
    auto gr = mut_v2::generate_arg_no_special(r, s, f.typ, syz::Dir::kIn);

    CHECK(f.special_calls == 0);
    CHECK(group_inner_size(gr.arg.get()) == 1);
    CHECK(gr.calls.empty());
}

void test_dir_out_disables_dispatch() {
    ProbeTarget f;

    mut_v2::RandGen  r(0xB3020000ULL);
    mut_v2::GenState s(f.target);
    auto gr = mut_v2::generate_arg(r, s, f.typ, syz::Dir::kOut);

    CHECK(f.special_calls == 0);
    CHECK(group_inner_size(gr.arg.get()) == 1);
    CHECK(gr.calls.empty());
}

} // namespace

int main() {
    RUN_TEST(test_dispatch_fires_for_registered_struct);
    RUN_TEST(test_no_special_bypasses_registration);
    RUN_TEST(test_dir_out_disables_dispatch);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
