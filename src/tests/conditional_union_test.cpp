// reFuzz syz_v2 — conditional-union correctness oracle (P3 / G6.4).
//
// Verifies the prog/expr.go::patchConditionalFields port: after generation,
// every CONDITIONAL union's selected arm must SATISFY its condition (evaluated
// against the final sibling-field values). A violation = the chosen arm's
// condition is computable and evaluates to false — i.e. the union shipped an
// arm that contradicts the descriptor's `if` rules.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/expr.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>
#include <vector>

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #cond,       \
                         __FILE__, __LINE__);                               \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;

int main() {
    const auto& target = syz::Target::linux_amd64();

    mut_v2::ChoiceTable ct;
    ct.build(target);
    CHECK(ct.ready());

    std::uint64_t conditional_unions = 0;  // conditional unions seen
    std::uint64_t with_condition     = 0;   // ...whose selected arm has a condition
    std::uint64_t computable         = 0;   // ...whose condition could be evaluated
    std::uint64_t violations         = 0;   // computable AND evaluates to false

    for (std::uint64_t i = 0; i < 4000; ++i) {
        auto prog = mut_v2::generate_program(
            target, /*seed=*/0x6c0000000000ULL + i, /*ncalls=*/10, &ct);
        if (!prog || prog->calls().empty()) continue;
        syz::assign_sizes_prog(*prog);

        for (auto& call : prog->mutable_calls()) {
            if (!call) continue;
            for (auto& arg_up : call->mutable_args()) {
                if (!arg_up) continue;
                syz::foreach_sub_arg_with_stack(
                    arg_up.get(), [&](syz::Arg* a, syz::ArgCtx* ctx) {
                        if (a != nullptr && syz::is_any_ptr(target, a->type())) {
                            ctx->stop = true;
                            return;
                        }
                        if (a == nullptr ||
                            a->arg_kind() != syz::ArgKind::kUnion) {
                            return;
                        }
                        const auto* t = a->type();
                        if (t == nullptr || t->kind() != syz::TypeKind::kUnion) return;
                        const auto* ut = static_cast<const syz::UnionType*>(t);
                        if (!ut->is_conditional()) return;
                        auto* ua = static_cast<syz::UnionArg*>(a);
                        ++conditional_unions;

                        const int idx = ua->index();
                        if (idx < 0 ||
                            idx >= static_cast<int>(ut->fields().size())) {
                            return;
                        }
                        const auto* cond = ut->fields()[static_cast<size_t>(idx)].condition();
                        if (cond == nullptr) return;  // no-condition arm: always valid
                        ++with_condition;

                        const std::vector<syz::Arg*> parents = ctx->parent_stack;
                        const syz::ArgFinder finder =
                            [&, parents](const std::vector<std::string>& p)
                                -> const syz::Arg* {
                                return syz::find_arg_by_path(ua->option(), p, parents);
                            };
                        const auto v = syz::evaluate_expr(cond, finder);
                        if (!v) return;  // uncomputable → not a violation
                        ++computable;
                        if (*v == 0) {
                            ++violations;
                            if (violations <= 3) {
                                std::fprintf(stderr,
                                    "VIOLATION seed=%llu union=%s arm=#%d "
                                    "condition false\n",
                                    static_cast<unsigned long long>(i),
                                    t->name().c_str(), idx);
                            }
                        }
                    });
            }
        }

        // The patched program must still lower to exec-wire cleanly.
        auto enc = syz::serialize_for_exec(*prog);
        CHECK(enc.has_value());
    }

    std::fprintf(stdout,
                 "conditional_union: unions=%llu with_condition=%llu "
                 "computable=%llu violations=%llu\n",
                 static_cast<unsigned long long>(conditional_unions),
                 static_cast<unsigned long long>(with_condition),
                 static_cast<unsigned long long>(computable),
                 static_cast<unsigned long long>(violations));

    // Correctness: no conditional union may ship an arm that contradicts its
    // (computable) condition.
    CHECK(violations == 0);
    std::fprintf(stdout, "ALL OK\n");
    return 0;
}
