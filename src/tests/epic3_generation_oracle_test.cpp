// Epic 3 probabilistic generation oracles, invoked by
// tools/run_all_oracles.sh (not registered as default CTest).
//
// Modes:
//   --resource-link-rate  oracle #26, 1000 generated programs
//   --anyres-spoof       oracle #27, 5000 create_resource attempts

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "syz_v2_test_helpers.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;
using ::refuzz::tests::syz_v2::find_resource_type;

int oracle_resource_link_rate() {
    const auto& target = syz::Target::linux_amd64();

    mut_v2::ChoiceTable ct;
    ct.build(target);
    CHECK(ct.ready());

    std::uint64_t consumers = 0;
    std::uint64_t linked    = 0;

    for (std::uint64_t i = 0; i < 1000; ++i) {
        auto prog = mut_v2::generate_program(
            target, /*seed=*/0x260000000000ULL + i,
            /*ncalls=*/8, &ct);
        CHECK(prog != nullptr);
        for (auto& call : prog->mutable_calls()) {
            if (!call) continue;
            syz::foreach_arg(call.get(), [&](syz::Arg* arg, syz::ArgCtx*) {
                if (arg == nullptr ||
                    arg->arg_kind() != syz::ArgKind::kResult ||
                    arg->dir() == syz::Dir::kOut ||
                    arg->type() == nullptr ||
                    arg->type()->kind() != syz::TypeKind::kResource) {
                    return;
                }
                ++consumers;
                if (static_cast<syz::ResultArg*>(arg)->res() != nullptr) {
                    ++linked;
                }
            });
        }
    }

    CHECK(consumers > 0);
    const double rate = static_cast<double>(linked) /
                        static_cast<double>(consumers);
    std::fprintf(stdout,
                 "oracle #26 resource_link_rate: linked=%llu consumers=%llu "
                 "rate=%.4f\n",
                 static_cast<unsigned long long>(linked),
                 static_cast<unsigned long long>(consumers),
                 rate);
    CHECK(rate >= 0.15);
    std::fprintf(stdout, "ALL OK\n");
    return 0;
}

int oracle_anyres_spoof() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::reset_anyres_spoof_hits();
    int succeeded = 0;
    for (int i = 0; i < 5000; ++i) {
        mut_v2::RandGen r(0x27000000ULL + static_cast<std::uint64_t>(i));
        mut_v2::GenState s(target);
        auto result = mut_v2::create_resource(r, s, fd_rt, syz::Dir::kIn);
        if (result.arg != nullptr) ++succeeded;
    }

    const std::uint64_t spoofs = mut_v2::anyres_spoof_hits();
    std::fprintf(stdout,
                 "oracle #27 anyres_spoof: succeeded=%d spoofs=%llu "
                 "iters=5000\n",
                 succeeded,
                 static_cast<unsigned long long>(spoofs));
    CHECK(succeeded >= 4500);
    CHECK(spoofs >= 1 && spoofs <= 25);
    std::fprintf(stdout, "ALL OK\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr,
                     "usage: %s --resource-link-rate|--anyres-spoof\n",
                     argv[0]);
        return 2;
    }
    if (std::strcmp(argv[1], "--resource-link-rate") == 0) {
        return oracle_resource_link_rate();
    }
    if (std::strcmp(argv[1], "--anyres-spoof") == 0) {
        return oracle_anyres_spoof();
    }
    std::fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
