// §3.10 Epic 2 step-2 unit test — SyscallMeta pseudo identity fields.
//
// Pins:
//   - Synthesized pseudo NR ≥ kPseudoNrBase (1 << 20).
//   - is_pseudo() agrees with the numeric range gate.
//   - typed pseudo count matches the worker-side kLinuxAmd64PseudoMetaSize.
//   - kPseudoNrBase matches the worker-side constant.
//
// [impl-kind removed] reFuzz no longer classifies pseudos as
// native/stub/unsupported, so there is nothing to assert about pseudo_impl.
// Pseudo identity is purely the NR-range gate (is_pseudo); non-fuzzable
// pseudos carry syz's (disabled) attr, exercised elsewhere.

#include "refuzz/program/syz/pseudo/target_view.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <string_view>

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

namespace syz = ::refuzz::program::syz;

const syz::SyscallMeta* require_syscall(std::string_view name) {
    const auto* m = syz::Target::linux_amd64().find_syscall(name);
    CHECK(m != nullptr);
    return m;
}

void test_real_syscall_is_not_pseudo() {
    const auto* read_meta = require_syscall("read");
    CHECK(read_meta->is_pseudo() == false);
    CHECK(read_meta->nr() < syz::kPseudoNrBase);
}

void test_synthesized_pseudo_identity() {
    // syz_open_dev$* is a synthesized pseudo: NR ≥ kPseudoNrBase and
    // is_pseudo() agrees with the numeric range gate.
    const auto* meta = require_syscall("syz_open_dev$I2C");
    CHECK(meta->is_pseudo() == true);
    CHECK(meta->nr() >= syz::kPseudoNrBase);
}

void test_pseudo_count_matches_worker_table() {
    // Cross-source invariant: counting is_pseudo == true syscalls in
    // the typed Target must match worker-side
    // kLinuxAmd64PseudoMetaSize. Target::finalize() also enforces
    // this (with std::abort on mismatch); this test pins the
    // observable count so a syzgen drift surfaces in CI rather than
    // at first Target init.
    std::size_t pseudo_count = 0;
    for (const auto& sc : syz::Target::linux_amd64().syscalls()) {
        if (sc && sc->is_pseudo()) {
            ++pseudo_count;
        }
    }
    CHECK(pseudo_count == ::refuzz::fuzzer::syz::kLinuxAmd64PseudoMetaSize);
}

void test_kPseudoNrBase_matches_worker_constant() {
    CHECK(syz::kPseudoNrBase == ::refuzz::fuzzer::syz::kLinuxAmd64PseudoNrBase);
}

}  // namespace

int main() {
    RUN_TEST(test_kPseudoNrBase_matches_worker_constant);
    RUN_TEST(test_real_syscall_is_not_pseudo);
    RUN_TEST(test_synthesized_pseudo_identity);
    RUN_TEST(test_pseudo_count_matches_worker_table);
    return 0;
}
