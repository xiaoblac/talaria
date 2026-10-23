// reFuzz syz_v2 — squash-to-ANY round-trip oracle (P2-M1).
//
// Verifies prog/any.go::squashPtr was ported correctly. For each generated
// program containing a complex (squashable) pointer we squash it and assert:
//
//   (1) the pointer becomes an any-ptr (is_any_ptr);
//   (2) SIZE INVARIANT — the flattened ANYUNION array occupies byte-for-byte
//       the same space as the original structured pointee (this is the
//       property upstream squashPtr guards with a panic);
//   (3) the squashed program still serialises to exec-wire without error;
//   (4) DOUBLE-SQUASH IDEMPOTENCE — squashing an already-squashed pointer
//       yields byte-identical exec-wire output (mirrors syz any_test.go
//       TestSquash's p1==p2 check). This catches any drift in the byte
//       serialisation (wrong endianness, padding, bitfield packing, ...).

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>

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

    std::uint64_t squashed   = 0;   // complex ptrs squashed + fully checked
    std::uint64_t idempotent = 0;   // double-squash byte-identical
    std::uint64_t progs_seen = 0;

    for (std::uint64_t i = 0; i < 6000; ++i) {
        auto prog = mut_v2::generate_program(
            target, /*seed=*/0x510000000000ULL + i, /*ncalls=*/10, &ct);
        if (!prog || prog->calls().empty()) continue;
        // Put LenType args into a consistent state so exec-wire encoding is a
        // fair before/after comparison (mirrors the engine's post-gen pass).
        syz::assign_sizes_prog(*prog);
        ++progs_seen;

        auto cands = syz::complex_ptrs(target, *prog);
        if (cands.empty()) continue;

        // Deterministically squash the first complex pointer.
        syz::PointerArg* ptr = cands[0].arg;
        if (ptr == nullptr || ptr->res() == nullptr) continue;
        if (syz::is_any_ptr(target, ptr->type())) continue;  // already squashed

        const std::uint64_t size0 = ptr->res()->size();

        syz::squash_ptr(target, ptr);

        // (1) now an any-ptr with a live pointee.
        CHECK(syz::is_any_ptr(target, ptr->type()));
        CHECK(ptr->res() != nullptr);

        // (2) size invariant — the flattened array occupies the same bytes.
        if (ptr->res()->size() != size0) {
            std::fprintf(stderr,
                         "SIZE INVARIANT VIOLATED: seed=%llu  %llu -> %llu\n",
                         static_cast<unsigned long long>(i),
                         static_cast<unsigned long long>(size0),
                         static_cast<unsigned long long>(ptr->res()->size()));
            std::abort();
        }

        // (3) squashed program serialises to exec-wire cleanly.
        auto enc1 = syz::serialize_for_exec(*prog);
        CHECK(enc1.has_value());
        ++squashed;

        // (4) double-squash idempotence — byte-identical exec-wire.
        syz::squash_ptr(target, ptr);
        CHECK(syz::is_any_ptr(target, ptr->type()));
        CHECK(ptr->res()->size() == size0);
        auto enc2 = syz::serialize_for_exec(*prog);
        CHECK(enc2.has_value());
        if (enc1.value() != enc2.value()) {
            std::fprintf(stderr,
                         "DOUBLE-SQUASH NOT IDEMPOTENT: seed=%llu  "
                         "%zu vs %zu bytes\n",
                         static_cast<unsigned long long>(i),
                         enc1.value().size(), enc2.value().size());
            std::abort();
        }
        ++idempotent;
    }

    std::fprintf(stdout,
                 "squash_any_roundtrip: progs=%llu squashed=%llu idempotent=%llu\n",
                 static_cast<unsigned long long>(progs_seen),
                 static_cast<unsigned long long>(squashed),
                 static_cast<unsigned long long>(idempotent));

    // Must have actually exercised the squash path (else the test proves
    // nothing — e.g. complex_ptrs broken or generation produces none).
    CHECK(squashed > 0);
    CHECK(idempotent == squashed);
    std::fprintf(stdout, "ALL OK\n");
    return 0;
}
