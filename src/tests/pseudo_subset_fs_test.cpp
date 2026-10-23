#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>

namespace {

const refuzz::fuzzer::syz::PseudoMeta& FindPseudo(const char* name)
{
    const auto& table = refuzz::fuzzer::syz::kDefaultSyzTarget.pseudos;
    for (size_t i = 0; i < table.size; ++i) {
        if (std::strcmp(table.entries[i].name, name) == 0) {
            return table.entries[i];
        }
    }
    assert(false && "pseudo not found");
    return table.entries[0];
}

} // namespace

int main()
{
    {
        // [Lane 3 close 2026-05-06] After PR-D1.A all 43 syz_mount_image
        // variants are kNative + kMount domain. There is no remaining
        // kStub pseudo in the fs domain (or anywhere in production
        // catalog). The kStub gate path of DispatchPseudo is still
        // worth exercising; switch fixture to syz_builtin0, an
        // upstream-disabled placeholder that stays kUnsupported by
        // design (plan §11; Target::finalize gates it out of generation
        // but the worker pseudo table entry is still reachable by NR).
        // [impl-kind removed] syz_builtin0's domain is kUnknown, so
        // DispatchPseudo's domain switch hits the default → ENOSYS. It is
        // also syz-(disabled), so generation never picks it; the worker
        // table entry stays reachable by NR for this direct-dispatch check.
        const auto& entry = FindPseudo("syz_builtin0");
        std::array<intptr_t, 6> args = {};
        const auto result = refuzz::worker::DispatchPseudo(
            refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 6);
        assert(result.ret == -1);
        assert(result.err == ENOSYS);
    }
    {
        const auto& entry = FindPseudo("syz_read_part_table");
        unsigned char image[512] = {};
        image[510] = 0x55;
        image[511] = 0xaa;
        std::array<intptr_t, 6> args = {
            static_cast<intptr_t>(sizeof(image)),
            reinterpret_cast<intptr_t>(image),
        };
        const auto ctx = refuzz::worker::DefaultPseudoContext();
        const auto result = refuzz::worker::DispatchPseudo(
            ctx, entry.nr, args.data(), 2);
        if (result.ret >= 0) {
            assert(result.err == 0);
        } else {
            // EIO covers "fixture is raw MBR, not a zlib stream" — after
            // the silent-drift fix, syz_read_part_table now mirrors upstream
            // and decompresses image bytes via libz; raw input fails at
            // inflateInit (per common_zlib.h:469-498 mechanism). The test
            // fixture intentionally stays a raw MBR to exercise the error
            // path; success path requires a real zlib-deflated image and
            // root + /dev/loop-control which CI may lack.
            assert(result.err == EPERM || result.err == EACCES ||
                   result.err == ENOENT || result.err == ENODEV ||
                   result.err == EBUSY || result.err == EINVAL ||
                   result.err == ENOTTY || result.err == EROFS ||
                   result.err == EIO);
            assert(result.err != ENOSYS);
        }

        std::array<intptr_t, 6> bad_args = {0, reinterpret_cast<intptr_t>(image)};
        const auto bad = refuzz::worker::DispatchPseudo(
            ctx, entry.nr, bad_args.data(), 2);
        assert(bad.ret == -1);
        assert(bad.err == EINVAL);
    }
    return 0;
}
