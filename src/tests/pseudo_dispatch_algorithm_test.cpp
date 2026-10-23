#include "worker/backend/pseudo/pseudo_dispatcher.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>

namespace {

int TestDenseDispatch()
{
    using refuzz::fuzzer::syz::PseudoDomain;
    using refuzz::fuzzer::syz::PseudoMeta;
    using refuzz::fuzzer::syz::PseudoMetaTable;
    using refuzz::worker::DispatchPseudo;
    using refuzz::worker::PseudoContext;

    PseudoMeta entries[] = {
        {0x1000ULL, "syz_create_resource$test", 1u,
         PseudoDomain::kCore, {}},
        {0x1001ULL, "syz_unknown", 0u,
         PseudoDomain::kUnknown, {}},
    };
    PseudoMetaTable table{0x1000ULL, entries, 2};
    PseudoContext ctx{&table, 0u};
    const intptr_t args[] = {0x1234};

    const auto ok = DispatchPseudo(ctx, 0x1000ULL, args, 1);
    assert(ok.ret == 0x1234);
    assert(ok.err == 0);

    const auto unsupported = DispatchPseudo(ctx, 0x1001ULL, args, 0);
    assert(unsupported.ret == -1);
    assert(unsupported.err == ENOSYS);
    return 0;
}

int TestMissesReturnEnosys()
{
    using refuzz::fuzzer::syz::PseudoDomain;
    using refuzz::fuzzer::syz::PseudoMeta;
    using refuzz::fuzzer::syz::PseudoMetaTable;
    using refuzz::worker::DispatchPseudo;
    using refuzz::worker::PseudoContext;

    PseudoMeta sparse[] = {
        {0x2000ULL, "syz_create_resource$first", 1u,
         PseudoDomain::kCore, {}},
        {0x2005ULL, "syz_create_resource$sparse", 1u,
         PseudoDomain::kCore, {}},
        {0x2002ULL, nullptr, 0u,
         PseudoDomain::kUnknown, {}},
    };
    PseudoMetaTable table{0x2000ULL, sparse, 3};
    PseudoContext ctx{&table, 0u};
    const intptr_t args[] = {0};

    assert(DispatchPseudo(ctx, 0x1fffULL, args, 0).err == ENOSYS);
    assert(DispatchPseudo(ctx, 0x3000ULL, args, 0).err == ENOSYS);
    assert(DispatchPseudo(ctx, 0x2001ULL, args, 0).err == ENOSYS);
    assert(DispatchPseudo(ctx, 0x2002ULL, args, 0).err == ENOSYS);

    PseudoMetaTable empty{0x4000ULL, nullptr, 0};
    PseudoContext empty_ctx{&empty, 0u};
    assert(DispatchPseudo(empty_ctx, 0x4000ULL, args, 0).err == ENOSYS);
    return 0;
}

} // namespace

int main()
{
    assert(TestDenseDispatch() == 0);
    assert(TestMissesReturnEnosys() == 0);
    return 0;
}
