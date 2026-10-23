#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>

int main()
{
    using namespace refuzz::fuzzer::syz;

    const SyzTargetTables& target = kDefaultSyzTarget;
    assert(std::strcmp(target.id.os, "linux") == 0);
    assert(std::strcmp(target.id.arch, "amd64") == 0);
    assert(target.pseudo_nr_base == target.pseudos.base);
    assert(target.max_real_nr < target.pseudo_nr_base);
    assert(target.pseudos.entries != nullptr);
    assert(target.pseudos.size >= 150);

    for (size_t i = 0; i < target.pseudos.size; ++i) {
        const PseudoMeta& entry = target.pseudos.entries[i];
        assert(entry.nr == target.pseudos.base + i);
        assert(entry.name != nullptr);
    }

    std::array<intptr_t, 6> args = {};
    errno = 0;
    auto result = refuzz::worker::DispatchPseudo(refuzz::worker::DefaultPseudoContext(),
                                                 1,
                                                 args.data(),
                                                 static_cast<uint32_t>(args.size()));
    assert(result.ret == -1);
    assert(result.err == ENOSYS);

    errno = 0;
    result = refuzz::worker::DispatchPseudo(refuzz::worker::DefaultPseudoContext(),
                                            target.pseudo_nr_base + target.pseudos.size + 1,
                                            args.data(),
                                            static_cast<uint32_t>(args.size()));
    assert(result.ret == -1);
    assert(result.err == ENOSYS);
    return 0;
}
