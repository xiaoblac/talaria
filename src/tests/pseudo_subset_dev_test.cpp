#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <unistd.h>

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
    const auto& entry = FindPseudo("syz_open_dev$loop");
    char dev[] = "/dev/loop#";
    std::array<intptr_t, 6> args = {reinterpret_cast<intptr_t>(dev), 0, 0};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 3);
    if (result.ret >= 0) {
        assert(result.err == 0);
        close(static_cast<int>(result.ret));
    }
    return 0;
}
