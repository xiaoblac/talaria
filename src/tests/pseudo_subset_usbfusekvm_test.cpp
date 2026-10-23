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

// [PR-D3] syz_fuse_handle_req is now kNative — handler runs through
// dispatcher. With all-zero args the args[3] (req_out) is null; handler
// validates and returns -1 with err == 0 (graceful, mirrors upstream
// debug-log + return -1 path). NOT ENOSYS.
void TestFuseHandlesNullReqOut()
{
    const auto& entry = FindPseudo("syz_fuse_handle_req");
    std::array<intptr_t, 6> args = {};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 4);
    assert(result.ret == -1);
    assert(result.err == 0);  // never ENOSYS post-PR-D3
}

int main()
{
    TestFuseHandlesNullReqOut();
    return 0;
}
