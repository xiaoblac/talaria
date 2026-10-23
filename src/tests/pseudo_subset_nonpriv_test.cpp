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

void TestCreateResource()
{
    const auto& entry = FindPseudo("syz_create_resource$binfmt");
    std::array<intptr_t, 6> args = {0x1234};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 1);
    assert(result.ret == 0x1234);
    assert(result.err == 0);
}

void TestOpenProcfs()
{
    const auto& entry = FindPseudo("syz_open_procfs");
    char path[] = "stat";
    std::array<intptr_t, 6> args = {0, reinterpret_cast<intptr_t>(path)};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 2);
    if (result.ret >= 0) {
        assert(result.err == 0);
        close(static_cast<int>(result.ret));
    }
}

void TestBtfIdByName()
{
    // [PR-A3] syz_btf_id_by_name$bpf_lsm is now kNative — handler reads
    // /sys/kernel/btf/vmlinux and scans for the requested name. Behavior
    // depends on host:
    //   - BTF kernel + name present → ret > 0 (BTF type id), err == 0
    //   - BTF kernel + name missing → ret == -1, err == 0
    //   - No BTF kernel              → ret == -1, err == 0 (graceful)
    // Pre-PR-A3 expected `ret == -1, err == ENOSYS` (kStub fallthrough);
    // that contract is gone — handler never returns ENOSYS now.
    const auto& entry = FindPseudo("syz_btf_id_by_name$bpf_lsm");
    char name[] = "task_struct";
    std::array<intptr_t, 6> args = {reinterpret_cast<intptr_t>(name)};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 1);
    assert(result.err == 0);  // never ENOSYS post-PR-A3
    // ret is either BTF type id (>= 1) on success or -1 on missing/no-BTF
    assert(result.ret == -1 || result.ret >= 1);
}

} // namespace

int main()
{
    TestCreateResource();
    TestOpenProcfs();
    TestBtfIdByName();
    return 0;
}
