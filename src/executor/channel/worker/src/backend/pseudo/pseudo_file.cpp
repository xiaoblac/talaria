#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {
namespace {

bool HasBaseName(const char* name, const char* base)
{
    if (name == nullptr) {
        return false;
    }
    const size_t n = std::strlen(base);
    return std::strncmp(name, base, n) == 0 &&
           (name[n] == '\0' || name[n] == '$');
}

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

} // namespace

PseudoResult DispatchFilePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc)
{
    (void)ctx;
    if (!HasBaseName(meta.name, "syz_open_procfs")) {
        return Error(ENOSYS);
    }
    if (args == nullptr || argc < 2 || args[1] == 0) {
        return Error(EINVAL);
    }

    // [silent-drift fix] upstream common_linux.h:2447-2463:
    //   pid == 0  → /proc/self/<rel>
    //   pid == -1 → /proc/thread-self/<rel>
    //   else      → /proc/self/task/<pid>/<rel>   (thread namespace, NOT global pid namespace)
    // Plus open(O_RDWR) → fallback open(O_RDONLY).
    //
    // The previous reFuzz `rel[0] == '/'` absolute-path branch is removed:
    // upstream has no such branch (charter `feedback_porting_keep_candidate_set_minimal.md`
    // — port semantics strictly).
    const long pid = static_cast<long>(args[0]);
    const char* rel = reinterpret_cast<const char*>(args[1]);
    char path[512] = {};
    if (pid == 0) {
        std::snprintf(path, sizeof(path), "/proc/self/%s", rel);
    } else if (pid == -1) {
        std::snprintf(path, sizeof(path), "/proc/thread-self/%s", rel);
    } else {
        std::snprintf(path, sizeof(path), "/proc/self/task/%ld/%s", pid, rel);
    }

    errno = 0;
    int fd = ::open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fd = ::open(path, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return Error(errno);
    }
    return PseudoResult{fd, 0};
}

} // namespace refuzz::worker::pseudo
