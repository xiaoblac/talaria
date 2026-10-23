#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif

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

bool IsLookupFailure(int err)
{
    return err == ENOENT || err == EOPNOTSUPP || err == EPROTONOSUPPORT ||
           err == EINVAL || err == EPERM || err == EACCES || err == ENOBUFS ||
           err == EBADMSG;
}

bool IsSocketFailure(int err)
{
    return err == ENOTSOCK || err == EBADF || err == EINVAL || err == ENODEV ||
           err == EOPNOTSUPP || err == ENOTCONN || err == EPERM;
}

} // namespace

int main()
{
    const auto& entry = FindPseudo("syz_genetlink_get_family_id$nbd");

    char family[] = "nbd";
    std::array<intptr_t, 6> args = {reinterpret_cast<intptr_t>(family), -1};
    const auto result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 2);
    if (result.ret >= 0) {
        assert(result.err == 0);
    } else {
        assert(IsLookupFailure(result.err));
        assert(result.err != ENOSYS);
    }

    char missing[] = "refuzz_missing_family";
    args = {reinterpret_cast<intptr_t>(missing), -1};
    const auto missing_result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 2);
    assert(missing_result.ret == -1);
    assert(IsLookupFailure(missing_result.err));
    assert(missing_result.err != ENOSYS);

    char nlctrl[] = "nlctrl";
    args = {reinterpret_cast<intptr_t>(nlctrl), -1};
    const auto nlctrl_result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 2);
    if (nlctrl_result.ret >= 0) {
        assert(nlctrl_result.err == 0);
    } else {
        assert(IsLookupFailure(nlctrl_result.err));
        assert(nlctrl_result.err != ENOSYS);
    }

    const int invalid_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(invalid_fd >= 0);
    args = {reinterpret_cast<intptr_t>(nlctrl), invalid_fd};
    const auto invalid_socket = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), entry.nr, args.data(), 2);
    close(invalid_fd);
    assert(invalid_socket.ret == -1);
    assert(IsSocketFailure(invalid_socket.err));
    assert(invalid_socket.err != ENOSYS);

    const auto& init = FindPseudo("syz_init_net_socket$nl_generic");
    std::array<intptr_t, 6> sock_args = {AF_NETLINK, SOCK_RAW, NETLINK_GENERIC};
    const auto sock_result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), init.nr, sock_args.data(), 3);
    if (sock_result.ret >= 0) {
        assert(sock_result.err == 0);
        close(static_cast<int>(sock_result.ret));
    } else {
        assert(IsSocketFailure(sock_result.err) || IsLookupFailure(sock_result.err));
        assert(sock_result.err != ENOSYS);
    }

    // [PR-B2 follow-up 2026-05-06] syz_init_net_socket$bt_hci was kStub
    // pre-PR-B2; it's now kNative — handler attempts socket(AF_BLUETOOTH, ...)
    // in init netns (or current ns when init_netns_fd unset). Without the
    // bluetooth kernel module loaded, socket() fails — assert handler
    // returns -1 with a non-ENOSYS errno.
    const auto& bt_hci = FindPseudo("syz_init_net_socket$bt_hci");
    std::array<intptr_t, 6> bt_args = {AF_BLUETOOTH, SOCK_RAW, /*HCI*/ 1};
    const auto bt_result = refuzz::worker::DispatchPseudo(
        refuzz::worker::DefaultPseudoContext(), bt_hci.nr, bt_args.data(), 3);
    // Either succeeds (BT module loaded) or fails with non-ENOSYS errno.
    if (bt_result.ret >= 0) {
        assert(bt_result.err == 0);
        close(static_cast<int>(bt_result.ret));
    } else {
        assert(bt_result.err != ENOSYS);
    }
    return 0;
}
