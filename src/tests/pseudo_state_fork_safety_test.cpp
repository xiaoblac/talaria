// Regression test for the pseudo-state pthread_atfork handlers.
//
// The prepare callbacks deliberately hold every state-map mutex across fork.
// The child must be able to enter all three GetOrCreate* functions immediately;
// a child handler that leaves any mutex locked will otherwise hang here.

#include "worker/backend/pseudo/kvm/kvm_state.hpp"
#include "worker/backend/pseudo/mount/mount_state.hpp"
#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/usb/usb_state.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

bool WaitForChild(pid_t pid, int* status)
{
    for (int attempt = 0; attempt < 200; ++attempt) {
        const pid_t result = ::waitpid(pid, status, WNOHANG);
        if (result == pid) {
            return true;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
        ::usleep(10'000);
    }
    (void)::kill(pid, SIGKILL);
    while (::waitpid(pid, status, 0) < 0 && errno == EINTR) {
    }
    return false;
}

} // namespace

int main()
{
    refuzz::worker::PseudoContext context;
    (void)refuzz::worker::pseudo::GetOrCreateMountState(context);
    (void)refuzz::worker::pseudo::GetOrCreateKvmState(context);
    (void)refuzz::worker::pseudo::GetOrCreateUsbState(context);

    const pid_t child = ::fork();
    if (child < 0) {
        std::perror("fork");
        return 1;
    }
    if (child == 0) {
        // Each call takes its corresponding map mutex. The atfork child
        // callbacks must have released the prepare locks before this point.
        refuzz::worker::PseudoContext child_context;
        (void)refuzz::worker::pseudo::GetOrCreateMountState(child_context);
        (void)refuzz::worker::pseudo::GetOrCreateKvmState(child_context);
        (void)refuzz::worker::pseudo::GetOrCreateUsbState(child_context);
        _exit(0);
    }

    int status = 0;
    if (!WaitForChild(child, &status) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        std::fprintf(stderr,
                     "FAIL: child could not use pseudo state after fork "
                     "status=0x%x\n",
                     status);
        return 1;
    }
    std::printf("PASS: pseudo state mutexes are fork-safe\n");
    return 0;
}
