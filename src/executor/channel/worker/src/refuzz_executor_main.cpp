#include "worker/topology/ns_runner.hpp"

#include <csignal>
#include <cstring>

volatile sig_atomic_t g_running = 1;

namespace {

void HandleSignal(int)
{
    g_running = 0;
}

} // namespace

int main(int argc, char** argv)
{
    ::signal(SIGINT, HandleSignal);
    ::signal(SIGTERM, HandleSignal);
    ::signal(SIGPIPE, SIG_IGN);

    if (argc == 2 && std::strcmp(argv[1], "--role=ns-runner") == 0) {
        return refuzz::worker::topology::RunExecNsRunnerRole();
    }
    return 2;
}
