// [machine-check C4.2] unit test for the probe-program builder: one default-arg
// call per syscall, order preserved, null metas skipped, encodes to a non-empty
// exec-wire payload. Uses the real linux/amd64 Target. (Live submit/drain +
// ENOSYS interpretation are integration-tested with the trial-exec runner.)

#include "refuzz/control/support/machine_check/probe_program.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace mc  = ::refuzz::control::support::machine_check;
namespace syz = ::refuzz::program::syz;

} // namespace

int main() {
    const auto& t = syz::Target::linux_amd64();

    // Collect a handful of real, generatable syscalls (some with args, to
    // exercise default_arg across types). No name assumptions.
    std::vector<const syz::SyscallMeta*> calls;
    for (const auto& sc : t.syscalls()) {
        if (calls.size() >= 5) break;
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        calls.push_back(sc.get());
    }
    CHECK(calls.size() == 5);

    syz::Prog prog = mc::BuildProbeProgram(t, calls);
    CHECK(prog.calls().size() == calls.size());
    for (std::size_t i = 0; i < calls.size(); ++i) {
        CHECK(prog.calls()[i]->meta() == calls[i]);            // order preserved
        CHECK(prog.calls()[i]->args().size() == calls[i]->args().size());
    }

    auto payload = mc::EncodeProbeProgram(prog);
    CHECK(payload.has_value());
    CHECK(!payload->empty());

    // null metas are skipped, not encoded as empty calls.
    std::vector<const syz::SyscallMeta*> with_null = {calls[0], nullptr, calls[1]};
    syz::Prog p2 = mc::BuildProbeProgram(t, with_null);
    CHECK(p2.calls().size() == 2);
    auto payload2 = mc::EncodeProbeProgram(p2);
    CHECK(payload2.has_value());

    // empty list → empty program, still encodes.
    syz::Prog p3 = mc::BuildProbeProgram(t, {});
    CHECK(p3.calls().empty());

    std::fprintf(stdout, "probe_program_test ALL PASS (payload=%zu bytes)\n",
                 payload->size());
    return 0;
}
