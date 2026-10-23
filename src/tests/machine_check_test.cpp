// [machine-check C4.6] unit test for the machine-check phase driver.
//
//   * EnvFeaturesToSupportEnv — wire POD → semantic SupportEnv.
//   * RunMachineCheck         — the full standard-data-plane flow: it pushes
//     probe HostFuzzTasks onto an InMemoryTaskQueue and drains ChannelEvents off
//     an InMemoryEventQueue. A FAKE Executor thread stands in for the real
//     channeldispatcher::Executor: it pops each task, reads the typed probe Prog,
//     synthesizes a Completion whose output carries per-call SyzExecResult errnos
//     (ENOSYS for one chosen syscall), and pushes it back. No VM/channel.
//
// Verifies the driver wires C4.2b (build/decode) + C4.3 (resolve) end-to-end:
// the ENOSYS syscall is dropped with reason "ENOSYS", the others survive, and the
// disabled report uses the canonical syz::DisabledCall record.

#include "refuzz/control/support/machine_check/machine_check.hpp"

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/task_queue.hpp"
#include "worker/backend/syz_exec_runner.hpp"  // SyzExecResult, kCallFlag*

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
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
namespace cs  = ::refuzz::control::support;
namespace cc  = ::refuzz::core::channel_contract;
namespace syz = ::refuzz::program::syz;

// Enable-eligible: a real syscall checkMode would keep in the enable set.
bool enable_eligible(const syz::SyscallMeta& sc) {
    return !sc.is_pseudo() && !sc.attrs().disabled && !sc.attrs().no_generate &&
           !sc.attrs().automatic && !sc.attrs().snapshot;
}

// Real, generatable, NON-socket syscalls with no input resources AND a UNIQUE
// base (no enable-eligible $variant siblings) — so enabling one by name does
// NOT expand to siblings (syz enables `name` + `name$*`), the probe count stays
// exact, and the only thing that can disable it is the DEFAULT trial-ENOSYS path
// (not socket-family / device-open / transitive).
std::vector<const syz::SyscallMeta*> find_real_no_input(const syz::Target& t, int n) {
    std::vector<const syz::SyscallMeta*> out;
    for (const auto& sc : t.syscalls()) {
        if (static_cast<int>(out.size()) >= n) break;
        if (!sc || !enable_eligible(*sc)) continue;
        const std::string& base = sc->call_name();
        if (base == "socket" || base == "socketpair") continue;
        if (!sc->input_resources().empty()) continue;
        // Reject if any OTHER enable-eligible syscall shares this base (enabling
        // `base` would pull the sibling in, inflating the probe count).
        std::size_t eligible_siblings = 0;
        for (const auto& other : t.syscalls()) {
            if (other && enable_eligible(*other) && other->call_name() == base) {
                ++eligible_siblings;
            }
        }
        if (eligible_siblings != 1) continue;
        out.push_back(sc.get());
    }
    return out;
}

void test_env_features_to_support_env() {
    ::EnvFeatures ef;
    std::memset(&ef, 0, sizeof(ef));
    ef.version = ENV_FEATURES_VERSION;
    env_features_append_filesystem(&ef, "ext4");
    env_features_append_filesystem(&ef, "btrfs");
    ef.flags |= ENV_FEAT_RAW_GADGET;          // has raw-gadget, no kvm
    ef.kernel_major = 6; ef.kernel_minor = 8;
    const char* lsm = "capability,apparmor";
    env_features_set_lsm(&ef, lsm, std::strlen(lsm));

    cs::SupportEnv env = mc::EnvFeaturesToSupportEnv(ef, /*sandbox_is_none=*/true);
    CHECK(env.sandbox_is_none);
    CHECK(env.probed);
    CHECK(env.filesystems.size() == 2);
    CHECK(env.filesystems[0] == "ext4" && env.filesystems[1] == "btrfs");
    CHECK(env.has_raw_gadget && !env.has_kvm);
    CHECK(env.kernel_major == 6 && env.kernel_minor == 8);
    CHECK(env.lsm_present);
    CHECK(env.lsms == "capability,apparmor");
}

void test_run_machine_check() {
    const auto& t = syz::Target::linux_amd64();
    auto calls = find_real_no_input(t, 3);
    CHECK(calls.size() == 3);
    const syz::SyscallMeta* a = calls[0];
    const syz::SyscallMeta* b = calls[1];
    const syz::SyscallMeta* k = calls[2];   // the one we'll mark ENOSYS
    const std::string enosys_name = k->name();

    ::refuzz::queue::InMemoryTaskQueue  task_queue;
    ::refuzz::queue::InMemoryEventQueue event_queue;

    // Fake Executor: pop probe tasks, synthesize per-call errno completions.
    std::atomic<bool> stop{false};
    std::thread fake([&]() {
        while (!stop.load()) {
            auto task = task_queue.Pop(std::chrono::milliseconds(50));
            if (!task.has_value()) continue;
            auto prog = task->artifact.template As<syz::Prog>();
            std::vector<refuzz::worker::SyzExecResult> recs;
            if (prog != nullptr) {
                for (const auto& c : prog->calls()) {
                    refuzz::worker::SyzExecResult r;
                    // Finished call (Executed|Finished) — the decode trusts the
                    // errno only when Finished is set.
                    r.flags = refuzz::worker::kCallFlagExecuted |
                              refuzz::worker::kCallFlagFinished;
                    r.err = (c->meta() != nullptr && c->meta()->name() == enosys_name)
                                ? 38   // ENOSYS
                                : 0;
                    recs.push_back(r);
                }
            }
            std::vector<std::uint8_t> output(
                recs.size() * sizeof(refuzz::worker::SyzExecResult));
            if (!recs.empty()) {
                std::memcpy(output.data(), recs.data(), output.size());
            }
            cc::Completion comp;
            comp.ctx.executor_id = task->executor_id;
            comp.output          = std::move(output);
            cc::ChannelEvent ev;
            ev.kind    = cc::ChannelEvent::Kind::kCompletion;
            ev.payload = std::move(comp);
            event_queue.Push(std::move(ev));
        }
    });

    mc::MachineCheckConfig cfg;
    cfg.enable       = {a->name(), b->name(), k->name()};
    cfg.env.sandbox_is_none = true;
    // No drain timeout — RunMachineCheck drains until all batches resolve; the
    // fake Executor answers every batch, so it terminates.

    mc::MachineCheckResult res = mc::RunMachineCheck(t, cfg, task_queue, event_queue);

    stop.store(true);
    fake.join();

    CHECK(res.enabled.ok);
    CHECK(res.probe_calls == 3);
    CHECK(res.probe_programs == 3);          // 1 call per program (kProbeMaxCalls=1)
    CHECK(res.programs_returned == 3);
    CHECK(res.enabled.mask[a->id()] == 1);   // errno 0 → kept
    CHECK(res.enabled.mask[b->id()] == 1);
    CHECK(res.enabled.mask[k->id()] == 0);   // ENOSYS → dropped

    bool found = false;
    for (const auto& d : res.disabled) {
        if (d.call == k) {
            found = true;
            CHECK(d.reason == "ENOSYS");
        }
    }
    CHECK(found);
}

} // namespace

int main() {
    std::fprintf(stdout, "Running machine_check_test...\n");
    test_env_features_to_support_env();
    std::fprintf(stderr, "OK   test_env_features_to_support_env\n");
    test_run_machine_check();
    std::fprintf(stderr, "OK   test_run_machine_check\n");
    std::fprintf(stdout, "machine_check_test ALL PASS\n");
    return 0;
}
