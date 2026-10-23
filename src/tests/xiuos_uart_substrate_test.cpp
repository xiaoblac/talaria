// xiuos_uart_substrate_test.cpp
//
// Phase 2 §B v1 review fix — XiuosUartSubstrate::IsVMAlive must not be
// fooled by zombie children. The original impl used kill(pid, 0) which
// returns success on zombies; crash/hang bucketing + restart logic needs
// the negative result here. The fix switches IsVMAlive to
// waitpid(WNOHANG) + on-the-spot reap.
//
// Strategy: use /bin/true as the "qemu_bin" so the child exec'd by
// SpawnQemu exits immediately (it ignores QEMU's CLI). The parent's
// qemu_pid_ is recorded; the child becomes a zombie until IsVMAlive reaps
// it. With the fix, IsVMAlive returns false promptly after the child
// exits.

#include "refuzz/channel/runtime/xiuos_uart_substrate.hpp"

#include <sys/stat.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

namespace runtime = refuzz::channel::runtime;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

bool FileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

// /bin/true (or /usr/bin/true on some systems) exists on all Linux hosts
// we care about. /etc/passwd is used as a placeholder for elf_path so the
// substrate's FileExists check passes — the substrate doesn't otherwise
// validate the ELF (QEMU would, but here we're not running QEMU).
runtime::XiuosUartSubstrate::Config MakeFastExitConfig() {
    runtime::XiuosUartSubstrate::Config cfg;
    cfg.qemu_bin = FileExists("/bin/true") ? "/bin/true" : "/usr/bin/true";
    cfg.elf_path = "/etc/passwd";  // any existing file
    cfg.serial_host = "127.0.0.1";
    cfg.serial_port = 39001;
    cfg.shutdown_grace = std::chrono::milliseconds(200);
    return cfg;
}

int TestIsVMAliveDetectsExitedChild() {
    if (!FileExists("/bin/true") && !FileExists("/usr/bin/true")) {
        std::fprintf(stdout, "SKIP: /bin/true not found\n");
        return 0;
    }

    runtime::XiuosUartSubstrate substrate(MakeFastExitConfig());

    // Pre-StartVM: no PID recorded, IsVMAlive is unambiguous false.
    CHECK(!substrate.IsVMAlive(0));

    auto r = substrate.StartVM(0);
    CHECK(r.ok());
    CHECK(substrate.qemu_pid() > 0);

    // Wait long enough for /bin/true to exec + exit. Generous bound: 1s.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    bool reaped = false;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!substrate.IsVMAlive(0)) {
            reaped = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(reaped);

    // After reap, qemu_pid_ should be cleared so subsequent calls are
    // unambiguous (the const method writes -1 through the mutable atomic).
    CHECK(substrate.qemu_pid() == -1);
    CHECK(!substrate.IsVMAlive(0));
    return 0;
}

// Calling IsVMAlive repeatedly after the child has exited must not block,
// not return a stale "alive", and not race on PID reuse.
int TestIsVMAliveIdempotentAfterReap() {
    if (!FileExists("/bin/true") && !FileExists("/usr/bin/true")) {
        std::fprintf(stdout, "SKIP: /bin/true not found\n");
        return 0;
    }

    runtime::XiuosUartSubstrate substrate(MakeFastExitConfig());
    CHECK(substrate.StartVM(0).ok());
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // First call: reaps zombie, returns false.
    CHECK(!substrate.IsVMAlive(0));
    // Repeat: should still be false, no waitpid hang.
    for (int i = 0; i < 8; ++i) {
        CHECK(!substrate.IsVMAlive(0));
    }
    CHECK(substrate.qemu_pid() == -1);
    return 0;
}

// StopVM (and destructor) must be a no-op after the substrate already
// reaped the child via IsVMAlive (i.e. qemu_pid_ already cleared).
int TestStopVMAfterReapIsNoOp() {
    if (!FileExists("/bin/true") && !FileExists("/usr/bin/true")) {
        std::fprintf(stdout, "SKIP: /bin/true not found\n");
        return 0;
    }

    runtime::XiuosUartSubstrate substrate(MakeFastExitConfig());
    CHECK(substrate.StartVM(0).ok());
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK(!substrate.IsVMAlive(0));     // reaps + clears
    CHECK(substrate.qemu_pid() == -1);

    // No throws / hangs.
    substrate.StopVM(0);
    auto r = substrate.Close();
    CHECK(r.ok());
    return 0;
}

// RebootVM should be functional even after a previous reap (Close + Start
// cycle).
int TestRebootVMAfterReapStartsNewChild() {
    if (!FileExists("/bin/true") && !FileExists("/usr/bin/true")) {
        std::fprintf(stdout, "SKIP: /bin/true not found\n");
        return 0;
    }

    runtime::XiuosUartSubstrate substrate(MakeFastExitConfig());
    CHECK(substrate.StartVM(0).ok());
    const auto first_pid = substrate.qemu_pid();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK(!substrate.IsVMAlive(0));

    auto r = substrate.RebootVM(0);
    CHECK(r.ok());
    const auto second_pid = substrate.qemu_pid();
    CHECK(second_pid > 0);
    CHECK(second_pid != first_pid);  // different process
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_substrate_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestIsVMAliveDetectsExitedChild,    "IsVMAliveDetectsExitedChild");
    exec(TestIsVMAliveIdempotentAfterReap,   "IsVMAliveIdempotentAfterReap");
    exec(TestStopVMAfterReapIsNoOp,          "StopVMAfterReapIsNoOp");
    exec(TestRebootVMAfterReapStartsNewChild,"RebootVMAfterReapStartsNewChild");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
