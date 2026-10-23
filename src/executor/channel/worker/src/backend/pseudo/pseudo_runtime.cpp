#include "worker/backend/pseudo/pseudo_runtime.hpp"

#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/coverage/kcov_collector.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

namespace refuzz::worker {
namespace {

using refuzz::fuzzer::syz::ResolvedCallKind;
namespace fs = std::filesystem;

constexpr int kSyzkallerInitNetNsFd = 201;

PseudoResult Error(int err, const char* reason = nullptr)
{
    return PseudoResult{-1, err, reason};
}

} // namespace

PseudoRuntimeContext::PseudoRuntimeContext(
    const refuzz::fuzzer::syz::SyzTargetTables* target_tables,
    uint32_t slot_id)
{
    if (target_tables == nullptr) {
        target_tables = &refuzz::fuzzer::syz::kDefaultSyzTarget;
    }
    target = target_tables;
    table = &target_tables->pseudos;
    proc_slot_id = slot_id;
    if (::fcntl(kSyzkallerInitNetNsFd, F_GETFD) >= 0) {
        init_netns_fd_for_pseudo_ = kSyzkallerInitNetNsFd;
    }
}

PseudoRuntimeContext::~PseudoRuntimeContext()
{
    Cleanup();
}

// [v1 RegisterCleanup / RegisterOwnedFd / Cleanup non-virtual non-const, no named regions — ROLLBACK: uncomment below and remove v2]
// void PseudoRuntimeContext::RegisterCleanup(std::function<void()> cleanup)
// {
//     cleanup_callbacks.push_back(std::move(cleanup));
// }
//
// void PseudoRuntimeContext::RegisterOwnedFd(int fd)
// {
//     if (fd >= 0) {
//         owned_fds.push_back(fd);
//     }
// }
//
// void PseudoRuntimeContext::Cleanup()
// {
//     while (!cleanup_callbacks.empty()) {
//         auto cleanup = std::move(cleanup_callbacks.back());
//         cleanup_callbacks.pop_back();
//         cleanup();
//     }
//     while (!owned_fds.empty()) {
//         const int fd = owned_fds.back();
//         owned_fds.pop_back();
//         close(fd);
//     }
// }

// [v2 lifecycle hooks 升 const override + 加 named_regions munmap (PR-A1 §5.0) — 当前版本]
void PseudoRuntimeContext::RegisterCleanup(std::function<void()> cleanup) const
{
    cleanup_callbacks.push_back(std::move(cleanup));
}

void PseudoRuntimeContext::RegisterOwnedFd(int fd) const
{
    if (fd >= 0) {
        owned_fds.push_back(fd);
    }
}

void PseudoRuntimeContext::RegisterNamedRegion(uint64_t key,
                                               void* base,
                                               std::size_t len) const
{
    if (base == nullptr || base == MAP_FAILED || len == 0) {
        return;
    }
    named_regions[key] = NamedRegion{base, len};
}

void* PseudoRuntimeContext::LookupNamedRegion(uint64_t key,
                                              std::size_t* len_out) const
{
    auto it = named_regions.find(key);
    if (it == named_regions.end()) {
        return nullptr;
    }
    if (len_out != nullptr) {
        *len_out = it->second.len;
    }
    return it->second.base;
}

// [PR-C0 §5.1] Tier 2 net-stack lazy infrastructure.

int PseudoRuntimeContext::tun_fd() const
{
    // -2 = not tried, -1 = tried-and-failed, >=0 = success
    if (tun_fd_cached_ != -2) {
        return tun_fd_cached_;
    }
    // [当前版本 sandbox-device-init D3] Prefer fd 200 if InitializeTun()
    // (worker/src/sandbox/device_init/tun.cpp) 已挂好 "syz_tun" device。
    // 这样 pseudo emit_ethernet 写包用的就是 init-time 设了 LOCAL_IPV4/
    // LOCAL_IPV6/REMOTE_MAC/neigh 的那个 iface,与 upstream byte-equal。
    // TUNGETIFF 确认 fd 200 是 tun 设备;不是就走 lazy 回退。
    static constexpr int kTunFd = 200;
    {
        struct ifreq ifr {};
        if (::ioctl(kTunFd, TUNGETIFF, &ifr) == 0) {
            tun_fd_cached_ = kTunFd;
            // 不 RegisterOwnedFd —— fd 200 由 sandbox device_init 拥有,
            // pseudo cleanup 不能 close 否则 loop child 下一次 program 看不到。
            return kTunFd;
        }
    }
    // Lazy fallback:initialize_tun 没跑(test harness、ApplyNone 没触发,
    // 或 CONFIG_TUN=n) → 自开一个,只做最小 TUNSETIFF,无 IPv6 sysctl /
    // address / neigh 设置。
    int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        tun_fd_cached_ = -1;
        return -1;
    }
    struct ifreq ifr {};
    static constexpr const char* kTunIface = "syz_tun0";
    std::strncpy(ifr.ifr_name, kTunIface, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ::close(fd);
        tun_fd_cached_ = -1;
        return -1;
    }
    tun_fd_cached_ = fd;
    RegisterOwnedFd(fd);  // auto-close at Cleanup()
    return fd;
}

int PseudoRuntimeContext::init_net_socket(int domain, int type, int protocol) const
{
    // SandboxCommon-supplied init-netns fd (syzkaller fixed fd 201), or a
    // test override. If unset, fall back to plain socket() in current ns
    // (degraded — mirrors upstream's no SYZ_NET_INJECTION fallback at
    // common_linux.h:2561).
    if (init_netns_fd_for_pseudo_ < 0) {
        errno = 0;
        return ::socket(domain, type | SOCK_CLOEXEC, protocol);
    }

    // [当前版本 upstream-parity: per-call open/close of /proc/self/ns/net]
    // Upstream syz_init_net_socket (common_linux.h) opens the worker netns
    // fresh on every call and close()s it before returning. The old impl
    // cached that fd (opened once, RegisterOwnedFd, reused) — so it never did
    // the per-call open/close, missing the fs/inode evict + fs/file_table +
    // fs/open path syz exercises when the netns fd is closed (162 syz_only PC
    // on syz_init_net_socket$nl_generic). Mirror upstream's
    // open → setns(init) → socket → setns(back) → close sequence exactly.
    int netns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (netns < 0) {
        return -1;
    }
    if (::setns(init_netns_fd_for_pseudo_, 0) < 0) {
        ::close(netns);
        return -1;
    }
    errno = 0;
    int sock = ::socket(domain, type | SOCK_CLOEXEC, protocol);
    int saved_err = errno;
    if (::setns(netns, 0) < 0) {
        // [B4 review fix 2026-05-06] Worker is now stuck in init-netns.
        // ALL subsequent worker syscalls (next pseudo dispatch, real
        // syscalls in the same program, Cleanup()) operate in the wrong
        // namespace → silent state corruption. Mirror upstream
        // `executor/common_linux.h:2504-2508` exitf("setns(netns) failed")
        // — abort rather than continue with corrupted state.
        if (sock >= 0) {
            ::close(sock);
        }
        ::close(netns);
        std::abort();
    }
    ::close(netns);
    if (sock < 0) {
        errno = saved_err;
        return -1;
    }
    return sock;
}

int PseudoRuntimeContext::vhci_fd() const
{
    // [当前版本 use-init-vhci-fd — 2026-05-22]
    // 上游 syz_emit_vhci (common_linux.h:2929) 用 global vhci_fd —— 即
    // initialize_vhci 做完 vendor_pkt + HCIDEVUP + event_thread 之后保存的
    // dup2 fd (kVhciFd=202)。reFuzz InitializeVhci 也 dup2 到 fd 202;
    // 这里直接复用,跟 worker init 的 HCI state 共享。
    //
    // 之前实现每次 open 新 /dev/vhci → 新 fd 没经过 vendor_pkt + reset 序列 →
    // 写时 kernel 返 ENODEV (vhci_fd context 在内核里跟 hci_dev 关联,新 fd
    // 没绑定 hci0/hci1)。5 个 syz_emit_vhci mismatch (syz=0, ref=19) 的根因。
    if (vhci_fd_cached_ != -2) {
        return vhci_fd_cached_;
    }
    constexpr int kVhciFd = 202;  // 跟 vhci.cpp:105 同步
    if (::fcntl(kVhciFd, F_GETFD) >= 0) {
        vhci_fd_cached_ = kVhciFd;
        return kVhciFd;
    }
    // worker init 没 setup vhci(CONFIG_BT 缺 / open 失败),fallback open。
    // 这条路径写时还是会 ENODEV,但至少 fd 是活的,跟 upstream `vhci_fd<0`
    // 直接返 -1 行为一致。
    int fd = ::open("/dev/vhci", O_RDWR);
    if (fd < 0) {
        vhci_fd_cached_ = -1;
        return -1;
    }
    vhci_fd_cached_ = fd;
    RegisterOwnedFd(fd);
    return fd;
}

void PseudoRuntimeContext::run_pre_program_setup() const
{
    if (pre_program_setup_done_) {
        return;
    }
    pre_program_setup_done_ = true;
    // Tier 2 families currently lazy-init their own resources at first
    // pseudo dispatch (tun_fd / init_net_socket / vhci /dev/vhci-fd).
    // No global pre-program setup is required. This hook is the
    // dispatcher-side anchor that future Tier 3 PRs (e.g. mount-image
    // namespace setup) can use without changing the dispatcher contract.
}

void PseudoRuntimeContext::set_init_netns_fd_for_pseudo(int fd)
{
    init_netns_fd_for_pseudo_ = fd;
}

void PseudoRuntimeContext::set_kcov_collector(KcovCollector* collector)
{
    kcov_collector_ = collector;
}

void PseudoRuntimeContext::KcovCursorReset() const
{
    // Mirror upstream `cover_reset(0)` (common_linux.h:3064, :3171). The
    // collector's ResetForCall has all the right guards (enabled / PC mode /
    // session-active) — if any guard fails it's a clean no-op. We don't
    // distinguish "mid-call" from "start-of-call" semantically because both
    // reduce to `area_[0] = 0; per_call_cursor_ = 0` which is idempotent at
    // start-of-call (per_call_cursor_ was already 0).
    if (kcov_collector_ != nullptr) {
        (void)kcov_collector_->ResetForCall();
    }
}

uint64_t PseudoRuntimeContext::DiagnosticExecutorId() const
{
    return diagnostic_executor_id_;
}

void PseudoRuntimeContext::RecordLoopDeviceUsed(uint32_t proc_slot_id) const
{
    // proc_slot_id >= 32 → bit-shift would be UB; promote to UINT32_MAX
    // sentinel because the diagnostic ABI cannot represent this fixed slot.
    if (proc_slot_id >= 32u) {
        loop_devices_used_mask_ = UINT32_MAX;
        if (loop_devices_used_mask_cursor_ != nullptr) {
            __atomic_store_n(loop_devices_used_mask_cursor_, UINT32_MAX,
                             __ATOMIC_RELEASE);
        }
        return;
    }
    // Once we've fallen back to UINT32_MAX (unknown), keep it sticky — a
    // subsequent in-range record shouldn't shrink the sweep set.
    if (loop_devices_used_mask_ == UINT32_MAX) {
        return;
    }
    const uint32_t bit = 1u << proc_slot_id;
    loop_devices_used_mask_ |= bit;
    if (loop_devices_used_mask_cursor_ != nullptr) {
        __atomic_fetch_or(loop_devices_used_mask_cursor_, bit, __ATOMIC_RELEASE);
    }
}

void PseudoRuntimeContext::set_diagnostic_executor_id(uint64_t executor_id)
{
    diagnostic_executor_id_ = executor_id;
}

void PseudoRuntimeContext::set_loop_devices_used_mask_cursor(uint32_t* cursor)
{
    loop_devices_used_mask_cursor_ = cursor;
}

void PseudoRuntimeContext::Cleanup()
{
    // Order: callbacks (in reverse insertion) → mmap regions → owned fds.
    // Callbacks run first so handlers that need to read/write a region
    // before munmap can do so via cleanup callback. Regions munmap before
    // fds close so a region's backing fd (e.g. io_uring) hasn't been
    // freed yet — though munmap doesn't actually depend on fd lifetime.
    while (!cleanup_callbacks.empty()) {
        auto cleanup = std::move(cleanup_callbacks.back());
        cleanup_callbacks.pop_back();
        cleanup();
    }
    for (auto& [key, region] : named_regions) {
        if (region.base != nullptr && region.len > 0) {
            munmap(region.base, region.len);
        }
    }
    named_regions.clear();
    while (!owned_fds.empty()) {
        const int fd = owned_fds.back();
        owned_fds.pop_back();
        close(fd);
    }
}

PseudoResult ExecuteNrOrPseudo(PseudoRuntimeContext& ctx,
                               uint64_t nr,
                               const intptr_t* args,
                               uint32_t argc)
{
    // [PR-C0] Idempotent pre-program setup hook (no-op body for Tier 2
    // since families lazy-init individually). Called here so the
    // architectural anchor exists for future Tier 3 PRs that need it.
    ctx.run_pre_program_setup();

    const auto* target = ctx.target;
    if (target == nullptr) {
        target = &refuzz::fuzzer::syz::kDefaultSyzTarget;
    }

    const auto resolved = refuzz::fuzzer::syz::ResolveSyzCallByNr(*target, nr);
    if (resolved.kind == ResolvedCallKind::kPseudo) {
        if (resolved.pseudo != nullptr &&
            resolved.pseudo->arg_count > refuzz::fuzzer::syz::kCompatFlatMaxArgs &&
            argc <= refuzz::fuzzer::syz::kCompatFlatMaxArgs) {
            return Error(E2BIG, "over_width_arg");
        }
        return DispatchPseudo(ctx, nr, args, argc);
    }

    if (resolved.kind == ResolvedCallKind::kMissing && nr >= target->pseudo_nr_base) {
        return Error(ENOSYS);
    }

    if (argc > refuzz::fuzzer::syz::kCompatFlatMaxArgs) {
        return Error(E2BIG, "over_width_arg");
    }

    intptr_t padded[refuzz::fuzzer::syz::kCompatFlatMaxArgs] = {};
    for (uint32_t i = 0; i < argc; ++i) {
        padded[i] = args == nullptr ? 0 : args[i];
    }

    errno = 0;
    const long ret = syscall(static_cast<long>(nr),
                             static_cast<long>(padded[0]),
                             static_cast<long>(padded[1]),
                             static_cast<long>(padded[2]),
                             static_cast<long>(padded[3]),
                             static_cast<long>(padded[4]),
                             static_cast<long>(padded[5]));
    return PseudoResult{static_cast<intptr_t>(ret), errno, nullptr};
}

bool WritePseudoOwnershipMarker(const std::string& path,
                                const std::string& run_id,
                                int pid)
{
    if (path.empty() || run_id.empty() || pid <= 0) {
        return false;
    }
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec) {
        return false;
    }
    const fs::path marker = fs::path(path) / ".refuzz-pseudo-owner";
    std::ofstream out(marker, std::ios::trunc);
    if (!out) {
        return false;
    }
    out << "run_id=" << run_id << "\n";
    out << "pid=" << pid << "\n";
    return static_cast<bool>(out);
}

uint32_t ReclaimStalePseudoRuntimeRoots(const std::string& root,
                                        const std::string& current_run_id)
{
    if (root.empty() || current_run_id.empty()) {
        return 0;
    }
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) {
        return 0;
    }

    uint32_t reclaimed = 0;
    for (const fs::directory_entry& entry : fs::directory_iterator(root, ec)) {
        if (ec || !entry.is_directory()) {
            continue;
        }
        const fs::path marker = entry.path() / ".refuzz-pseudo-owner";
        std::ifstream in(marker);
        if (!in) {
            continue;
        }
        std::string line;
        std::string run_id;
        while (std::getline(in, line)) {
            constexpr const char* kPrefix = "run_id=";
            if (line.rfind(kPrefix, 0) == 0) {
                run_id = line.substr(std::strlen(kPrefix));
                break;
            }
        }
        if (run_id.empty() || run_id == current_run_id) {
            continue;
        }
        fs::remove_all(entry.path(), ec);
        if (!ec) {
            reclaimed++;
        }
    }
    return reclaimed;
}

} // namespace refuzz::worker
