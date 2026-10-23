// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Linux/amd64 ICSourceTargetInfo
// singleton.
//
// Field values copied from upstream sys/targets/targets.go's
// Linux/AMD64 entry plus the OS-level `Linux` osCommon block.
// Drift detection lives in tools/csource_target_info_check
// (Go-side); CI surfaces upstream rebase that touches the values.
//
// make_data_mmap_prog ports sys/targets/common.go::MakePosixMmap
// for (target, exec=true, contain=true). Linux registers
// `target.MakeDataMmap = MakePosixMmap(target, true, true)` at
// sys/linux/init.go:49, which is what pkg/csource.Write actually
// invokes via prog.Target.DataMmapProg() — exec=true adds PROT_EXEC
// to the data-range mapping so reproducers that JIT into data pages
// continue to work.
//
// Schema-side primitives (Target::find_syscall, Target::find_const,
// page_size, num_pages) are read at call time; csource module owns
// the helper rather than extending program/syz/Target
// (target_ownership row 111).

#include "refuzz/crash/repro/csource/target_info.hpp"

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::crash::repro::csource {

namespace {

namespace syz = ::refuzz::program::syz;

// host_goos compile-time constant.
#if defined(__linux__)
constexpr std::string_view kHostGoos = "linux";
#elif defined(__APPLE__)
constexpr std::string_view kHostGoos = "darwin";
#elif defined(__FreeBSD__)
constexpr std::string_view kHostGoos = "freebsd";
#elif defined(__OpenBSD__)
constexpr std::string_view kHostGoos = "openbsd";
#elif defined(__NetBSD__)
constexpr std::string_view kHostGoos = "netbsd";
#elif defined(_WIN32)
constexpr std::string_view kHostGoos = "windows";
#else
constexpr std::string_view kHostGoos = "linux";
#endif

// Linux/amd64 cflags from sys/targets/targets.go's
// `Linux: { ... }` block (search "AMD64" + the OS-level CFlags).
// Drift detection is in tools/csource_target_info_check.
const std::vector<std::string>& cflags_linux_amd64() {
    static const std::vector<std::string> kFlags = {
        "-m64",
        "-O2",
        "-pthread",
        "-Wall",
        "-Werror",
        "-Wparentheses",
        "-Wunused-const-variable",
        "-Wframe-larger-than=16384",
        "-Wno-stringop-overflow",
        "-Wno-array-bounds",
        "-Wno-format-overflow",
        "-Wno-unused-but-set-variable",
        "-Wno-unused-command-line-argument",
        "-static-pie",
    };
    return kFlags;
}

const std::unordered_map<std::string, std::string>& empty_string_map() {
    static const std::unordered_map<std::string, std::string> kEmpty;
    return kEmpty;
}

// PseudoSyscallDeps for Linux — port of sys/targets/targets.go:506-513
// `Linux.PseudoSyscallDeps`. csource consumes this via
// generateSyscallDefines (csource.go:92-100) to add `__NR_*` defines
// for the native syscalls a syz_* pseudo invokes from its handler
// body.
const std::unordered_map<std::string, std::vector<std::string>>&
pseudo_syscall_deps_linux() {
    static const std::unordered_map<std::string, std::vector<std::string>>
        kDeps = {
            {"syz_read_part_table", {"memfd_create"}},
            {"syz_mount_image",     {"memfd_create"}},
            {"syz_io_uring_setup",  {"io_uring_setup"}},
            {"syz_clone3",          {"clone3", "exit"}},
            {"syz_clone",           {"clone", "exit"}},
            {"syz_pidfd_open",      {"pidfd_open"}},
        };
    return kDeps;
}

// Build a single mmap call. Mirror of MakePosixMmap's inner makeMmap
// closure (sys/targets/common.go:23-39).
std::unique_ptr<syz::Call> make_mmap_call(const syz::SyscallMeta& meta,
                                          uint64_t addr, uint64_t size,
                                          uint64_t prot, uint64_t flags,
                                          uint64_t invalid_fd) {
    const auto& fields = meta.args();
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);

    std::vector<std::unique_ptr<syz::Arg>> args;

    // arg 0: VmaPointer (addr, size)
    {
        auto a = std::make_unique<syz::PointerArg>();
        a->set_type(fields[0].type());
        a->set_dir(syz::Dir::kIn);
        a->set_address(addr);
        a->set_vma_size(size);
        args.push_back(std::move(a));
    }
    // arg 1: ConstArg = size
    {
        auto a = std::make_unique<syz::ConstArg>();
        a->set_type(fields[1].type());
        a->set_dir(syz::Dir::kIn);
        a->set_val(size);
        args.push_back(std::move(a));
    }
    // arg 2: ConstArg = prot
    {
        auto a = std::make_unique<syz::ConstArg>();
        a->set_type(fields[2].type());
        a->set_dir(syz::Dir::kIn);
        a->set_val(prot);
        args.push_back(std::move(a));
    }
    // arg 3: ConstArg = flags
    {
        auto a = std::make_unique<syz::ConstArg>();
        a->set_type(fields[3].type());
        a->set_dir(syz::Dir::kIn);
        a->set_val(flags);
        args.push_back(std::move(a));
    }
    // arg 4: ResultArg = invalid_fd (no producer)
    {
        auto a = std::make_unique<syz::ResultArg>();
        a->set_type(fields[4].type());
        a->set_dir(syz::Dir::kIn);
        a->set_val(invalid_fd);
        args.push_back(std::move(a));
    }
    // arg 5..: trailing offset (and optional padding for arches where
    // mmap takes 7 args). Linux/amd64 mmap takes 6 args, so this loop
    // emits exactly the offset arg as ConstArg=0.
    std::size_t i = args.size();
    if (fields.size() > 6) {
        auto pad = std::make_unique<syz::ConstArg>();
        pad->set_type(fields[i].type());
        pad->set_dir(syz::Dir::kIn);
        pad->set_val(0);
        args.push_back(std::move(pad));
        ++i;
    }
    {
        auto off = std::make_unique<syz::ConstArg>();
        off->set_type(fields[i].type());
        off->set_dir(syz::Dir::kIn);
        off->set_val(0);
        args.push_back(std::move(off));
    }

    call->set_args(std::move(args));
    return call;
}

class LinuxAmd64TargetInfo final : public ICSourceTargetInfo {
public:
    std::string_view cpp_path()   const override { return "cpp"; }
    std::string_view c_compiler() const override { return "gcc"; }

    std::span<const std::string> cflags() const override {
        const auto& v = cflags_linux_amd64();
        return std::span<const std::string>(v.data(), v.size());
    }

    CSourceTimeouts timeouts(int slowdown) const override {
        // Mirror upstream sys/targets/targets.go::Target.Timeouts
        // (lines 849-883):
        //   Scale   = min(slowdown, 3)         (capped at 3)
        //   Syscall = 50ms * slowdown          (linear in slowdown)
        //   Program = 5000ms * Scale           (capped via Scale)
        // Note: csource only uses program_ms, syscall_ms, and scale —
        // the upstream Timeouts struct also carries NoOutput /
        // VMRunningTime / NoOutputRunningTime which the reproducer
        // doesn't read. We expose only the consumed subset.
        const std::int64_t s = slowdown < 1 ? 1 : slowdown;
        const std::int64_t scale = s > 3 ? 3 : s;
        return CSourceTimeouts{
            .program_ms = 5'000 * scale,
            .syscall_ms = 50    * s,
            .scale      = scale,
        };
    }

    std::string_view syscall_prefix() const override { return "__NR_"; }

    const std::unordered_map<std::string, std::string>&
    syscall_trampolines() const override {
        return empty_string_map();
    }

    const std::unordered_map<std::string, std::vector<std::string>>&
    pseudo_syscall_deps() const override {
        return pseudo_syscall_deps_linux();
    }

    bool need_syscall_define(std::uint64_t nr) const override {
        // sys/targets/targets.go Linux/AMD64 NeedSyscallDefine: nr >= 313.
        return nr >= 313;
    }

    bool has_call_number(std::string_view call_name) const override {
        // Linux/amd64 has no Trampolines entries; syz_* pseudos have no
        // native NR. Mirror sys/targets.Target.HasCallNumber: return true
        // unless the call is a pseudo (name starts with "syz_").
        return !call_name.starts_with("syz_");
    }

    bool executor_uses_fork_server() const override { return true; }
    bool ptr_size_is_4()             const override { return false; }

    std::string_view goos()      const override { return "linux"; }
    std::string_view goarch()    const override { return "amd64"; }
    std::string_view host_goos() const override { return kHostGoos; }

    std::unique_ptr<syz::Prog>
    make_data_mmap_prog(const syz::Target& target) const override {
        const auto* meta = target.find_syscall("mmap");
        if (meta == nullptr || meta->args().size() < 5) return nullptr;
        const auto* prot_read     = target.find_const("PROT_READ");
        const auto* prot_write    = target.find_const("PROT_WRITE");
        const auto* prot_exec     = target.find_const("PROT_EXEC");
        const auto* map_anonymous = target.find_const("MAP_ANONYMOUS");
        const auto* map_private   = target.find_const("MAP_PRIVATE");
        const auto* map_fixed     = target.find_const("MAP_FIXED");
        if (prot_read == nullptr || prot_write == nullptr ||
            prot_exec == nullptr || map_anonymous == nullptr ||
            map_private == nullptr || map_fixed == nullptr) {
            return nullptr;
        }
        // Linux registers MakePosixMmap(target, exec=true, contain=true)
        // (sys/linux/init.go:49). The data range is mapped
        // PROT_READ|PROT_WRITE|PROT_EXEC; the surrounding pages stay
        // PROT_NONE.
        const std::uint64_t prot_rwx =
            *prot_read | *prot_write | *prot_exec;
        const std::uint64_t flags =
            *map_anonymous | *map_private | *map_fixed;
        const std::uint64_t page  = target.page_size();
        const std::uint64_t total = target.num_pages() * page;
        constexpr std::uint64_t kInvalidFD = ~std::uint64_t{0};

        auto prog = std::make_unique<syz::Prog>();
        prog->set_target(&target);
        prog->add_call(make_mmap_call(*meta, ~page + 1, page, 0,        flags, kInvalidFD));
        prog->add_call(make_mmap_call(*meta, 0,         total, prot_rwx, flags, kInvalidFD));
        prog->add_call(make_mmap_call(*meta, total,     page, 0,        flags, kInvalidFD));
        return prog;
    }
};

} // namespace

const ICSourceTargetInfo& linux_amd64_target_info() {
    static const LinuxAmd64TargetInfo kInstance;
    return kInstance;
}

} // namespace refuzz::crash::repro::csource
