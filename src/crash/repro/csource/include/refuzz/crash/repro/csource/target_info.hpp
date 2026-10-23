// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — ICSourceTargetInfo.
//
// Carries the build-time / per-arch facts csource consumes
// (sys/targets.Target plus prog.Target.MakeDataMmap / HasCallNumber).
// Owned by csource module so reFuzz schema layer (program/syz Target)
// stays csource-unaware; mirrors target_ownership.md row 111
// (MakeDataMmap is Tier C / Class C, not on schema Target).
//
// PR-4-A ships the interface plus the Linux/amd64 singleton including
// make_data_mmap_prog (port of sys/targets/common.go::MakePosixMmap
// for exec=false, contain=true).

#pragma once

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::crash::repro::csource {

struct CSourceTimeouts {
    std::int64_t program_ms = 0;
    std::int64_t syscall_ms = 0;
    std::int64_t scale      = 1;
};

class ICSourceTargetInfo {
public:
    virtual ~ICSourceTargetInfo() = default;

    // Tooling
    virtual std::string_view cpp_path() const = 0;        // "cpp"
    virtual std::string_view c_compiler() const = 0;      // "gcc"
    virtual std::span<const std::string> cflags() const = 0;
    virtual CSourceTimeouts timeouts(int slowdown) const = 0;

    // Syscall-define emission
    virtual std::string_view syscall_prefix() const = 0;  // "__NR_"
    virtual const std::unordered_map<std::string, std::string>&
            syscall_trampolines() const = 0;
    virtual const std::unordered_map<std::string, std::vector<std::string>>&
            pseudo_syscall_deps() const = 0;
    virtual bool need_syscall_define(std::uint64_t nr) const = 0;
    // M2 fix — port of sys/targets.Target.HasCallNumber. Used by
    // generateSyscallDefines (csource.go:217-241) to skip syz_*
    // pseudo entries that have no native NR on the host.
    virtual bool has_call_number(std::string_view call_name) const = 0;

    // Common-header SYZ_* defines
    virtual bool executor_uses_fork_server() const = 0;
    virtual bool ptr_size_is_4() const = 0;
    virtual std::string_view goos()   const = 0;          // "linux"
    virtual std::string_view goarch() const = 0;          // "amd64"
    // M2 fix — host OS at csource library compile time. For Linux
    // build hosts: "linux". Mirrors runtime.GOOS for upstream
    // HOSTGOOS_<runtime> define (common.go:97).
    virtual std::string_view host_goos() const = 0;

    // B3 fix — csource-owned data-mmap-prog builder. Constructs the
    // same Calls upstream MakePosixMmap(target, exec=false,
    // contain=true)() produces (sys/targets/common.go:14-50). Caller
    // takes ownership of the returned Prog.
    virtual std::unique_ptr<::refuzz::program::syz::Prog>
            make_data_mmap_prog(
                const ::refuzz::program::syz::Target& target) const = 0;
};

// Linux/amd64 singleton.
const ICSourceTargetInfo& linux_amd64_target_info();

} // namespace refuzz::crash::repro::csource
