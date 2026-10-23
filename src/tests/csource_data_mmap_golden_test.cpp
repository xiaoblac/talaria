// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-A — make_data_mmap_prog structural golden.
//
// Asserts the linux_amd64 target_info's make_data_mmap_prog returns
// the 3-call shape upstream MakePosixMmap(target, exec=true,
// contain=true)() produces (sys/linux/init.go:49 registers exec=true):
//   [0] mmap( ~PageSize+1, PageSize,        PROT_NONE,                       flags, -1, 0 )
//   [1] mmap( 0,           NumPages*PageSize, PROT_READ|PROT_WRITE|PROT_EXEC, flags, -1, 0 )
//   [2] mmap( NumPages*PageSize, PageSize,  PROT_NONE,                       flags, -1, 0 )
//
// where flags = MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED.
//
// Byte-equal vs upstream `serialize_for_exec` output is covered by
// the Go-side drift test (tools/csource_target_info_check). This
// test is the C++-side structural assertion.

#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace syz = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

uint64_t const_arg_val(const syz::Arg* arg) {
    return static_cast<const syz::ConstArg*>(arg)->val();
}

uint64_t result_arg_val(const syz::Arg* arg) {
    return static_cast<const syz::ResultArg*>(arg)->val();
}

uint64_t pointer_arg_addr(const syz::Arg* arg) {
    return static_cast<const syz::PointerArg*>(arg)->address();
}

uint64_t pointer_arg_vma_size(const syz::Arg* arg) {
    return static_cast<const syz::PointerArg*>(arg)->vma_size();
}

void check_mmap_call_shape(const syz::Call& call,
                           uint64_t expected_addr,
                           uint64_t expected_size,
                           uint64_t expected_prot,
                           uint64_t expected_flags,
                           uint64_t expected_fd_invalid) {
    CHECK(call.meta() != nullptr);
    CHECK(call.meta()->call_name() == "mmap");
    const auto& args = call.args();
    // Linux/amd64 mmap takes 6 args: addr, size, prot, flags, fd, offset.
    CHECK(args.size() == 6);

    CHECK(args[0]->arg_kind() == syz::ArgKind::kPointer);
    CHECK(pointer_arg_addr(args[0].get())     == expected_addr);
    CHECK(pointer_arg_vma_size(args[0].get()) == expected_size);

    CHECK(args[1]->arg_kind() == syz::ArgKind::kConst);
    CHECK(const_arg_val(args[1].get()) == expected_size);

    CHECK(args[2]->arg_kind() == syz::ArgKind::kConst);
    CHECK(const_arg_val(args[2].get()) == expected_prot);

    CHECK(args[3]->arg_kind() == syz::ArgKind::kConst);
    CHECK(const_arg_val(args[3].get()) == expected_flags);

    CHECK(args[4]->arg_kind() == syz::ArgKind::kResult);
    CHECK(result_arg_val(args[4].get()) == expected_fd_invalid);

    CHECK(args[5]->arg_kind() == syz::ArgKind::kConst);
    CHECK(const_arg_val(args[5].get()) == 0);   // offset
}

} // namespace

int main() {
    const auto& target = syz::Target::linux_amd64();
    const auto& ti     = cs::linux_amd64_target_info();
    auto prog          = ti.make_data_mmap_prog(target);
    CHECK(prog != nullptr);
    CHECK(prog->target() == &target);
    CHECK(prog->calls().size() == 3);

    const uint64_t page  = target.page_size();
    const uint64_t total = target.num_pages() * page;
    // Linux/amd64 registers exec=true,contain=true → data range is
    // PROT_READ|PROT_WRITE|PROT_EXEC.
    const uint64_t prot_rwx =
        *target.find_const("PROT_READ") |
        *target.find_const("PROT_WRITE") |
        *target.find_const("PROT_EXEC");
    const uint64_t flags =
        *target.find_const("MAP_ANONYMOUS") |
        *target.find_const("MAP_PRIVATE")   |
        *target.find_const("MAP_FIXED");
    constexpr uint64_t kInvalidFD = ~uint64_t{0};

    // Leading PROT_NONE page (one page before address 0).
    check_mmap_call_shape(*prog->calls()[0],
                          /*addr=*/  ~page + 1,
                          /*size=*/  page,
                          /*prot=*/  0,
                          /*flags=*/ flags,
                          kInvalidFD);

    // Data range.
    check_mmap_call_shape(*prog->calls()[1],
                          /*addr=*/  0,
                          /*size=*/  total,
                          /*prot=*/  prot_rwx,
                          /*flags=*/ flags,
                          kInvalidFD);

    // Trailing PROT_NONE page.
    check_mmap_call_shape(*prog->calls()[2],
                          /*addr=*/  total,
                          /*size=*/  page,
                          /*prot=*/  0,
                          /*flags=*/ flags,
                          kInvalidFD);

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
