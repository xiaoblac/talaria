// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — emit_call + copyin/copyout +
// fmt_call_body. Adapt of upstream pkg/csource/csource.go::
//   emitCall (339-376) / fmtCallBody (378-426) /
//   copyin (449-490) / copyinVal (493-515) / copyout (517-545)
//   isNative (334-337).

#pragma once

#include "refuzz/crash/repro/csource/annotator.hpp"
#include "refuzz/crash/repro/csource/internal/emit_args.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

constexpr std::uint64_t kExecNoCopyout = ~std::uint64_t{0};

struct EmitCallCtx {
    const ::refuzz::program::syz::Target* target      = nullptr;
    const ICSourceTargetInfo*             target_info = nullptr;
    const Options*                        opts        = nullptr;
    const ICallAnnotator*                 annotator   = nullptr;
};

// True when the call has a native syscall NR and no SyscallTrampolines
// entry. Mirror of csource.go::isNative.
bool is_native(const EmitCallCtx& ctx,
               const ::refuzz::program::syz::SyscallMeta& meta);

// Emit a single copyin into `out`. Mirror of csource.go::copyin.
// `csum_seq` is mutated when a checksum is emitted (incremented
// before assigning the variable index — matches upstream).
//
// `data_offset` is added to copyin.addr and to every WireCsumChunk
// kArgData address — matches upstream DeserializeExec
// (decodeexec.go:121, :233) which rebases at decode time. reFuzz's
// decode_exec_wire keeps raw wire offsets, so csource (the layer
// upstream's csource consumes ExecProg from) does the rebasing.
void emit_copyin(std::string& out,
                 const EmitArgsCtx& args_ctx,
                 const ::refuzz::program::syz::WireCopyin& copyin,
                 int* csum_seq,
                 uint64_t data_offset);

// Emit the copyout block for a call. Mirror of csource.go::copyout.
//
// `res_copyout` indicates the call's `index != ExecNoCopyout` (i.e.,
// the call's return value is captured into r[index]).
// `copyouts` is the slice of WireCopyout instructions that belong to
// this call (already gathered by the caller from the WireProgram
// stream).
//
// `data_offset` is added to each WireCopyout.addr — matches upstream
// DeserializeExec (decodeexec.go:127).
void emit_copyout(std::string& out,
                  const EmitCallCtx& ctx,
                  const ::refuzz::program::syz::SyscallMeta& meta,
                  std::uint64_t result_index,
                  bool res_copyout,
                  std::span<const ::refuzz::program::syz::WireCopyout> copyouts,
                  uint64_t data_offset);

// Emit the per-call C source line (NONFAILING / res = / fmtCallBody)
// followed by trailing trace/comment formatting. Mirror of
// csource.go::emitCall.
void emit_call(std::string& out,
               const EmitCallCtx& ctx,
               const ::refuzz::program::syz::SyscallMeta& meta,
               const ::refuzz::program::syz::WireCall& call,
               int call_index, bool have_copyout, bool trace);

// Format the call body. Mirror of csource.go::fmtCallBody.
std::string fmt_call_body(const EmitCallCtx& ctx,
                          const ::refuzz::program::syz::SyscallMeta& meta,
                          const ::refuzz::program::syz::WireCall& call);

} // namespace refuzz::crash::repro::csource::internal
