// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::generateCalls (296-332).
//
// Vars accounting note (PR-4-B-rev2 BLOCKER #3 fix):
// Upstream `prog.ExecProg.Vars []uint64` is the per-result-slot
// default value, indexed by the result slot index. `Vars[i]` is set
// from `ExecArgResult.Default` (decodeexec.go:209-212) and from
// copyout slots (default 0). reFuzz's WireResult.default_val carries
// the same datum; we walk the wire stream to materialize a dense
// vector indexed by result idx.

#include "refuzz/crash/repro/csource/internal/emit_prog_calls.hpp"

#include <format>
#include <unordered_set>
#include <variant>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

namespace {

CSourceFailure internal_err(std::string msg) {
    return CSourceFailure{
        .code = CSourceError::kInternal,
        .message = std::move(msg),
    };
}

// Resolve WireCall.call_id → SyscallMeta via Target::syscalls(). The
// id is the position in Target's syscalls() vector (set in finalize).
const syz::SyscallMeta* find_meta(const syz::Target& target, std::uint64_t id) {
    const auto& v = target.syscalls();
    if (id >= v.size()) return nullptr;
    return v[id].get();
}

} // namespace

std::expected<EmitProgCallsResult, CSourceFailure>
emit_prog_calls(const syz::Prog& /*prog*/, const syz::WireProgram& wp,
                const EmitCallCtx& ctx,
                std::span<const std::string> call_comments,
                bool trace, bool add_comments) {
    if (ctx.target == nullptr || ctx.target_info == nullptr ||
        ctx.opts == nullptr) {
        return std::unexpected(internal_err(
            "emit_prog_calls: EmitCallCtx requires target/target_info/opts"));
    }

    EmitProgCallsResult result;
    int csum_seq = 0;
    std::size_t call_index = 0;
    const uint64_t data_offset = ctx.target->data_offset();

    // vars_dense[idx] = default value (mirror upstream Vars[]).
    std::vector<std::uint64_t> vars_dense;
    auto ensure_idx = [&](std::uint64_t idx) {
        if (idx >= vars_dense.size()) {
            vars_dense.resize(idx + 1, 0);
        }
    };
    auto record_result = [&](std::uint64_t idx, std::uint64_t default_val) {
        ensure_idx(idx);
        // Last writer wins; matches upstream which assigns each time
        // it sees an ExecArgResult. Copyout idx defaults to 0 so it's
        // a no-op when the result reference also exists.
        vars_dense[idx] = default_val;
    };
    auto record_copyout_idx = [&](std::uint64_t idx) {
        ensure_idx(idx);
        // Copyout slot — upstream sets vars[idx]=0 by virtue of the
        // append-zero growth (decodeexec.go grows with zeros). Don't
        // overwrite a non-zero default already recorded by a result
        // reference.
    };

    // Walk wp.instrs. Copyin/Copyout/SetProps preceding a WireCall
    // belong to that WireCall — we accumulate into per-call buffers.
    // The wire stream interleaves: a chunk of Copyins, then a
    // SetProps (optional), then the WireCall, then optional
    // Copyouts. Mirror upstream prog.ExecProg structure: each
    // ExecCall owns its Copyin/Copyout slices.

    std::vector<syz::WireCopyin>  pending_copyins;
    std::vector<syz::WireCopyout> pending_copyouts_after;

    auto flush_call = [&](const syz::WireCall& wc,
                          std::vector<syz::WireCopyout>& copyouts_for_call)
        -> std::expected<void, CSourceFailure> {
        const auto* meta = find_meta(*ctx.target, wc.call_id);
        if (meta == nullptr) {
            return std::unexpected(internal_err(std::format(
                "WireCall[{}].call_id={} out of range "
                "(target has {} syscalls)",
                call_index, wc.call_id, ctx.target->syscalls().size())));
        }

        std::string buf;
        if (add_comments && call_index < call_comments.size()) {
            buf += call_comments[call_index];
            buf += "\n";
        }

        // Emit copyins (with data_offset rebasing).
        EmitArgsCtx args_ctx{ .target = ctx.target, .opts = ctx.opts };
        for (const auto& ci : pending_copyins) {
            emit_copyin(buf, args_ctx, ci, &csum_seq, data_offset);
        }

        // FailNth / Rerun emit happens here in upstream
        // (csource.go:310-323) but baseline gate rejects non-zero
        // values — so we never emit inject_fault / for-loop. The
        // contract is documented in plan §10.

        const bool res_copyout =
            wc.copyout_idx != kExecNoCopyout;
        const bool arg_copyout = !copyouts_for_call.empty();
        const bool have_copyout = res_copyout || arg_copyout;

        emit_call(buf, ctx, *meta, wc, static_cast<int>(call_index),
                  have_copyout, trace);
        // Rerun loop omitted — see baseline_gate.

        if (have_copyout) {
            emit_copyout(buf, ctx, *meta, wc.copyout_idx, res_copyout,
                         std::span<const syz::WireCopyout>(
                             copyouts_for_call.data(),
                             copyouts_for_call.size()),
                         data_offset);
        }
        result.calls.push_back(std::move(buf));
        return {};
    };

    // Pass-1: pre-scan to find each WireCall's index in the call
    // stream and the trailing Copyouts that belong to that call (the
    // ones between the WireCall and the next WireCall, or end).
    // Upstream's ExecProg materializes this once at decode time;
    // since reFuzz's WireProgram preserves the raw instruction order,
    // we reconstruct it here. Same intent, different representation.
    //
    // Iteration scheme:
    //   - Accumulate copyins into pending_copyins until we hit a WireCall.
    //   - On WireCall: scan ahead until the next WireCall (or end) to
    //     collect copyouts that belong to this call.
    //   - flush_call → reset accumulators.

    // Track WireResult references for vars[idx] = default_val.
    auto observe_result_refs = [&](const syz::WireArg& wa) {
        if (auto* r = std::get_if<syz::WireResult>(&wa)) {
            record_result(r->idx, r->default_val);
        }
    };

    for (std::size_t i = 0; i < wp.instrs.size(); ++i) {
        const auto& instr = wp.instrs[i];
        if (auto* ci = std::get_if<syz::WireCopyin>(&instr)) {
            pending_copyins.push_back(*ci);
            observe_result_refs(ci->arg);
            continue;
        }
        if (std::holds_alternative<syz::WireSetProps>(instr)) {
            // SetProps belongs to the immediately-following WireCall.
            // Baseline gate rejects non-default props; ignore here.
            continue;
        }
        if (std::holds_alternative<syz::WireCopyout>(instr)) {
            // A Copyout NOT preceded by its WireCall in the stream
            // shouldn't happen in well-formed wire; skip defensively.
            continue;
        }
        if (auto* wc = std::get_if<syz::WireCall>(&instr)) {
            // Gather subsequent Copyouts up to the next non-Copyout.
            std::vector<syz::WireCopyout> copyouts_for_call;
            for (std::size_t j = i + 1; j < wp.instrs.size(); ++j) {
                if (auto* co = std::get_if<syz::WireCopyout>(&wp.instrs[j])) {
                    copyouts_for_call.push_back(*co);
                    record_copyout_idx(co->idx);
                    continue;
                }
                break;
            }

            for (const auto& wa : wc->args) observe_result_refs(wa);

            // Result-of-call var index — when present, included in vars
            // (default 0 for the call's own result slot).
            if (wc->copyout_idx != kExecNoCopyout) {
                record_copyout_idx(wc->copyout_idx);
            }

            auto r = flush_call(*wc, copyouts_for_call);
            if (!r.has_value()) {
                return std::unexpected(r.error());
            }

            pending_copyins.clear();
            ++call_index;
        }
    }

    result.vars = std::move(vars_dense);
    return result;
}

} // namespace refuzz::crash::repro::csource::internal
