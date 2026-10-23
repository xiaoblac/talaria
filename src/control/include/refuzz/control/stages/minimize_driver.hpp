#pragma once
// Phase 3 Step 3.4 — MinimizeDriver
//
// Core-path jobs run the syz ProgramMinimizer synchronously on the job thread.
// Each minimizer candidate is executed through the injected InlineExecFn
// (production: JobContext::exec), and RunInline returns the final minimized
// payload/artifact/cover for control-thread admission.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::control {

class MinimizeDriver {
public:
    // 注入式 minimize 实现签名（与 ProgramMinimizer::Minimize 等价）。
    using MinimizerFn = std::function<refuzz::crash::MinimizeResult(
        const ::refuzz::program::ProgramArtifact&,
        refuzz::crash::CandidateTestFunc,
        refuzz::crash::StopFunc,
        refuzz::crash::MinimizeMode,
        int)>;

    // ProgramMinimizer candidate wire bytes. These are already serialized for
    // executor submission; callers must not rematerialize from text.
    struct Candidate {
        std::vector<std::uint8_t> exec_wire_payload;
        std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
        int call_index = -1;
    };

    struct CallSignalObservation {
        std::vector<std::uint64_t> coverage_hashes;
        std::int32_t               errno_value = 0;
        std::uint32_t              syscall_id = 0;
        std::vector<std::uint64_t> edge_hashes;
        std::uint8_t signal_priority = 0;
    };

    struct ExecSignalSnapshot {
        std::vector<std::uint64_t> signal_hashes;
        std::vector<CallSignalObservation> per_call;
        // [Extra/-1] program-level remote/async coverage for THIS re-exec, in
        // the admission unit (edges in cover_edges mode). Distinct from
        // signal_hashes (per-call union) — a guilty_call_index<0 target must
        // observe only this, not the whole-program union which also contains
        // ordinary per-call coverage.
        std::vector<std::uint64_t> extra_signal_hashes;
        refuzz::proto::ResultCode exec_status = refuzz::proto::ResultCode::kOk;
        bool hard_stop = false;
    };

    struct StartArgs {
        std::shared_ptr<const ::refuzz::program::ProgramArtifact> initial_artifact;
        // minimize 必须保留完整 target hash set 才算 "still triggers original cov"。
        std::vector<std::uint64_t>     target_signal_hashes;
        std::vector<std::uint8_t>      target_signal_prios;
        std::optional<std::int32_t>    target_errno_value;
        std::optional<std::uint32_t>   target_syscall_id;
        refuzz::proto::ResultCode      target_exec_status = refuzz::proto::ResultCode::kOk;
        int                            attempts          = 3;
        refuzz::crash::MinimizeMode    mode              = refuzz::crash::MinimizeMode::kCrash;
        int                            guilty_call_index = -1;
        bool                           target_is_edge_signal = false;
    };

    struct StepVerdict {
        std::optional<std::vector<std::uint8_t>> final_payload;
        std::shared_ptr<const ::refuzz::program::ProgramArtifact> final_artifact;
        std::vector<std::uint64_t> final_cover;
        int remapped_guilty_call_index = -1;
    };

    // RunInline returns value fields; core_path_job converts it to StepVerdict
    // for the existing control-thread admit path.
    struct InlineVerdict {
        std::vector<std::uint8_t>                                  final_payload;
        std::shared_ptr<const ::refuzz::program::ProgramArtifact>  final_artifact;
        std::vector<std::uint64_t>                                 final_cover;
        int                                                        remapped_guilty_call_index = -1;
        bool                                                       hard_stopped = false;
    };

    // Production = job ctx.exec + SnapshotFrom; tests return snapshots directly.
    using InlineExecFn = std::function<ExecSignalSnapshot(const Candidate&)>;

    MinimizeDriver();
    explicit MinimizeDriver(MinimizerFn fn);
    ~MinimizeDriver() = default;

    MinimizeDriver(const MinimizeDriver&)            = delete;
    MinimizeDriver& operator=(const MinimizeDriver&) = delete;
    MinimizeDriver(MinimizeDriver&&)                 = delete;
    MinimizeDriver& operator=(MinimizeDriver&&)      = delete;

    InlineVerdict RunInline(const StartArgs&                    args,
                            const InlineExecFn&                 exec_fn,
                            const std::function<bool()>&        cancelled_fn);

private:
    MinimizerFn                     minimizer_fn_;
};

} // namespace refuzz::control
