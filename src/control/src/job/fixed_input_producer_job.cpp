// [fixed request stream, Step 4] see fixed_input_producer_job.hpp.
//
// Structurally mirrors explore_job.cpp: body iterates records, builds a
// job::Request per record, emits fire-and-forget. The two differences from
// ExploreJob: (1) it consumes a fixed, pre-validated sequence instead of
// generating/mutating, so there is no MAB/corpus/collide involvement; (2) it
// does not self-respawn -- on stream exhaustion it tracks outstanding
// completions via emit's on_completed and signals on_fully_drained exactly
// once everything has come back, instead of retaining a respawn closure.

#include "refuzz/control/job/fixed_input_producer_job.hpp"

#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"   // MakeArtifactFromTypedProg
#include "refuzz/program/syz/encoding.hpp"                // TextDecoder — v2 text -> typed Prog
#include "refuzz/program/syz/exec_wire.hpp"               // serialize_for_exec — reFuzz's own lowering
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/queue/task_tier.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

namespace refuzz::control {

namespace {

// flatrpc.ExecFlag (Syzkaller wire numbering, pkg/flatrpc/flatrpc.go) ->
// refuzz::proto::ExecFlag (domain numbering, proto/domain/include/.../types.hpp).
// The two namespaces do NOT share bit positions (domain bits are chosen to
// avoid colliding with wire-layer masks; see types.hpp's kExecFlagIntraThreaded
// comment), so this is an explicit translation, not a raw bit copy.
//
// Only bits with a real reFuzz per-task equivalent translate. Everything else
// a request-stream record carries (exec_env_flags, sandbox_arg, request_flags,
// all_signal, and flatrpc's CollectSignal/CollectCover/DedupCover bits) has no
// reFuzz per-task field to receive it:
//   - sandbox is a whole-run refuzz::orchestrator::TargetRuntimeConfig knob,
//     not per-request;
//   - request_flags/all_signal gate Syzkaller's own output-return semantics,
//     which reFuzz's own completion/feedback path does not consume per-task;
//   - reFuzz's coverage/signal collection is unconditional in its own feedback
//     pipeline, not request-gated the way Syzkaller's CollectSignal/CollectCover/
//     DedupCover are.
// This is a documented limitation (see docs/plans/
// fixed-request-stream-performance-replay.md Step 4's Gate 4 record), not a
// silent drop.
std::uint32_t TranslateExecFlags(std::uint64_t flatrpc_exec_flags)
{
    // Mirrors pkg/flatrpc/flatrpc.go: ExecFlagCollectComps = 1<<3, ExecFlagThreaded = 1<<4.
    constexpr std::uint64_t kFlatRpcCollectComps = 1ULL << 3;
    constexpr std::uint64_t kFlatRpcThreaded     = 1ULL << 4;

    std::uint32_t flags = 0;
    if ((flatrpc_exec_flags & kFlatRpcCollectComps) != 0) {
        flags |= static_cast<std::uint32_t>(::refuzz::proto::kExecFlagCollectComps);
    }
    if ((flatrpc_exec_flags & kFlatRpcThreaded) != 0) {
        flags |= static_cast<std::uint32_t>(::refuzz::proto::kExecFlagIntraThreaded);
    }
    return flags;
}

// record -> job::Request, structurally identical to what ExploreJob hands the
// scheduler: a typed artifact PLUS the lowered payload (explore_job.cpp
// ToExploreRequest sets both). That symmetry is the point.
//
// The stream carries canonical syzlang text (v2), so the program is rebuilt here
// into a real syz::Prog and lowered by reFuzz's own serialize_for_exec -- the
// same two steps a generated program goes through. v1 stored SerializeForExec
// bytes instead, and because that form is lowered and one-way, replay could only
// forward opaque bytes: ctx.artifact stayed null all the way to the feedback
// engine, so KcovCoverageSignal's per-call decode was skipped wholesale
// (per_call empty -> fuzzer.calls.executed stuck at 0, no per-call coverage, and
// ~10% of completions logged coverage_without_per_call and were marked
// malformed). Replay was silently running a different, degraded pipeline than
// fuzzing -- which invalidates it as a controlled comparison. Rebuilding the
// typed program removes the divergence at its source rather than special-casing
// each consumer that trips over the missing artifact.
//
// Returns nullopt when the text does not decode; the caller counts and skips it
// rather than emitting a request that cannot be attributed.
std::optional<job::Request> ToRequest(const refuzz::request_stream::RequestRecord& record,
                                      std::uint32_t exec_timeout_ms,
                                      const refuzz::program::syz::Target& target)
{
    refuzz::program::syz::TextDecoder decoder(target);
    auto decoded = decoder.decode(std::string_view(
        reinterpret_cast<const char*>(record.prog_text.data()), record.prog_text.size()));
    if (!decoded.has_value() || *decoded == nullptr) {
        return std::nullopt;
    }
    std::shared_ptr<const refuzz::program::syz::Prog> prog(std::move(*decoded));

    auto lowered = refuzz::program::syz::serialize_for_exec(*prog);
    if (!lowered.has_value()) {
        return std::nullopt;
    }

    job::Request req;
    req.artifact = std::make_shared<const refuzz::program::ProgramArtifact>(
        refuzz::program::syz::MakeArtifactFromTypedProg(prog));
    req.payload = std::move(*lowered);
    req.opts.timeout_ms = exec_timeout_ms;
    req.opts.flags = TranslateExecFlags(record.exec_flags);
    // seed_id/origin_seed_id stay 0: an externally supplied program has no
    // source corpus seed (mirrors ExploreJob's GenerateProgram primitive, not
    // its MutateProgram primitive).
    req.tier = refuzz::queue::TaskTier::Candidate;
    return req;
}

// Tracks outstanding emitted-but-not-yet-completed requests so
// on_fully_drained fires exactly once, only once every record has been BOTH
// emitted AND had its completion observed. All access happens on the control
// thread (job body between yields; on_completed callbacks from FuzzerLoop's
// completion dispatch) -- strict alternation per job_scheduler.hpp's own
// invariant, so a plain struct needs no locking.
struct DrainState {
    std::size_t in_flight = 0;
    bool producer_done = false;
    bool signaled = false;
    std::function<void()> on_fully_drained;

    void MaybeSignal()
    {
        if (producer_done && in_flight == 0 && !signaled) {
            signaled = true;
            if (on_fully_drained) {
                on_fully_drained();
            }
        }
    }
};

}  // namespace

job::JobFn MakeFixedInputProducerJob(FixedInputProducerJobDeps deps)
{
    return [deps = std::move(deps)](job::JobContext& ctx) {
        auto state = std::make_shared<DrainState>();
        state->on_fully_drained = deps.on_fully_drained;

        const auto& target = refuzz::program::syz::Target::linux_amd64();
        const auto& records = deps.stream->records;
        std::size_t undecodable = 0;
        for (const auto& record : records) {
            if (ctx.cancelled()) {
                return;   // shutdown teardown; no self-respawn, nothing to signal
            }
            auto req = ToRequest(record, deps.exec_timeout_ms, target);
            if (!req.has_value()) {
                // A record whose text will not rebuild is NOT emitted: dispatching
                // it without an artifact would silently reintroduce the degraded
                // bytes-only path this format change exists to remove. Count and
                // report it instead -- a non-zero count means the two systems did
                // not run the same workload, which the run must not hide.
                ++undecodable;
                continue;
            }
            job::OnCompleted on_completed = [state](const job::ExecResult&) {
                --state->in_flight;
                state->MaybeSignal();
            };
            if (!ctx.emit(std::move(*req), /*on_submitted=*/{}, std::move(on_completed))) {
                return;   // cancelled mid-emit (invariant #9): unwind, do not re-emit
            }
            ++state->in_flight;
        }
        if (undecodable != 0) {
            refuzz::logging::HostLineBuilder("FixedInputProducer", "records_undecodable")
                << undecodable << " of " << records.size()
                << " stream records failed text->Prog->exec rebuild and were NOT"
                   " replayed; this run does not cover the whole stream\n";
        }
        state->producer_done = true;
        state->MaybeSignal();   // covers the (typical) case in_flight already hit 0
    };
}

}  // namespace refuzz::control
