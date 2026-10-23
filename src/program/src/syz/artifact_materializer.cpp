// syz_v2 IArtifactMaterializer adapter (§3.10 follow-up — registry
// refactor). Top-level dispatch lives in
// `program/src/artifact_materializer_dispatch.cpp`; this file owns
// only the syz_v2 format implementation.
//
// Adapter responsibilities:
//   * Decode canonical .syz text into an immutable `syz::Prog`,
//     wrap into a ProgramArtifact (typed view eager, canonical bytes
//     preloaded).
//   * Lower an artifact to exec-wire bytes via `serialize_for_exec`.
//
// Target policy: this adapter currently supports linux/amd64 only
// (D9 / §3.14 multi-arch deferred). The arch check stays *here*, not
// in the registry, because it's a syz-side capability boundary; AFL
// or other formats may not have any target concept at all.

#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/mount_image_segment.hpp"  // SegmentizeMountImages

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <memory>
#include <string_view>
#include <utility>

namespace refuzz::program::syz {

namespace {

constexpr std::string_view kLinuxOs   = "linux";
constexpr std::string_view kAmd64Arch = "amd64";

bool IsLinuxAmd64(const ::refuzz::program::ProgramTargetKey& k) {
    return k.os == kLinuxOs && k.arch == kAmd64Arch;
}

::refuzz::program::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = Target::linux_amd64();
    return ::refuzz::program::ProgramTargetKey{t.os(), t.arch(), t.revision()};
}

class SyzV2Materializer final : public ::refuzz::program::IArtifactMaterializer {
public:
    ::refuzz::fuzzer::ProgFormat format() const override {
        return ::refuzz::fuzzer::ProgFormat::kSyzProg;
    }

    std::expected<::refuzz::program::ProgramArtifact, ::refuzz::program::MaterializeError>
    BuildFromCanonicalPayload(::refuzz::program::ProgramTargetKey  target,
                              std::vector<std::uint8_t>            canonical_bytes) override
    {
        // D9 / §3.14 — adapter-side capability check; multi-arch lifts
        // here, NOT at the registry boundary.
        if (!IsLinuxAmd64(target)) {
            return std::unexpected(::refuzz::program::MaterializeError{
                "SyzV2Materializer: only linux/amd64 supported (D9; "
                "multi-arch lifts in §3.14)"});
        }

        const auto& schema_target = Target::linux_amd64();
        TextDecoder decoder(schema_target, DecodeMode::kNonStrict);
        std::string_view text(reinterpret_cast<const char*>(canonical_bytes.data()),
                              canonical_bytes.size());
        auto prog_or = decoder.decode(text);
        if (!prog_or) {
            return std::unexpected(::refuzz::program::MaterializeError{
                "SyzV2Materializer: decode failed: " + prog_or.error().message});
        }

        // [chunk-based mount image] Pre-segment syz_mount_image imgs ONCE here,
        // while the Prog is still mutable — so the (immutable) artifact and every
        // MaterializeExecWire / mutated child carry the uncompressed SEGS form
        // and the guest skips per-exec zlib decompress. Consumer = WriteSegmentsToFd
        // in the worker's mount_helpers.cpp. No-op for non-mount programs.
        SegmentizeMountImages(**prog_or, schema_target);

        // Decoder returns unique_ptr; promote to shared so the typed
        // view can fan out (D3 — immutable shared object).
        std::shared_ptr<const Prog> prog_sp(prog_or->release());

        // [≥1-call 不变量 — corpus admit gate] kNonStrict 解码可能得到 0-call 空程序
        //   (text 无任何可解析 call)。空程序无 syscall 可执行,留在 corpus 只会让
        //   smash/mutational 反复对它 MutateTyped(早退 kSkipped)空转烧 task。拒在
        //   materializer:返 MaterializeError → corpus loader StrictTyped fail-closed
        //   drop,不进 corpus。与 MutateTyped 的 ≥1-call 输出不变量两头堵死空程序。
        if (prog_sp->calls().empty()) {
            return std::unexpected(::refuzz::program::MaterializeError{
                "SyzV2Materializer: decoded program has 0 calls (empty)"});
        }

        // [v2 Epic 6 PR-6-D — corpus admit gate, mirror upstream
        //  pkg/manager/seeds.go:289-293 "input has fail_nth > 0"]
        // Refuse FailNth>0 inputs at the syz-owned materializer (D2 — only
        // syz modules may inspect typed view; corpus_disk_io stays IR-blind).
        // Returning MaterializeError surfaces to the corpus loader as
        // "materializer returned null" → existing StrictTyped fail-closed
        // path drops the seed without entering the corpus.
        //
        // Reason this gate exists: fault-inject task replays produced by
        // FaultInjectionConsumerStage carry FailNth>0 transiently and bypass
        // corpus admit (Consumer no-admit FeedbackActions per epic-6 plan
        // §3 D-10). But operator-supplied corpus dirs / fuzzer disk persistence
        // could contain FailNth>0 inputs (mistake / leftover / hand-crafted);
        // refuse them at materialization so they never enter the corpus.
        for (const auto& call : prog_sp->calls()) {
            if (call->props().fail_nth > 0) {
                return std::unexpected(::refuzz::program::MaterializeError{
                    "SyzV2Materializer: input has fail_nth > 0"});
            }
        }

        auto canonical_sp = std::make_shared<const std::vector<std::uint8_t>>(
            std::move(canonical_bytes));

        if (target.revision.empty()) {
            target.revision = LinuxAmd64Key().revision;
        }

        return ::refuzz::program::ProgramArtifact::Build(
            ::refuzz::fuzzer::ProgFormat::kSyzProg,
            std::move(target),
            std::shared_ptr<const void>(prog_sp, prog_sp.get()),
            typeid(Prog),
            std::move(canonical_sp),
            ::refuzz::program::ProgramArtifact::CanonicalProvider{});
    }

    std::expected<std::vector<std::uint8_t>, ::refuzz::program::MaterializeError>
    LowerToExecWire(const ::refuzz::program::ProgramArtifact& artifact) override
    {
        // The dispatch layer already filters on artifact.format(); we
        // only see kSyzProg artifacts here.
        auto prog = artifact.As<Prog>();
        if (prog == nullptr) {
            return std::unexpected(::refuzz::program::MaterializeError{
                "SyzV2Materializer::LowerToExecWire: artifact has no syz::Prog typed view"});
        }
        auto bytes_or = serialize_for_exec(*prog);
        if (!bytes_or) {
            return std::unexpected(::refuzz::program::MaterializeError{
                "SyzV2Materializer::LowerToExecWire: serialize_for_exec failed: "
                + bytes_or.error().message});
        }
        return std::move(bytes_or.value());
    }
};

} // namespace

std::unique_ptr<::refuzz::program::IArtifactMaterializer> CreateSyzV2Materializer() {
    return std::make_unique<SyzV2Materializer>();
}

// -----------------------------------------------------------------
// syz-specific helper — wrap a typed Prog in an artifact (§3.10
// step 3 hot-path producer route used by SyzV2MutatorEngine::MutateTyped).
// Stays in this TU because it depends on the syz Prog / TextEncoder /
// Target schema; not a registry-dispatched API.
// -----------------------------------------------------------------

::refuzz::program::ProgramArtifact MakeArtifactFromTypedProg(std::shared_ptr<const Prog> prog)
{
    if (prog == nullptr || prog->target() == nullptr) {
        return ::refuzz::program::ProgramArtifact{};
    }

    const Target* tgt = prog->target();
    ::refuzz::program::ProgramTargetKey key{tgt->os(), tgt->arch(), tgt->revision()};

    std::shared_ptr<const void> typed_void(prog, prog.get());

    ::refuzz::program::ProgramArtifact::CanonicalProvider provider =
        [prog, tgt]() -> std::shared_ptr<const std::vector<std::uint8_t>> {
            TextEncoder enc(*tgt);
            std::string text = enc.encode(*prog);
            auto bytes = std::make_shared<std::vector<std::uint8_t>>(
                text.begin(), text.end());
            return std::const_pointer_cast<const std::vector<std::uint8_t>>(bytes);
        };

    return ::refuzz::program::ProgramArtifact::Build(
        ::refuzz::fuzzer::ProgFormat::kSyzProg,
        std::move(key),
        std::move(typed_void),
        typeid(Prog),
        /*canonical_bytes=*/nullptr,
        std::move(provider));
}

// [syscall-enable-whitelist] 见 hpp 文档头。用 per-id enabled mask 判定:
// 任意一条 call 的 id 不在 mask → 整 program drop。empty mask = 无白名单,
// 直接透传。(impl-kind 移除后,这是唯一的 corpus-load pseudo/whitelist 闸。)
::refuzz::program::ArtifactMaterializerFn WrapWithEnabledCalls(
    ::refuzz::program::ArtifactMaterializerFn base,
    std::vector<std::uint8_t>                 enabled_mask)
{
    return [base = std::move(base), mask = std::move(enabled_mask)](
        const std::vector<std::uint8_t>& payload)
        -> std::shared_ptr<const ::refuzz::program::ProgramArtifact> {
        auto artifact = base ? base(payload) : nullptr;
        if (artifact == nullptr) return nullptr;
        if (mask.empty()) return artifact;   // no whitelist → pass-through

        auto prog_sp = artifact->As<Prog>();
        if (prog_sp != nullptr) {
            for (const auto& call : prog_sp->calls()) {
                if (!call) continue;
                const SyscallMeta* meta = call->meta();
                if (meta == nullptr) continue;
                const std::uint64_t id = meta->id();
                if (id >= mask.size() || mask[id] == 0) {
                    return nullptr;
                }
            }
        }
        return artifact;
    };
}

} // namespace refuzz::program::syz
