// kcov_coverage_signal_saturation_pipeline_test.cpp
//
// [v2 batch 3 G5] KcovCoverageSignal::Sample 完整 pipeline 集成测试。
//
// 5 断言(plan §3.G5 验收):
//   (a) NoDropByteEqual           — filter 返 nullopt → c.hashes 严格 ==
//                                     c.decoded.cov_hashes(byte-equal invariant)
//   (b) DropNormalizedUnion       — filter 返 SaturationDecision → c.hashes =
//                                     decision.hashes,per-call merge 按 keep_calls
//   (c) ObservationFieldsAligned  — c.observation.Get<KCO>() 完整 + per_call[i]
//                                     字段对齐(coverage_hashes / errno / syscall_id)
//   (d) AllDropFiredFalse         — filter 返 empty decision.hashes → c.fired=false 但
//                                     c.observation 已 set(observation 不丢)
//   (e) NoFeedbackPathObservation — payload 没 KCOV packet → kNoFeedback →
//                                     c.fired=false + c.observation 含 errno/syscall_id
//
// Mock:用 `syz::TextDecoder` 从 text("getpid()\ngetuid()\n")造真 syz::Prog
// + ProgramArtifact;mock IFeedbackStore + IPriorityCalculator + ISaturationFilter
// 控制行为。

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/feedback/priority_calculator.hpp"
#include "refuzz/feedback/saturation_filter.hpp"
#include "refuzz/feedback/signal/kcov_coverage_signal.hpp"
#include "refuzz/feedback/signal_attributes.hpp"
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/backend/syz_exec_runner.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <unordered_map>
#include <vector>

namespace cc  = refuzz::core::channel_contract;
namespace pr  = refuzz::program;
namespace syz = refuzz::program::syz;

namespace {

// ── Mocks ─────────────────────────────────────────────────────────────────────

class StubPriorityCalculator final : public refuzz::fuzzer::IPriorityCalculator {
public:
    std::uint8_t Calculate(const refuzz::fuzzer::SignalAttributes&) const override {
        return 3;  // 任意 prio
    }
};

class StubFeedbackStore final : public refuzz::fuzzer::IFeedbackStore {
public:
    bool HasNewCoverage(const std::vector<std::uint64_t>&) const override { return true; }
    std::size_t MergeCoverage(const std::vector<std::uint64_t>& hashes,
                              std::uint8_t prio) override {
        return MergeCoverage(hashes, prio, nullptr);
    }
    std::size_t MergeCoverage(const std::vector<std::uint64_t>& hashes,
                              std::uint8_t prio,
                              std::vector<std::uint64_t>* novel_hashes) override {
        last_hashes = hashes;
        merge_calls.push_back(hashes);
        last_prio   = prio;
        std::size_t gain = 0;
        if (novel_hashes != nullptr) {
            novel_hashes->clear();
        }
        for (std::uint64_t h : hashes) {
            auto it = seen.find(h);
            if (it == seen.end()) {
                seen.emplace(h, prio);
                ++gain;
                if (novel_hashes != nullptr) {
                    novel_hashes->push_back(h);
                }
            } else if (prio > it->second) {
                it->second = prio;
                ++gain;
                if (novel_hashes != nullptr) {
                    novel_hashes->push_back(h);
                }
            }
        }
        return gain;
    }
    std::vector<std::uint64_t> last_hashes;
    std::vector<std::vector<std::uint64_t>> merge_calls;
    std::uint8_t               last_prio = 0xFF;
    std::unordered_map<std::uint64_t, std::uint8_t> seen;
};

// 可控 filter:返预设 optional<SaturationDecision>。
class ConfigurableFilter final : public refuzz::fuzzer::ISaturationFilter {
public:
    void SetReturn(std::nullopt_t) {
        return_.reset();
    }
    void SetReturn(std::optional<refuzz::fuzzer::SaturationDecision> r) {
        return_ = std::move(r);
    }
    void SetReturn(std::optional<std::vector<std::uint64_t>> r) {
        if (!r.has_value()) {
            return_.reset();
            return;
        }
        refuzz::fuzzer::SaturationDecision d;
        d.hashes = std::move(*r);
        return_ = std::move(d);
    }
    void RecordCalls(bool record) { record_ = record; }
    std::optional<refuzz::fuzzer::SaturationDecision> Filter(
        const refuzz::fuzzer::ExecutionObservation& obs,
        std::span<const std::uint64_t> program_hashes) override {
        if (record_) {
            ++call_count;
            last_program_hashes.assign(program_hashes.begin(), program_hashes.end());
            // capture observation snapshot for cross-test introspection
            if (const auto* kco = obs.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
                last_kco_per_call_size = kco->per_call.size();
            } else {
                last_kco_per_call_size = 0;
            }
        }
        return return_;
    }
    int                        call_count            = 0;
    std::vector<std::uint64_t> last_program_hashes;
    std::size_t                last_kco_per_call_size = 0;
private:
    std::optional<refuzz::fuzzer::SaturationDecision> return_ = std::nullopt;
    bool record_ = true;
};

// ── helpers ───────────────────────────────────────────────────────────────────

// 造 syz::Prog + ProgramArtifact(2 calls — getpid / getuid)。
std::shared_ptr<const pr::ProgramArtifact> BuildArtifact()
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(), syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode("getpid()\ngetuid()\n");
    assert(prog_or.has_value() && *prog_or != nullptr);
    std::shared_ptr<const syz::Prog> typed = std::move(*prog_or);
    auto art = pr::ProgramArtifact::Build(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{},
        typed,
        typeid(syz::Prog),
        nullptr,
        []() -> std::shared_ptr<const std::vector<std::uint8_t>> {
            return std::make_shared<std::vector<std::uint8_t>>();
        });
    return std::make_shared<pr::ProgramArtifact>(std::move(art));
}

// 构造完整 worker output payload:
//   [SyzExecResult × n][uint64 × tail][WorkerFeedbackHeader + KCOV packet]
//
// `with_kcov_packet=false` → 不写尾部 packet(测 case e kNoFeedback path)。
std::vector<std::uint8_t> MakePayload(
    const std::vector<refuzz::worker::SyzExecResult>& results,
    const std::vector<std::uint64_t>&                  cov_tail,
    const std::vector<std::uint64_t>&                  kcov_packet_entries,
    bool                                                with_kcov_packet)
{
    namespace proto = refuzz::proto;
    std::vector<std::uint8_t> p;
    const std::size_t head_bytes = results.size() * sizeof(refuzz::worker::SyzExecResult);
    const std::size_t tail_bytes = cov_tail.size() * sizeof(std::uint64_t);
    p.resize(head_bytes + tail_bytes);
    if (head_bytes > 0) std::memcpy(p.data(), results.data(), head_bytes);
    if (tail_bytes > 0) std::memcpy(p.data() + head_bytes, cov_tail.data(), tail_bytes);
    if (with_kcov_packet) {
        const std::size_t pkt_entries_bytes =
            kcov_packet_entries.size() * sizeof(std::uint64_t);
        const std::size_t hdr_bytes = sizeof(proto::WorkerFeedbackHeader);
        const std::size_t old_size = p.size();
        p.resize(old_size + pkt_entries_bytes + hdr_bytes);
        if (pkt_entries_bytes > 0) {
            std::memcpy(p.data() + old_size,
                        kcov_packet_entries.data(),
                        pkt_entries_bytes);
        }
        proto::WorkerFeedbackHeader hdr{};
        hdr.magic       = proto::kWorkerFeedbackMagic;
        hdr.version     = proto::kWorkerFeedbackVersion;
        hdr.kind        = static_cast<std::uint16_t>(proto::FeedbackKind::kCoverageKcov);
        hdr.entry_count = static_cast<std::uint32_t>(kcov_packet_entries.size());
        hdr.flags       = 0;
        std::memcpy(p.data() + old_size + pkt_entries_bytes, &hdr, hdr_bytes);
    }
    return p;
}

cc::ChannelEvent MakeCompletionEvent(std::vector<std::uint8_t> payload,
                                     std::shared_ptr<const pr::ProgramArtifact> art)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    cc::Completion c;
    c.output       = std::move(payload);
    c.ctx.artifact = std::move(art);
    ev.payload     = std::move(c);
    return ev;
}

}  // namespace

int main()
{
    using refuzz::fuzzer::KcovCoverageSignal;
    using refuzz::fuzzer::KernelExecutionObservation;
    using refuzz::worker::SyzExecResult;

    std::fprintf(stdout, "Running kcov_coverage_signal_saturation_pipeline_test...\n");

    auto art = BuildArtifact();
    // 反查 syscall_id(getpid / getuid)走 prog.calls()[i]->meta()->id();
    // 在断言时直接拿 art 算出 expected。
    const auto* prog = art->As<syz::Prog>().get();
    assert(prog != nullptr);
    assert(prog->calls().size() == 2);
    const std::uint32_t sid_0 = static_cast<std::uint32_t>(prog->calls()[0]->meta()->id());
    const std::uint32_t sid_1 = static_cast<std::uint32_t>(prog->calls()[1]->meta()->id());

    // 共用:2 个 SyzExecResult,call 0 cov[0..2),call 1 cov[2..5)
    std::vector<SyzExecResult> results(2);
    results[0] = {/*ret=*/0,  /*err=*/0,
                  /*flags=*/::refuzz::worker::kCallFlagExecuted |
                              ::refuzz::worker::kCallFlagFinished,
                  /*cover_offset=*/0, /*cover_count=*/2};
    results[1] = {/*ret=*/-1, /*err=*/13,
                  /*flags=*/::refuzz::worker::kCallFlagExecuted |
                              ::refuzz::worker::kCallFlagFinished,
                  /*cover_offset=*/2, /*cover_count=*/3};
    const std::vector<std::uint64_t> cov_tail = {0xA1, 0xA2, 0xB1, 0xB2, 0xB3};
    const std::vector<std::uint64_t> kcov_pkt = {0xA1, 0xA2, 0xB1, 0xB2, 0xB3, 0xC1, 0xC2};
    // ↑ kcov packet 含 cov_tail union 加上 dispatch 之间的 cov(0xC1, 0xC2)
    //   模拟 cursor-based 设计 program-level 含 dispatch-之间 cov,per_call slice 不含

    // ── (a) NoDropByteEqual ────────────────────────────────────────────────
    {
        StubFeedbackStore store;
        StubPriorityCalculator calc;
        ConfigurableFilter filter;
        filter.SetReturn(std::nullopt);  // no drop

        KcovCoverageSignal signal(store, calc, filter);
        auto payload = MakePayload(results, cov_tail, kcov_pkt, /*with_kcov_packet=*/true);
        auto event = MakeCompletionEvent(std::move(payload), art);

        auto c = signal.Sample(event);
        assert(c.fired);
        // byte-equal:c.hashes 严格 == c.decoded.cov_hashes(原 program-level)
        assert(c.hashes == c.decoded.cov_hashes);
        // store 按 call 顺序消费,不是再整程序 MergeCoverage 一次。
        assert(store.merge_calls.size() == 3);  // call0, call1, extra
        assert(store.merge_calls[0] == std::vector<std::uint64_t>({0xA1, 0xA2}));
        assert(store.merge_calls[1] == std::vector<std::uint64_t>({0xB1, 0xB2, 0xB3}));
        assert(store.merge_calls[2] == kcov_pkt);
        const auto* kco = c.observation.Get<KernelExecutionObservation>();
        assert(kco != nullptr);
        assert(kco->extra_novel_signal_hashes ==
               std::vector<std::uint64_t>({0xC1, 0xC2}));
        // filter 收到的 program_hashes = c.decoded.cov_hashes(byte-equal source)
        assert(filter.call_count == 1);
        assert(filter.last_program_hashes == c.decoded.cov_hashes);
    }

    // ── (per-call novelty) a shared novel edge is owned by exactly one call ────
    // call0 = cov_tail[0..2) = {0xD0, 0x5AED}; call1 = cov_tail[1..4) = {0x5AED, 0xD2,
    // 0xD3}. 0x5AED sits in BOTH per-call slices; on a fresh store it must be attributed
    // to call0 (first owner) only, never call1 — the syz addRawMaxSignal claim order that
    // stops one novel edge fanning out into a candidate per touching call.
    {
        StubFeedbackStore store;                 // fresh: nothing claimed yet
        StubPriorityCalculator calc;
        ConfigurableFilter filter;
        filter.SetReturn(std::nullopt);          // no drop

        KcovCoverageSignal signal(store, calc, filter);
        std::vector<SyzExecResult> rr(2);
        rr[0] = {/*ret=*/0, /*err=*/0,
                 /*flags=*/::refuzz::worker::kCallFlagExecuted |
                             ::refuzz::worker::kCallFlagFinished,
                 /*cover_offset=*/0, /*cover_count=*/2};
        rr[1] = {/*ret=*/0, /*err=*/0,
                 /*flags=*/::refuzz::worker::kCallFlagExecuted |
                             ::refuzz::worker::kCallFlagFinished,
                 /*cover_offset=*/1, /*cover_count=*/3};
        const std::vector<std::uint64_t> tail = {0xD0, 0x5AED, 0xD2, 0xD3};
        auto c = signal.Sample(
            MakeCompletionEvent(MakePayload(rr, tail, tail, true), art));
        assert(c.fired);
        const auto* kco = c.observation.Get<KernelExecutionObservation>();
        assert(kco != nullptr && kco->per_call.size() == 2);
        const auto& n0 = kco->per_call[0].novel_signal_hashes;
        const auto& n1 = kco->per_call[1].novel_signal_hashes;
        // disjoint: no edge attributed to two calls (each novel edge owned once).
        for (auto h : n0) {
            assert(std::find(n1.begin(), n1.end(), h) == n1.end());
        }
        // fresh store: call0 owns both its edges; call1 owns only its two NON-shared
        // edges (shared 0x5AED already claimed by call0) → sizes 2 and 2, not 2 and 3.
        assert(n0.size() == 2);
        assert(n1.size() == 2);
        // every per-call novel edge is part of the program novel set.
        for (auto h : n0) {
            assert(std::binary_search(c.novel_hashes.begin(), c.novel_hashes.end(), h));
        }
        for (auto h : n1) {
            assert(std::binary_search(c.novel_hashes.begin(), c.novel_hashes.end(), h));
        }
        std::fprintf(stdout,
                     "  [OK] per-call novelty: shared edge owned by exactly one call\n");
    }

    // ── (b) DropNormalizedUnion ────────────────────────────────────────────
    {
        StubFeedbackStore store;
        StubPriorityCalculator calc;
        ConfigurableFilter filter;
        // mock filter 返"accepted union" — 假装只 accept call 0 的 slice
        // (sort+unique:{0xA1, 0xA2})
        refuzz::fuzzer::SaturationDecision decision;
        decision.hashes = {0xA1, 0xA2};
        decision.keep_calls = {true, false};
        filter.SetReturn(std::move(decision));

        KcovCoverageSignal signal(store, calc, filter);
        auto payload = MakePayload(results, cov_tail, kcov_pkt, /*with_kcov_packet=*/true);
        auto event = MakeCompletionEvent(std::move(payload), art);

        auto c = signal.Sample(event);
        assert(c.fired);
        // c.hashes = filter 输出(non-byte-equal,放弃 dispatch 之间 cov 0xC1/0xC2)
        assert(c.hashes.size() == 2);
        assert(c.hashes[0] == 0xA1);
        assert(c.hashes[1] == 0xA2);
        // store 只消费 accepted call,不从 filtered union 反推 attribution。
        assert(store.merge_calls.size() == 1);
        assert(store.merge_calls[0] == std::vector<std::uint64_t>({0xA1, 0xA2}));
        // c.decoded.cov_hashes 仍是原 program-level(codec 输出未被改),但 c.hashes
        // 已切到 filtered union — 验证 byte-equal invariant **非** trivial
        assert(c.hashes != c.decoded.cov_hashes);
    }

    // ── (c) ObservationFieldsAligned + (d) AllDropFiredFalse 一起测 ─────────
    {
        StubFeedbackStore store;
        StubPriorityCalculator calc;
        ConfigurableFilter filter;
        refuzz::fuzzer::SaturationDecision decision;
        decision.keep_calls = {false, false};
        filter.SetReturn(std::move(decision));  // empty hashes → all drop

        KcovCoverageSignal signal(store, calc, filter);
        auto payload = MakePayload(results, cov_tail, kcov_pkt, /*with_kcov_packet=*/true);
        auto event = MakeCompletionEvent(std::move(payload), art);

        auto c = signal.Sample(event);
        // (d) 全 drop → fired=false
        assert(!c.fired);
        // store 不应被调
        assert(store.last_hashes.empty());

        // (c) observation 必须存在且字段对齐
        const auto* kco = c.observation.Get<KernelExecutionObservation>();
        assert(kco != nullptr);
        assert(kco->per_call.size() == 2);
        // call 0: errno=0, syscall_id=sid_0, coverage_hashes = NormalizeCoverageEntries({0xA1, 0xA2})
        //         (codec 默认 raw_pc=true,sample_rate=1.0 → normalize 是 identity-ish)
        assert(kco->per_call[0].errno_value == 0);
        assert(kco->per_call[0].syscall_id  == sid_0);
        assert(kco->per_call[0].coverage_hashes.size() == 2);
        // call 1: errno=13, syscall_id=sid_1, slice = {0xB1, 0xB2, 0xB3}
        assert(kco->per_call[1].errno_value == 13);
        assert(kco->per_call[1].syscall_id  == sid_1);
        assert(kco->per_call[1].coverage_hashes.size() == 3);
    }

    // ── (e) PCmodePerCallTailIsPrimary ─────────────────────────────────────
    // [当前补丁] PC mode worker 不发 task-end kCoverageKcov packet,per-syscall
    // coverage 只通过 [SyzExecResult × n][uint64 × tail] 落到 payload。
    // codec 返 kNoFeedback,但 KcovCoverageSignal::Sample 现在仍 decode tail、
    // 填 per_call.coverage_hashes、union 进 program-level cov_hashes,跑
    // saturation + MergeCoverage。fired=true 是正确的 PC mode 主路径行为。
    {
        StubFeedbackStore store;
        StubPriorityCalculator calc;
        ConfigurableFilter filter;
        filter.SetReturn(std::nullopt);  // no drop

        KcovCoverageSignal signal(store, calc, filter);
        auto payload = MakePayload(results, cov_tail, /*pkt=*/{}, /*with_kcov_packet=*/false);
        auto event = MakeCompletionEvent(std::move(payload), art);

        auto c = signal.Sample(event);
        // PC mode no packet 现在是 valid coverage 主路径 → fired=true
        assert(c.fired);
        // filter 被调一次(program-level union 进 filter)
        assert(filter.call_count == 1);
        // store 被调
        assert(!store.last_hashes.empty());

        // per_call 切片 byte-equal 跟 case (c) 一致(同 tail 同 cover_offset/count)
        const auto* kco = c.observation.Get<KernelExecutionObservation>();
        assert(kco != nullptr);
        assert(kco->per_call.size() == 2);
        assert(kco->per_call[0].errno_value == 0);
        assert(kco->per_call[0].syscall_id  == sid_0);
        assert(kco->per_call[0].coverage_hashes.size() == 2);  // {0xA1, 0xA2}
        assert(kco->per_call[1].errno_value == 13);
        assert(kco->per_call[1].syscall_id  == sid_1);
        assert(kco->per_call[1].coverage_hashes.size() == 3);  // {0xB1, 0xB2, 0xB3}

        // program-level cov_hashes 是 per-call slices 的 normalized union;
        // 跟 case (a) 不同的是这里没有 dispatch-之间 cov(0xC1/0xC2),所以
        // size = 2+3 = 5(每个值唯一)。
        assert(c.decoded.cov_hashes.size() == 5);
        // filter 收到的就是这个 union
        assert(filter.last_program_hashes == c.decoded.cov_hashes);
        // byte-equal path(filter 返 nullopt)→ c.hashes == c.decoded.cov_hashes
        assert(c.hashes == c.decoded.cov_hashes);
        assert(store.merge_calls.size() == 2);
        assert(store.merge_calls[0] == std::vector<std::uint64_t>({0xA1, 0xA2}));
        assert(store.merge_calls[1] == std::vector<std::uint64_t>({0xB1, 0xB2, 0xB3}));
    }

    return 0;
}
