// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosMutatorEngine — Phase 2 §C #20 v1 mutator for XiUOS kernel programs.
//
// IMutatorEngine implementation that decodes a Seed.payload as a XiUOS
// PROGRAM payload (via XiuosDecodeProgram), applies one randomly chosen
// mutation op, and returns the re-encoded bytes. Lives in the host-side
// mutator/ module alongside SyzV2MutatorEngine; built on the same
// IMutatorEngine contract so MutatorManager/FuzzerLoop can route to it
// without knowing it's XiUOS-specific.
//
// v1 mutation op set (uniform pick over the four ops; sequence-level ops
// like lifecycle reorder and intentional all-invalid programs are
// deferred — see docs/xiuos-refuzz roadmap):
//
//   kInsertCall   — insert one new call at a random index. Generated call's
//                   api_id + args may be lifecycle-aware or not (see Config
//                   .lifecycle_violation_pct).
//   kDeleteCall   — remove one call at a random index. Skipped if empty.
//   kReplaceCall  — overwrite one call's api_id + args. argc and arg domains
//                   follow the new api's descriptor.
//   kMutateArg    — keep the call's api_id, resample exactly one arg from
//                   the argument's typed domain. Skipped if the call has
//                   argc == 0.
//
// Lifecycle awareness mirrors `tools/xiuos_refuzz/descriptors/
// common_kernel_sem_mutex.json`: by default we only emit calls whose
// "expected" state matches the slot's current lifecycle state (SEM_OBTAIN
// requires LIVE, MUTEX_ABANDON requires OWNED, etc.). A small percentage
// (Config.lifecycle_violation_pct, default 20%) of inserted/replaced calls
// ignore lifecycle and pick any api uniformly — this is how the mutator
// produces adversarial input for the worker's slot/lifecycle gates.
//
// Stats expose per-op attempted/produced counters; useful when tuning the
// mix and verifying coverage of all ops in tests.
//
// Threading: matches IMutatorEngine contract — Mutate() is called from a
// single FuzzerLoop thread, so the internal RNG and stats are unguarded.

#pragma once

#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::fuzzer {

class XiuosMutatorEngine final : public IMutatorEngine {
public:
    enum class MutationOp : std::uint8_t {
        kInsertCall = 0,
        kDeleteCall,
        kReplaceCall,
        kMutateArg,
        kCount,
    };

    struct Stats {
        std::array<std::uint64_t,
                   static_cast<std::size_t>(MutationOp::kCount)> attempted{};
        std::array<std::uint64_t,
                   static_cast<std::size_t>(MutationOp::kCount)> produced{};
        std::uint64_t total_calls = 0;
        std::uint64_t empty_seed_skipped = 0;
        std::uint64_t decode_failed = 0;
        std::uint64_t encode_failed = 0;
        std::uint64_t op_skipped = 0;          // op decided no change (eg. delete on empty)
        std::uint64_t lifecycle_violations = 0; // generated call that ignored lifecycle state
    };

    struct Config {
        // 0 = use std::random_device for the seed.
        std::uint64_t rng_seed = 0;
        // % of inserted/replaced calls that ignore lifecycle state. 0..100.
        unsigned lifecycle_violation_pct = 20;
        // % of arg values drawn from the invalid-domain table (slot=255,
        // timeout=0xffffffff, value=0xffffffff). 0..100.
        unsigned arg_invalid_value_pct = 10;
        // Hard cap on the call count after a mutation. The program encoder
        // also enforces kXiuosMaxCallsPerProgram so the final PROGRAM payload
        // stays within XIUOS_MAX_PAYLOAD.
        unsigned max_calls_per_program = 24;
    };

    // Lifecycle state per slot — mirrors the FSM in
    // common_kernel_sem_mutex.json §"lifecycle".
    enum class SemLife   : std::uint8_t { kEmpty, kLive };
    enum class MutexLife : std::uint8_t { kEmpty, kLive, kOwned };
    // MsgQueue lifecycle is two-state: EMPTY / LIVE. The descriptor does
    // not model queue depth — Send/Recv are always "valid" against a
    // LIVE slot; the worker dispatches them and tolerates -ETIMEOUT /
    // -EFULL outcomes the same way Sem* tolerates -EINVALED.
    enum class MsgqLife  : std::uint8_t { kEmpty, kLive };
    // Event lifecycle is also two-state. The 29-bit events mask inside a
    // LIVE slot is not modeled in the FSM — Trigger/Process always accept
    // a LIVE slot regardless of which bits are set/waited.
    enum class EventLife : std::uint8_t { kEmpty, kLive };
    // Timer FSM mirrors the mutex three-state shape: CREATED is the
    // "owned but quiescent" state, RUNNING is "owned and ticking". The
    // valid transitions live in the descriptor (lifecycle.timer).
    enum class TimerLife : std::uint8_t { kEmpty, kCreated, kRunning };
    // Task FSM: kEmpty (no aux task) / kBlocked (victim task spawned, sitting
    // on a kernel pend_list). TERMINATE returns slot to kEmpty.
    enum class TaskLife  : std::uint8_t { kEmpty, kBlocked };
    // WQ FSM: kEmpty (no work queue) / kLive (created, callable). SUBMIT /
    // SUBMIT_DELAYED don't change state; DEINIT returns to kEmpty.
    enum class WqLife    : std::uint8_t { kEmpty, kLive };
    // Direct allocator FSM: kEmpty (slot holds no pointer) / kAllocated
    // (worker-owned heap pointer in the slot). MALLOC/CALLOC/REALLOC may
    // overwrite an allocated slot; FREE returns it to kEmpty.
    enum class MallocLife : std::uint8_t { kEmpty, kAllocated };

    struct LifecycleState {
        std::array<SemLife,   XIUOS_SEM_SLOTS>   sem{};       // all kEmpty
        std::array<MutexLife, XIUOS_MUTEX_SLOTS> mutex{};     // all kEmpty
        std::array<MsgqLife,  XIUOS_MSGQ_SLOTS>  msgq{};      // all kEmpty
        std::array<EventLife, XIUOS_EVENT_SLOTS> event{};     // all kEmpty
        std::array<TimerLife, XIUOS_TIMER_SLOTS> timer{};     // all kEmpty
        std::array<TaskLife,  XIUOS_TASK_SLOTS>  task{};      // all kEmpty
        std::array<WqLife,    XIUOS_WQ_SLOTS>    wq{};        // all kEmpty
        std::array<MallocLife, XIUOS_MALLOC_SLOTS> malloc{};  // all kEmpty

        // Advance state by the effect of `call`. Calls that are not legal
        // under the current state are still applied with the descriptor's
        // "invalid" transitions: state stays put. Calls with arg out-of-
        // range slots are no-ops.
        void Apply(const refuzz::program::xiuos::XiuosProgramCall& call);

        // True if `call` is legal under the current state (i.e. matches a
        // descriptor transition with invalid=false).
        bool IsValid(const refuzz::program::xiuos::XiuosProgramCall& call) const;
    };

    XiuosMutatorEngine();  // default Config
    explicit XiuosMutatorEngine(Config cfg);

    // [Stage 3] catalog id == engine Name() so MutatorManager::SwitchEngineByName
    // (driven by the profile's mutator_engine="xiuos") routes here, same convention
    // as SyzV2MutatorEngine::Name()=="syz".
    std::string Name() const override { return "xiuos"; }

    std::vector<std::uint8_t> Mutate(const Seed& seed) override;

    bool SwitchPolicyByName(std::string_view name) override {
        return name == "default";
    }
    std::string ActivePolicyName() const override { return "default"; }

    Stats GetStats() const { return stats_; }
    void  ResetStats()     { stats_ = Stats{}; }

    // Test-visible helper: walk `calls` and return the LifecycleState that
    // a call inserted at `position` would see. Public so the unit test can
    // poke at the FSM directly.
    static LifecycleState StateAt(
        std::span<const refuzz::program::xiuos::XiuosProgramCall> calls,
        std::size_t position);

    // Test-visible helper: produce one call given a current LifecycleState.
    // `lifecycle_aware = true` only emits calls satisfying IsValid(state);
    // `false` picks any api uniformly. Slot index is always 0..N-1; arg
    // values come from the typed domain (small chance of invalid_domain).
    refuzz::program::xiuos::XiuosProgramCall
    GenerateCall(const LifecycleState& state, bool lifecycle_aware);

private:
    bool OpInsertCall(
        std::vector<refuzz::program::xiuos::XiuosProgramCall>& calls);
    bool OpDeleteCall(
        std::vector<refuzz::program::xiuos::XiuosProgramCall>& calls);
    bool OpReplaceCall(
        std::vector<refuzz::program::xiuos::XiuosProgramCall>& calls);
    bool OpMutateArg(
        std::vector<refuzz::program::xiuos::XiuosProgramCall>& calls);

    std::uint32_t SampleSlot(std::uint32_t max_slot, bool include_invalid);
    std::uint32_t SampleTimeout(bool include_invalid);
    std::uint32_t SampleSmallValue(bool include_invalid);
    bool          RollChance(unsigned pct);  // true with prob pct/100

    Config        cfg_;
    std::mt19937_64 rng_;
    Stats         stats_;
};

}  // namespace refuzz::fuzzer
