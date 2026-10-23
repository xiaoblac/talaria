// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosMutatorEngine impl. See header for design notes.
//
// Constants (slot counts, timeouts, small_value domain, API ids) MUST stay
// in sync with tools/xiuos_refuzz/descriptors/common_kernel_sem_mutex.json —
// the Python generator reads that file directly; the C++ mutator hard-codes
// values here. Any descriptor change needs to land in BOTH places.

#include "refuzz/mutator/xiuos/xiuos_mutator_engine.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <random>
#include <stdexcept>

namespace refuzz::fuzzer {

namespace progx = refuzz::program::xiuos;

namespace {

// Mirrors common_kernel_sem_mutex.json §"limits".timeouts.
constexpr std::array<std::uint32_t, 4> kValidTimeouts = {0u, 1u, 2u, 10u};
// Mirrors common_kernel_sem_mutex.json §"domains".timeout.invalid.
constexpr std::array<std::uint32_t, 1> kInvalidTimeouts = {0xffffffffu};
// Mirrors common_kernel_sem_mutex.json §"limits".small_values.
constexpr std::array<std::uint32_t, 4> kValidSmallValues = {0u, 1u, 2u, 3u};
constexpr std::array<std::uint32_t, 1> kInvalidSmallValues = {0xffffffffu};
// Slot invalid domain: anything >= max_slot. We pick one nominal value.
constexpr std::uint32_t kInvalidSlotValue = 255u;

// Per-API spec mirroring common_kernel_sem_mutex.json §"apis".
//
// arg layout: args[0] is always the slot id (within the family's slot
// table); args[1..argc-1] are described by ArgT entries. v1 only uses
// arg1 + arg2 (argc <= 3). The byte_pattern_idx args for MSGQ_SEND etc.
// reuse the kSmallValue domain {0,1,2,3} — the worker maps the idx
// through a fixed 4-pattern table.
struct ApiSpec {
    progx::XiuosApiId api_id;
    std::uint8_t      argc;
    enum class Family : std::uint8_t {
        kSem,
        kMutex,
        kMsgq,
        kEvent,
        kTimer,
        kTask,
        kWq,
        kMalloc,
    };
    Family            family;
    enum class ArgT   : std::uint8_t { kNone, kSmallValue, kTimeout };
    ArgT              arg1_type;
    ArgT              arg2_type;
    // Optional 3rd typed arg (args[3]) for the few argc==4 ops (e.g.
    // EVENT_PROCESS process_options_idx). Defaults to kNone so the existing
    // 5-field initializers stay valid; only argc==4 entries set it.
    ArgT              arg3_type = ArgT::kNone;
};

constexpr std::array<ApiSpec, 37> kApis = {{
    {progx::XiuosApiId::SemCreate,    2, ApiSpec::Family::kSem,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::SemDelete,    1, ApiSpec::Family::kSem,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::SemObtain,    2, ApiSpec::Family::kSem,
        ApiSpec::ArgT::kTimeout,    ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::SemAbandon,   1, ApiSpec::Family::kSem,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::SemSetValue,  2, ApiSpec::Family::kSem,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MutexCreate,  1, ApiSpec::Family::kMutex,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MutexDelete,  1, ApiSpec::Family::kMutex,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MutexObtain,  2, ApiSpec::Family::kMutex,
        ApiSpec::ArgT::kTimeout,    ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MutexAbandon, 1, ApiSpec::Family::kMutex,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},

    // KMsgQueue family — Phase 2 §C #22 follow-up.
    //   CREATE(slot, msg_size_idx, max_msgs_idx)  argc=3
    //   DELETE(slot)                              argc=1
    //   SEND(slot, byte_pattern_idx)              argc=2 (non-blocking)
    //   RECV(slot, timeout_idx)                   argc=2
    //   URGENT_SEND(slot, byte_pattern_idx)       argc=2
    //   REINIT(slot)                              argc=1
    {progx::XiuosApiId::MsgqCreate,      3, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kSmallValue},
    {progx::XiuosApiId::MsgqDelete,      1, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MsgqSend,        2, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MsgqRecv,        2, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kTimeout,    ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MsgqUrgentSend,  2, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::MsgqReinit,      1, ApiSpec::Family::kMsgq,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},

    // KEvent family — Phase 2 §C #22 follow-up.
    //   CREATE(slot, options_idx)                argc=2
    //   DELETE(slot)                             argc=1
    //   TRIGGER(slot, events_pattern_idx)        argc=2
    //   PROCESS(slot, events_pattern_idx,
    //                 timeout_idx)               argc=3
    {progx::XiuosApiId::EventCreate,     2, ApiSpec::Family::kEvent,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::EventDelete,     1, ApiSpec::Family::kEvent,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::EventTrigger,    2, ApiSpec::Family::kEvent,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::EventProcess,    4, ApiSpec::Family::kEvent,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kTimeout,
        ApiSpec::ArgT::kSmallValue},  // arg3 = process_options_idx

    // KTimer family — 3-state FSM (EMPTY / CREATED / RUNNING). Args:
    //   CREATE(slot, ticks_idx, mode_idx) argc=3
    //   DELETE(slot)                      argc=1
    //   START_RUN(slot)                   argc=1
    //   QUIT_RUN(slot)                    argc=1
    //   MODIFY(slot, ticks_idx)           argc=2
    // ticks_idx / mode_idx are kSmallValue domain (worker maps via
    // bounded tables to real ticks / trigger modes).
    {progx::XiuosApiId::TimerCreate,     3, ApiSpec::Family::kTimer,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kSmallValue},
    {progx::XiuosApiId::TimerDelete,     1, ApiSpec::Family::kTimer,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TimerStartRun,   1, ApiSpec::Family::kTimer,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TimerQuitRun,    1, ApiSpec::Family::kTimer,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TimerModify,     2, ApiSpec::Family::kTimer,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},

    // KTask family — auxiliary victim tasks for multi-waiter scenarios.
    //   SPAWN_BLOCK_SEM(task_slot, sem_slot)        argc=2
    //   SPAWN_BLOCK_EVENT(task_slot, event_slot)    argc=2
    //   SPAWN_BLOCK_MSGQ_RECV(task_slot, mq_slot)   argc=2
    //   TERMINATE(task_slot)                        argc=1
    // arg2 is a cross-family slot id; mutator treats it as kSmallValue
    // (the per-program FSM doesn't model the target's state — worker
    // bails -ERROR if target is empty, which the mutator's IsValid()
    // tolerates).
    {progx::XiuosApiId::TaskSpawnBlockSem,      2, ApiSpec::Family::kTask,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TaskSpawnBlockEvent,    2, ApiSpec::Family::kTask,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TaskSpawnBlockMsgqRecv, 2, ApiSpec::Family::kTask,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::TaskTerminate,          1, ApiSpec::Family::kTask,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    // PRIO_SET acts on a BLOCKED victim, second arg is prio_idx.
    {progx::XiuosApiId::TaskPrioSet,            2, ApiSpec::Family::kTask,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},

    // KWorkQueue family — 2-state lifecycle (EMPTY / LIVE).
    //   CREATE(slot, prio_idx)            argc=2
    //   DEINIT(slot)                      argc=1
    //   SUBMIT(slot)                      argc=1
    //   SUBMIT_DELAYED(slot, time_idx)    argc=2
    {progx::XiuosApiId::WqCreate,        2, ApiSpec::Family::kWq,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::WqDeinit,        1, ApiSpec::Family::kWq,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::WqSubmit,        1, ApiSpec::Family::kWq,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::WqSubmitDelayed, 2, ApiSpec::Family::kWq,
        ApiSpec::ArgT::kTimeout,    ApiSpec::ArgT::kNone},

    // Direct allocator family — 2-state lifecycle (EMPTY / ALLOCATED).
    // size_idx / count_idx reuse the small-value domain and fold through
    // worker tables: size {0,16,64,256}, count {0,1,4,16}.
    {progx::XiuosApiId::Malloc,          2, ApiSpec::Family::kMalloc,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::Free,            1, ApiSpec::Family::kMalloc,
        ApiSpec::ArgT::kNone,       ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::Realloc,         2, ApiSpec::Family::kMalloc,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kNone},
    {progx::XiuosApiId::Calloc,          3, ApiSpec::Family::kMalloc,
        ApiSpec::ArgT::kSmallValue, ApiSpec::ArgT::kSmallValue},
}};

std::uint32_t SlotsForFamily(ApiSpec::Family f) {
    switch (f) {
    case ApiSpec::Family::kSem:   return XIUOS_SEM_SLOTS;
    case ApiSpec::Family::kMutex: return XIUOS_MUTEX_SLOTS;
    case ApiSpec::Family::kMsgq:  return XIUOS_MSGQ_SLOTS;
    case ApiSpec::Family::kEvent: return XIUOS_EVENT_SLOTS;
    case ApiSpec::Family::kTimer: return XIUOS_TIMER_SLOTS;
    case ApiSpec::Family::kTask:  return XIUOS_TASK_SLOTS;
    case ApiSpec::Family::kWq:    return XIUOS_WQ_SLOTS;
    case ApiSpec::Family::kMalloc:return XIUOS_MALLOC_SLOTS;
    }
    return 0;
}

const ApiSpec& FindApi(progx::XiuosApiId id) {
    for (const auto& a : kApis) {
        if (a.api_id == id) return a;
    }
    // Unknown api — return SemCreate as a stub. Mutator never calls this
    // with an unknown id; defensive.
    return kApis[0];
}

}  // namespace

// ──────────────────────── LifecycleState ────────────────────────────────

void XiuosMutatorEngine::LifecycleState::Apply(
        const progx::XiuosProgramCall& call) {
    // Slot index lives in args[0]. Out-of-range slot or argc==0 → no state
    // change (matches worker behavior: -EINVALED, slot table untouched).
    if (call.argc == 0) return;
    const std::uint32_t slot = call.args[0];

    switch (call.api_id) {
    case progx::XiuosApiId::SemCreate:
        if (slot < XIUOS_SEM_SLOTS) {
            // Worker overwrites: existing LIVE gets deleted first, then
            // CREATE makes a new one. Net new state is LIVE either way.
            sem[slot] = SemLife::kLive;
        }
        break;
    case progx::XiuosApiId::SemDelete:
        if (slot < XIUOS_SEM_SLOTS && sem[slot] == SemLife::kLive) {
            sem[slot] = SemLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::SemObtain:
    case progx::XiuosApiId::SemAbandon:
    case progx::XiuosApiId::SemSetValue:
        // Semaphore use does not change LIVE state regardless of timeout
        // outcome (descriptor §sem_obtain_live / sem_abandon_live).
        break;
    case progx::XiuosApiId::MutexCreate:
        if (slot < XIUOS_MUTEX_SLOTS) {
            mutex[slot] = MutexLife::kLive;
        }
        break;
    case progx::XiuosApiId::MutexDelete:
        if (slot < XIUOS_MUTEX_SLOTS &&
                (mutex[slot] == MutexLife::kLive ||
                 mutex[slot] == MutexLife::kOwned)) {
            mutex[slot] = MutexLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::MutexObtain:
        if (slot < XIUOS_MUTEX_SLOTS && mutex[slot] == MutexLife::kLive) {
            mutex[slot] = MutexLife::kOwned;
        }
        break;
    case progx::XiuosApiId::MutexAbandon:
        if (slot < XIUOS_MUTEX_SLOTS && mutex[slot] == MutexLife::kOwned) {
            mutex[slot] = MutexLife::kLive;
        }
        break;
    case progx::XiuosApiId::MsgqCreate:
        if (slot < XIUOS_MSGQ_SLOTS) {
            // Worker overwrites: existing LIVE gets deleted then re-created.
            msgq[slot] = MsgqLife::kLive;
        }
        break;
    case progx::XiuosApiId::MsgqDelete:
        if (slot < XIUOS_MSGQ_SLOTS && msgq[slot] == MsgqLife::kLive) {
            msgq[slot] = MsgqLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::MsgqSend:
    case progx::XiuosApiId::MsgqRecv:
    case progx::XiuosApiId::MsgqUrgentSend:
    case progx::XiuosApiId::MsgqReinit:
        // Slot LIVE state unchanged; queue depth not modeled in FSM.
        break;
    case progx::XiuosApiId::EventCreate:
        if (slot < XIUOS_EVENT_SLOTS) {
            event[slot] = EventLife::kLive;
        }
        break;
    case progx::XiuosApiId::EventDelete:
        if (slot < XIUOS_EVENT_SLOTS && event[slot] == EventLife::kLive) {
            event[slot] = EventLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::EventTrigger:
    case progx::XiuosApiId::EventProcess:
        // Slot LIVE state unchanged; 29-bit events mask not modeled.
        break;
    case progx::XiuosApiId::TimerCreate:
        if (slot < XIUOS_TIMER_SLOTS) {
            // Worker overwrites existing; net new state is CREATED.
            timer[slot] = TimerLife::kCreated;
        }
        break;
    case progx::XiuosApiId::TimerDelete:
        if (slot < XIUOS_TIMER_SLOTS &&
                (timer[slot] == TimerLife::kCreated ||
                 timer[slot] == TimerLife::kRunning)) {
            timer[slot] = TimerLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::TimerStartRun:
        if (slot < XIUOS_TIMER_SLOTS && timer[slot] == TimerLife::kCreated) {
            timer[slot] = TimerLife::kRunning;
        }
        break;
    case progx::XiuosApiId::TimerQuitRun:
        if (slot < XIUOS_TIMER_SLOTS && timer[slot] == TimerLife::kRunning) {
            timer[slot] = TimerLife::kCreated;
        }
        break;
    case progx::XiuosApiId::TimerModify:
        // Ticks change does not alter CREATED/RUNNING state.
        break;
    case progx::XiuosApiId::TaskSpawnBlockSem:
    case progx::XiuosApiId::TaskSpawnBlockEvent:
    case progx::XiuosApiId::TaskSpawnBlockMsgqRecv:
        if (slot < XIUOS_TASK_SLOTS) {
            // Worker overwrites occupied task slot (terminate + respawn);
            // net new state is BLOCKED regardless of prior state.
            task[slot] = TaskLife::kBlocked;
        }
        break;
    case progx::XiuosApiId::TaskSpawnBlockSemTimeout:
    case progx::XiuosApiId::TaskSpawnBlockEventTimeout:
    case progx::XiuosApiId::TaskSpawnBlockMsgqRecvTimeout:
    case progx::XiuosApiId::TaskSpawnBlockMutexTimeout:
        // Oracle-only delay-list watermark op; never generated by the mutator.
        break;
    case progx::XiuosApiId::TaskTerminate:
        if (slot < XIUOS_TASK_SLOTS && task[slot] == TaskLife::kBlocked) {
            task[slot] = TaskLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::TaskPrioSet:
        // PRIO_SET doesn't change BLOCKED state.
        break;
    case progx::XiuosApiId::TaskSpawnSelfSuspend:
    case progx::XiuosApiId::TaskWakeup:
    case progx::XiuosApiId::TaskSpawnSelfDelay:
        // Newer scheduler-state ops are descriptor/corpus driven; this
        // legacy FSM only models the BLOCKED victim subset.
        break;
    case progx::XiuosApiId::WqCreate:
        if (slot < XIUOS_WQ_SLOTS) {
            wq[slot] = WqLife::kLive;
        }
        break;
    case progx::XiuosApiId::WqDeinit:
        if (slot < XIUOS_WQ_SLOTS && wq[slot] == WqLife::kLive) {
            wq[slot] = WqLife::kEmpty;
        }
        break;
    case progx::XiuosApiId::WqSubmit:
    case progx::XiuosApiId::WqSubmitDelayed:
        // LIVE state unchanged.
        break;
    case progx::XiuosApiId::DqInit:
    case progx::XiuosApiId::DqDeinit:
    case progx::XiuosApiId::DqPush:
    case progx::XiuosApiId::DqPop:
    case progx::XiuosApiId::DqPeek:
    case progx::XiuosApiId::WaitqInit:
    case progx::XiuosApiId::WaitqSpawnWait:
    case progx::XiuosApiId::WaitqWake:
        // Not represented in this legacy mutator FSM.
        break;
    case progx::XiuosApiId::ResourceSnapshot:
        // Oracle-only introspection op; never generated by the mutator.
        break;
    case progx::XiuosApiId::Malloc:
    case progx::XiuosApiId::Realloc:
    case progx::XiuosApiId::Calloc:
        if (slot < XIUOS_MALLOC_SLOTS) {
            malloc[slot] = MallocLife::kAllocated;
        }
        break;
    case progx::XiuosApiId::Free:
        if (slot < XIUOS_MALLOC_SLOTS &&
                malloc[slot] == MallocLife::kAllocated) {
            malloc[slot] = MallocLife::kEmpty;
        }
        break;
    }
}

bool XiuosMutatorEngine::LifecycleState::IsValid(
        const progx::XiuosProgramCall& call) const {
    // argc=0 is never ABI-valid; treat as invalid for lifecycle purposes.
    if (call.argc == 0) return false;
    const std::uint32_t slot = call.args[0];

    switch (call.api_id) {
    case progx::XiuosApiId::SemCreate:
        return slot < XIUOS_SEM_SLOTS && sem[slot] == SemLife::kEmpty;
    case progx::XiuosApiId::SemDelete:
    case progx::XiuosApiId::SemObtain:
    case progx::XiuosApiId::SemAbandon:
    case progx::XiuosApiId::SemSetValue:
        return slot < XIUOS_SEM_SLOTS && sem[slot] == SemLife::kLive;
    case progx::XiuosApiId::MutexCreate:
        return slot < XIUOS_MUTEX_SLOTS && mutex[slot] == MutexLife::kEmpty;
    case progx::XiuosApiId::MutexDelete:
        return slot < XIUOS_MUTEX_SLOTS &&
               (mutex[slot] == MutexLife::kLive ||
                mutex[slot] == MutexLife::kOwned);
    case progx::XiuosApiId::MutexObtain:
        return slot < XIUOS_MUTEX_SLOTS && mutex[slot] == MutexLife::kLive;
    case progx::XiuosApiId::MutexAbandon:
        return slot < XIUOS_MUTEX_SLOTS && mutex[slot] == MutexLife::kOwned;
    case progx::XiuosApiId::MsgqCreate:
        return slot < XIUOS_MSGQ_SLOTS && msgq[slot] == MsgqLife::kEmpty;
    case progx::XiuosApiId::MsgqDelete:
    case progx::XiuosApiId::MsgqSend:
    case progx::XiuosApiId::MsgqRecv:
    case progx::XiuosApiId::MsgqUrgentSend:
    case progx::XiuosApiId::MsgqReinit:
        return slot < XIUOS_MSGQ_SLOTS && msgq[slot] == MsgqLife::kLive;
    case progx::XiuosApiId::EventCreate:
        return slot < XIUOS_EVENT_SLOTS && event[slot] == EventLife::kEmpty;
    case progx::XiuosApiId::EventDelete:
    case progx::XiuosApiId::EventTrigger:
    case progx::XiuosApiId::EventProcess:
        return slot < XIUOS_EVENT_SLOTS && event[slot] == EventLife::kLive;
    case progx::XiuosApiId::TimerCreate:
        return slot < XIUOS_TIMER_SLOTS && timer[slot] == TimerLife::kEmpty;
    case progx::XiuosApiId::TimerDelete:
    case progx::XiuosApiId::TimerModify:
        // DELETE + MODIFY accept any non-EMPTY state (CREATED or RUNNING).
        return slot < XIUOS_TIMER_SLOTS &&
               (timer[slot] == TimerLife::kCreated ||
                timer[slot] == TimerLife::kRunning);
    case progx::XiuosApiId::TimerStartRun:
        return slot < XIUOS_TIMER_SLOTS && timer[slot] == TimerLife::kCreated;
    case progx::XiuosApiId::TimerQuitRun:
        return slot < XIUOS_TIMER_SLOTS && timer[slot] == TimerLife::kRunning;
    case progx::XiuosApiId::TaskSpawnBlockSem:
    case progx::XiuosApiId::TaskSpawnBlockEvent:
    case progx::XiuosApiId::TaskSpawnBlockMsgqRecv:
        // Slot just needs to be in range; target-resource validation
        // happens at the worker (-ERROR on empty target).
        return slot < XIUOS_TASK_SLOTS && task[slot] == TaskLife::kEmpty;
    case progx::XiuosApiId::TaskSpawnBlockSemTimeout:
    case progx::XiuosApiId::TaskSpawnBlockEventTimeout:
    case progx::XiuosApiId::TaskSpawnBlockMsgqRecvTimeout:
    case progx::XiuosApiId::TaskSpawnBlockMutexTimeout:
        return false;
    case progx::XiuosApiId::TaskTerminate:
    case progx::XiuosApiId::TaskPrioSet:
        return slot < XIUOS_TASK_SLOTS && task[slot] == TaskLife::kBlocked;
    case progx::XiuosApiId::TaskSpawnSelfSuspend:
    case progx::XiuosApiId::TaskWakeup:
    case progx::XiuosApiId::TaskSpawnSelfDelay:
        return false;
    case progx::XiuosApiId::WqCreate:
        return slot < XIUOS_WQ_SLOTS && wq[slot] == WqLife::kEmpty;
    case progx::XiuosApiId::WqDeinit:
    case progx::XiuosApiId::WqSubmit:
    case progx::XiuosApiId::WqSubmitDelayed:
        return slot < XIUOS_WQ_SLOTS && wq[slot] == WqLife::kLive;
    case progx::XiuosApiId::DqInit:
    case progx::XiuosApiId::DqDeinit:
    case progx::XiuosApiId::DqPush:
    case progx::XiuosApiId::DqPop:
    case progx::XiuosApiId::DqPeek:
    case progx::XiuosApiId::WaitqInit:
    case progx::XiuosApiId::WaitqSpawnWait:
    case progx::XiuosApiId::WaitqWake:
        return false;
    case progx::XiuosApiId::ResourceSnapshot:
        return false;
    case progx::XiuosApiId::Malloc:
    case progx::XiuosApiId::Realloc:
    case progx::XiuosApiId::Calloc:
        return slot < XIUOS_MALLOC_SLOTS;
    case progx::XiuosApiId::Free:
        return slot < XIUOS_MALLOC_SLOTS &&
               malloc[slot] == MallocLife::kAllocated;
    }
    return false;
}

XiuosMutatorEngine::LifecycleState
XiuosMutatorEngine::StateAt(
        std::span<const progx::XiuosProgramCall> calls,
        std::size_t position) {
    LifecycleState s;
    const std::size_t end = std::min(position, calls.size());
    for (std::size_t i = 0; i < end; ++i) {
        s.Apply(calls[i]);
    }
    return s;
}

// ──────────────────────── XiuosMutatorEngine ────────────────────────────

XiuosMutatorEngine::XiuosMutatorEngine() : XiuosMutatorEngine(Config{}) {}

XiuosMutatorEngine::XiuosMutatorEngine(Config cfg)
    : cfg_(cfg),
      rng_(cfg.rng_seed != 0
               ? cfg.rng_seed
               : static_cast<std::uint64_t>(std::random_device{}())) {
    if (cfg_.lifecycle_violation_pct > 100) cfg_.lifecycle_violation_pct = 100;
    if (cfg_.arg_invalid_value_pct   > 100) cfg_.arg_invalid_value_pct   = 100;
    if (cfg_.max_calls_per_program < 1)     cfg_.max_calls_per_program   = 1;
    if (cfg_.max_calls_per_program > progx::kXiuosMaxCallsPerProgram) {
        cfg_.max_calls_per_program =
            static_cast<unsigned>(progx::kXiuosMaxCallsPerProgram);
    }
}

bool XiuosMutatorEngine::RollChance(unsigned pct) {
    std::uniform_int_distribution<unsigned> d(0u, 99u);
    return d(rng_) < pct;
}

std::uint32_t XiuosMutatorEngine::SampleSlot(std::uint32_t max_slot,
                                             bool include_invalid) {
    if (include_invalid && RollChance(cfg_.arg_invalid_value_pct)) {
        return kInvalidSlotValue;
    }
    std::uniform_int_distribution<std::uint32_t> d(0u, max_slot - 1);
    return d(rng_);
}

std::uint32_t XiuosMutatorEngine::SampleTimeout(bool include_invalid) {
    if (include_invalid && RollChance(cfg_.arg_invalid_value_pct)) {
        std::uniform_int_distribution<std::size_t> d(0, kInvalidTimeouts.size() - 1);
        return kInvalidTimeouts[d(rng_)];
    }
    std::uniform_int_distribution<std::size_t> d(0, kValidTimeouts.size() - 1);
    return kValidTimeouts[d(rng_)];
}

std::uint32_t XiuosMutatorEngine::SampleSmallValue(bool include_invalid) {
    if (include_invalid && RollChance(cfg_.arg_invalid_value_pct)) {
        std::uniform_int_distribution<std::size_t> d(0, kInvalidSmallValues.size() - 1);
        return kInvalidSmallValues[d(rng_)];
    }
    std::uniform_int_distribution<std::size_t> d(0, kValidSmallValues.size() - 1);
    return kValidSmallValues[d(rng_)];
}

progx::XiuosProgramCall
XiuosMutatorEngine::GenerateCall(const LifecycleState& state,
                                 bool lifecycle_aware) {
    // Build the candidate set:
    //   lifecycle_aware=true  → only apis whose IsValid() for *some* slot
    //                           passes under the current state
    //   lifecycle_aware=false → all 9 apis
    //
    // We pick api first, then a slot that satisfies the requirement (if
    // lifecycle_aware). For lifecycle_aware mode, if no api/slot combo is
    // valid (e.g. all slots LIVE so SEM_CREATE blocked, none LIVE so the
    // others are too), we fall back to lifecycle-ignoring generation.
    //
    // Args beyond slot are drawn from the api's typed domain (with a small
    // chance of invalid values, regardless of lifecycle_aware).

    progx::XiuosProgramCall out{};

    auto pick_random_api = [&]() -> const ApiSpec& {
        std::uniform_int_distribution<std::size_t> d(0, kApis.size() - 1);
        return kApis[d(rng_)];
    };

    // Inline helper closing over engine state — dispatch ApiSpec::ArgT to
    // the right Sample* method. We can't make this a free function because
    // ArgT lives in this anonymous namespace and SampleTimeout / SampleSmallValue
    // are private members; we can't make it a class method because ArgT
    // isn't visible from the header. Lambda is the clean middle ground.
    auto sample_arg = [&](ApiSpec::ArgT t) -> std::uint32_t {
        switch (t) {
        case ApiSpec::ArgT::kTimeout:    return SampleTimeout(/*include_invalid=*/true);
        case ApiSpec::ArgT::kSmallValue: return SampleSmallValue(/*include_invalid=*/true);
        case ApiSpec::ArgT::kNone:       return 0;
        }
        return 0;
    };

    auto fill_args = [&](const ApiSpec& spec, std::uint32_t slot) {
        out.api_id = spec.api_id;
        out.argc   = spec.argc;
        out.args[0] = slot;
        if (spec.argc >= 2) out.args[1] = sample_arg(spec.arg1_type);
        if (spec.argc >= 3) out.args[2] = sample_arg(spec.arg2_type);
        if (spec.argc >= 4) out.args[3] = sample_arg(spec.arg3_type);
    };

    if (lifecycle_aware) {
        // Enumerate every (api, slot) pair valid under the current state.
        // 15 apis × 4 slots = 60 worst case; small fixed-size table avoids
        // heap allocation on the hot path. If anything matches, sample
        // uniformly over the full candidate set (not "api then slot",
        // which biases toward apis that only fit one slot under the
        // current state). If no candidate exists — every slot empty AND
        // every slot live, which only happens in degenerate inputs — we
        // fall through to the unconstrained pick below.
        struct Candidate { const ApiSpec* spec; std::uint32_t slot; };
        std::array<Candidate, kApis.size() * 4> candidates{};
        std::size_t n_candidates = 0;
        for (const auto& spec : kApis) {
            const std::uint32_t max_slot = SlotsForFamily(spec.family);
            for (std::uint32_t s = 0; s < max_slot; ++s) {
                progx::XiuosProgramCall probe{};
                probe.api_id = spec.api_id;
                probe.argc = spec.argc;
                probe.args[0] = s;
                if (state.IsValid(probe)) {
                    candidates[n_candidates++] = {&spec, s};
                }
            }
        }
        if (n_candidates > 0) {
            std::uniform_int_distribution<std::size_t> d(0, n_candidates - 1);
            const auto& c = candidates[d(rng_)];
            fill_args(*c.spec, c.slot);
            return out;
        }
        ++stats_.lifecycle_violations;
        // Fall through to unconstrained pick below.
    } else {
        ++stats_.lifecycle_violations;
    }

    // Lifecycle-ignoring pick (either by request or after a failed search).
    const auto& spec = pick_random_api();
    const std::uint32_t max_slot = SlotsForFamily(spec.family);
    fill_args(spec, SampleSlot(max_slot, /*include_invalid=*/true));
    return out;
}

// ──────────────────────── Op impls ──────────────────────────────────────

bool XiuosMutatorEngine::OpInsertCall(
        std::vector<progx::XiuosProgramCall>& calls) {
    if (calls.size() >= cfg_.max_calls_per_program) {
        return false;
    }
    std::uniform_int_distribution<std::size_t> pos_d(0, calls.size());
    const std::size_t pos = pos_d(rng_);
    const bool lifecycle_aware = !RollChance(cfg_.lifecycle_violation_pct);
    const auto state = StateAt(
        std::span<const progx::XiuosProgramCall>(calls.data(), calls.size()),
        pos);
    auto new_call = GenerateCall(state, lifecycle_aware);
    calls.insert(calls.begin() + static_cast<std::ptrdiff_t>(pos), new_call);
    return true;
}

bool XiuosMutatorEngine::OpDeleteCall(
        std::vector<progx::XiuosProgramCall>& calls) {
    if (calls.empty()) return false;
    std::uniform_int_distribution<std::size_t> pos_d(0, calls.size() - 1);
    const std::size_t pos = pos_d(rng_);
    calls.erase(calls.begin() + static_cast<std::ptrdiff_t>(pos));
    return true;
}

bool XiuosMutatorEngine::OpReplaceCall(
        std::vector<progx::XiuosProgramCall>& calls) {
    if (calls.empty()) return false;
    std::uniform_int_distribution<std::size_t> pos_d(0, calls.size() - 1);
    const std::size_t pos = pos_d(rng_);
    const bool lifecycle_aware = !RollChance(cfg_.lifecycle_violation_pct);
    const auto state = StateAt(
        std::span<const progx::XiuosProgramCall>(calls.data(), calls.size()),
        pos);
    calls[pos] = GenerateCall(state, lifecycle_aware);
    return true;
}

bool XiuosMutatorEngine::OpMutateArg(
        std::vector<progx::XiuosProgramCall>& calls) {
    if (calls.empty()) return false;
    std::uniform_int_distribution<std::size_t> pos_d(0, calls.size() - 1);
    const std::size_t pos = pos_d(rng_);
    progx::XiuosProgramCall& target = calls[pos];
    if (target.argc == 0) return false;

    const auto& spec = FindApi(target.api_id);
    // Pick which arg to mutate. For argc==1, only slot; argc==2 -> slot/arg1;
    // argc==3 -> slot/arg1/arg2; argc==4 -> also arg3 (e.g. EVENT_PROCESS
    // process_options_idx, whose idx3 reaches the KEventProcess CHECK(0) spin).
    std::uniform_int_distribution<unsigned> which_d(0u, target.argc - 1u);
    const unsigned which = which_d(rng_);

    auto sample_typed = [&](ApiSpec::ArgT t) -> std::uint32_t {
        switch (t) {
        case ApiSpec::ArgT::kTimeout:    return SampleTimeout(/*include_invalid=*/true);
        case ApiSpec::ArgT::kSmallValue: return SampleSmallValue(/*include_invalid=*/true);
        case ApiSpec::ArgT::kNone:       return target.args[1];  // shouldn't fire
        }
        return target.args[1];
    };

    if (which == 0) {
        const std::uint32_t max_slot = SlotsForFamily(spec.family);
        target.args[0] = SampleSlot(max_slot, /*include_invalid=*/true);
    } else if (which == 1) {
        if (spec.arg1_type == ApiSpec::ArgT::kNone) return false;
        target.args[1] = sample_typed(spec.arg1_type);
    } else if (which == 2) {
        if (spec.arg2_type == ApiSpec::ArgT::kNone) return false;
        target.args[2] = sample_typed(spec.arg2_type);
    } else if (which == 3) {
        if (spec.arg3_type == ApiSpec::ArgT::kNone) return false;
        target.args[3] = sample_typed(spec.arg3_type);
    } else {
        return false;
    }
    return true;
}

// ──────────────────────── Mutate(seed) ──────────────────────────────────

std::vector<std::uint8_t> XiuosMutatorEngine::Mutate(const Seed& seed) {
    ++stats_.total_calls;

    if (seed.payload.empty()) {
        ++stats_.empty_seed_skipped;
        // Bytes path: return empty → admission filter rejects (NonEmptyPayload).
        // Caller can then fall back to its own generation path; XiUOS v1
        // does not implement Generate() so we cannot synthesize from scratch.
        return {};
    }

    progx::XiuosDecodedProgram decoded;
    try {
        decoded = progx::XiuosDecodeProgram(
            std::span<const std::uint8_t>(seed.payload.data(),
                                          seed.payload.size()));
    } catch (const std::exception&) {
        ++stats_.decode_failed;
        // Don't lose the seed bytes; mutator contract says "return mutated
        // bytes or original on no-op". Return the original payload.
        return seed.payload;
    }

    auto calls = std::move(decoded.calls);

    // Uniform op pick. We loop a few times if the chosen op declined
    // (e.g., delete on empty); we cap the retries to avoid infinite loop
    // when the program is empty AND insert is the only option that works.
    std::uniform_int_distribution<unsigned> op_d(
        0u, static_cast<unsigned>(MutationOp::kCount) - 1u);
    bool changed = false;
    for (int retry = 0; retry < 4 && !changed; ++retry) {
        const auto op = static_cast<MutationOp>(op_d(rng_));
        ++stats_.attempted[static_cast<std::size_t>(op)];
        switch (op) {
        case MutationOp::kInsertCall:  changed = OpInsertCall(calls);  break;
        case MutationOp::kDeleteCall:  changed = OpDeleteCall(calls);  break;
        case MutationOp::kReplaceCall: changed = OpReplaceCall(calls); break;
        case MutationOp::kMutateArg:   changed = OpMutateArg(calls);   break;
        case MutationOp::kCount:       break;
        }
        if (changed) {
            ++stats_.produced[static_cast<std::size_t>(op)];
        } else {
            ++stats_.op_skipped;
        }
    }

    if (!changed) {
        // No op fired (e.g., empty program + delete/replace/mutate picked
        // before insert). Return the original bytes — no mutation, but no
        // damage either.
        return seed.payload;
    }

    try {
        return progx::XiuosEncodeProgram(
            std::span<const progx::XiuosProgramCall>(calls.data(), calls.size()),
            decoded.suite_id, decoded.flags);
    } catch (const std::exception&) {
        ++stats_.encode_failed;
        return seed.payload;
    }
}

}  // namespace refuzz::fuzzer
